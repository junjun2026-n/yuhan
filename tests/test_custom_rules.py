from datetime import datetime,timedelta,timezone

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from waf.custom_rules import CustomRule,evaluate
from waf.dataplane import Inspector
from waf.main import create_app
from waf.migrate import migrate
from waf.store import Store


def record(identifier='CUSTOM-test',**kwargs):
    return {**CustomRule(name='test',**kwargs).model_dump(mode='json'),'id':identifier}


def test_priority_cidr_combined_conditions_and_decoding():
    deny=record('CUSTOM-deny',source_ip='203.0.113.0/24',domain='*.example.com',methods=['post'],path='/admin',keyword='exploit',priority=10)
    allow=record('CUSTOM-allow',source_ip='203.0.113.9',action='allow',priority=20)
    assert evaluate([allow,deny],'203.0.113.9','app.example.com','POST','/%61dmin','q=ex%70loit')['id']=='CUSTOM-deny'
    assert evaluate([allow,deny],'203.0.113.9','app.example.com','GET','/admin','q=exploit')['id']=='CUSTOM-allow'
    assert evaluate([deny],'203.0.114.1','app.example.com','POST','/admin','exploit') is None
    assert evaluate([deny],'203.0.113.1','deep.app.example.com','POST','/admin','exploit') is None
    ipv6=record(source_ip='2001:db8::/32')
    assert evaluate([ipv6],'2001:db8::9','','GET','/')


def test_expiry_disable_and_exact_path():
    old=record(path='/admin',path_match='exact',expires_at=datetime.now(timezone.utc)-timedelta(seconds=1))
    assert evaluate([old],'1.1.1.1','','GET','/admin') is None
    disabled=record(path='/admin',enabled=False)
    assert evaluate([disabled],'1.1.1.1','','GET','/admin') is None
    exact=record(path='/Admin',path_match='exact',case_sensitive=True)
    assert evaluate([exact],'1.1.1.1','','GET','/Admin')
    assert evaluate([exact],'1.1.1.1','','GET','/admin') is None
    assert evaluate([exact],'1.1.1.1','','GET','/Admin/more') is None


@pytest.mark.parametrize('value',[{},dict(name=' '),dict(source_ip='bad'),dict(domain='http://example.com'),dict(methods=['INVALID']),dict(path='admin'),dict(priority=0),dict(expires_at=datetime(2030,1,1))])
def test_invalid_or_empty_rules(value):
    with pytest.raises(ValidationError): CustomRule(**({'name':'test'}|value))


@pytest.fixture
def apps(tmp_path,monkeypatch):
    monkeypatch.setenv('WAF_ADMIN_PASSWORD','test-password')
    path=tmp_path/'waf.db'
    admin=create_app('admin',database=path)
    proxy=create_app(database=path,transport=httpx.MockTransport(lambda request:httpx.Response(200,stream=httpx.ByteStream(b'upstream-ok'))))
    store=admin.state.store
    store.save({**store.settings(),'upstream':'http://origin.example'})
    with TestClient(admin,headers={'Origin':'http://testserver'}) as management, TestClient(proxy,client=('203.0.113.9',1234)) as traffic:
        management.auth=('admin','test-password')
        yield management,traffic,store


def test_crud_auth_csrf_and_stale_settings_do_not_erase_rules(apps):
    admin,traffic,store=apps
    original=admin.get('/api/settings').json()
    payload={'name':'deny admin','path':'/admin'}
    assert admin.post('/api/custom-rules',json=payload,headers={'Origin':'http://evil'}).status_code==403
    created=admin.post('/api/custom-rules',json=payload)
    assert created.status_code==200
    identifier=created.json()['id']
    assert traffic.get('/admin').status_code==403
    assert store.events()[0]['rule_id']==identifier
    assert admin.put('/api/settings',json=original).status_code==200
    assert len(admin.get('/api/custom-rules').json())==1
    assert traffic.get('/admin').status_code==403
    assert admin.put('/api/custom-rules/'+identifier,json={**payload,'enabled':False}).status_code==200
    assert traffic.get('/admin').status_code==200
    assert admin.request('DELETE','/api/custom-rules/'+identifier,json={}).status_code==200
    assert admin.get('/api/custom-rules').json()==[]
    assert admin.put('/api/custom-rules/'+identifier,json=payload).status_code==404
    admin.auth=('admin','wrong')
    assert admin.get('/api/custom-rules').status_code==401
    assert admin.post('/api/custom-rules',json=payload).status_code==401


def test_emergency_block_in_monitor_and_white_bypasses_signatures_only(apps):
    admin,traffic,store=apps
    store.save({**store.settings(),'mode':'monitor','enabled':False})
    emergency=admin.post('/api/custom-rules',json={'name':'emergency','path':'/emergency','priority':1}).json()['id']
    assert traffic.get('/emergency').status_code==403
    assert store.events()[0]['rule_id']==emergency
    admin.post('/api/custom-rules',json={'name':'white','source_ip':'203.0.113.9','action':'allow','priority':20}).raise_for_status()
    store.save({**store.settings(),'mode':'block','enabled':True})
    assert traffic.get('/?q=union+select+password').status_code==200
    assert store.events()[0]['action']=='allowed' and store.events()[0]['rule_id'].startswith('CUSTOM-')
    assert traffic.get('/emergency').status_code==403
    assert traffic.request('TRACE','/').status_code==405
    store.save({**store.settings(),'rate_limit':1})
    assert traffic.get('/').status_code==429


def test_ip_blacklist_ignores_spoofed_forwarded_headers_and_monitor_audits(apps):
    admin,traffic,store=apps
    created=admin.post('/api/custom-rules',json={'name':'black','source_ip':'203.0.113.0/24'}).json()
    assert traffic.get('/',headers={'X-Forwarded-For':'127.0.0.1'}).status_code==403
    payload={key:value for key,value in created.items() if key!='id'}
    payload['action']='monitor'
    admin.put('/api/custom-rules/'+created['id'],json=payload).raise_for_status()
    assert traffic.get('/').status_code==200
    assert store.events()[0]['action']=='detected' and store.events()[0]['rule_id']==created['id']


@pytest.mark.parametrize('passive',[True,False])
def test_inline_and_mirror_rules(tmp_path,passive):
    store=Store(tmp_path/'flow.db')
    store.save({**store.settings(),'mode':'monitor','enabled':False,'custom_rules':[record(path='/blocked')]})
    inspector=Inspector(store,passive=passive)
    blocked=inspector.feed(('203.0.113.9',1234,'10.0.0.1',80),10,b'GET /blocked HTTP/1.1\r\nHost: example.com\r\n\r\n')
    assert blocked is (not passive)
    assert store.events()[0]['rule_id']=='CUSTOM-test'
    assert store.events()[0]['action']==('detected' if passive else 'blocked')
    store.save({**store.settings(),'enabled':True,'mode':'block','custom_rules':[record(source_ip='203.0.113.9',action='allow')]})
    inspector=Inspector(store,passive=passive)
    assert not inspector.feed(('203.0.113.9',1234,'10.0.0.1',80),10,b'GET /?q=union+select+password HTTP/1.1\r\nHost: example.com\r\n\r\n')
    assert store.events()[0]['rule_id']=='CUSTOM-test'
    assert store.events()[0]['action']==('observed' if passive else 'allowed')


def test_rules_survive_verified_database_migration(tmp_path):
    source=Store(tmp_path/'source.db');target=Store(tmp_path/'target.db')
    source.change_custom_rule('CUSTOM-test',record(path='/blocked')|{'id':'CUSTOM-test'},create=True)
    migrate(source,target)
    assert target.settings()['custom_rules']==source.settings()['custom_rules']
