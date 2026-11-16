import sqlite3
from datetime import datetime,timedelta,timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from waf.geoip import source
from waf.main import create_app
from waf.reporting import overview
from waf.store import Store


def seed(store):
    for i in range(7):store.event(str(i),'8.8.8.8','GET','/login','blocked','SQL-001',403,'App.Example.com')
    for i in range(3):store.event('cn'+str(i),'223.5.5.5','POST','/api','allowed','',200,'other.example.com')
    store.event('local','192.168.17.5','GET','/local','detected','XSS-001',200,'app.example.com')
    store.event('old','1.1.1.1','GET','/old','error','UPSTREAM',502)
    store.event('admin','admin','PUT','/settings','admin','CONFIG',200)
    with store.connect() as db:
        db.execute('UPDATE events SET created_at=? WHERE request_id=?',((datetime.now(timezone.utc)-timedelta(days=40)).isoformat(),'old'))


def assert_overview(store):
    result=overview(store,'24h')
    assert result['counts']['total']==11
    assert result['counts']['blocked']==7 and result['counts']['errors']==0
    assert result['rankings']['domains']==[{'value':'app.example.com','count':8},{'value':'other.example.com','count':3}]
    assert result['rankings']['external_ips']==[{'value':'8.8.8.8','count':7},{'value':'223.5.5.5','count':3}]
    assert result['rankings']['countries']==[{'value':'US','count':7},{'value':'CN','count':3}]
    assert result['external_requests']==10 and result['missing_domains']==0
    for key,action in [('total','business'),('blocked','blocked'),('detected','detected'),('allowed','allowed'),('errors','error')]:
        assert store.events_page(action,since=result['since'],until=result['until'])['total']==result['counts'][key]
    for key,field in [('domains','domain'),('external_ips','ip'),('countries','country'),('rules','rule_id'),('methods','method'),('statuses','status'),('paths','path')]:
        for item in result['rankings'][key]:
            filters={field:item['value'],'since':result['since'],'until':result['until']}
            if key in ('external_ips','countries'):filters['external']=True
            assert store.events_page('hits' if key=='rules' else 'business',**filters)['total']==item['count']
    assert overview(store)['counts']['total']==12
    assert overview(store)['missing_domains']==1


def test_overview_rankings_and_drilldown(tmp_path):
    store=Store(tmp_path/'report.db');seed(store);assert_overview(store)
    # Reopening does not duplicate or reclassify correctly stored records.
    assert_overview(Store(tmp_path/'report.db'))


def assert_threat_rankings(store):
    from waf.custom_rules import CustomRule
    store.change_custom_rule('CUSTOM-black',CustomRule(name='blacklist',source_ip='203.0.113.0/24').model_dump(mode='json'),create=True)
    for i in range(7):
        for j in range(7-i):
            store.event(f'black-{i}-{j}',f'203.0.113.{i+1}','GET','/','blocked','CUSTOM-black',403)
    store.event('mirror-black','203.0.113.1','GET','/','detected','CUSTOM-black',200)
    store.event('port-black','203.0.113.1','GET','/','blocked','PORT_DENY:PORT-123',403)
    store.event('allow','203.0.113.1','GET','/','allowed','CUSTOM-black',200)
    for i,rule in enumerate(('SQLI-001','XSS-001','PATH-001','CMD-001','SCAN-001','CC_RATE:CC-123','PORT_ALLOW:PORT-123')):
        for j in range(8-i):
            store.event(f'attack-{i}-{j}','8.8.8.8','GET','/attack','detected' if j%2 else 'blocked',rule,403)
    store.event('error','8.8.8.8','GET','/','error','UPSTREAM',502)
    store.event('admin','admin','PUT','/','admin','SQLI-001',200)
    # Classification survives rule edit/removal and reopening.
    store.change_custom_rule('CUSTOM-black',delete=True)
    result=overview(store)
    assert result['rankings']['blacklist_ips']==[{'value':f'203.0.113.{i+1}','count':9 if i==0 else 7-i} for i in range(5)]
    assert [(r['value'],r['count']) for r in result['rankings']['attacks']]==[('SQLi',8),('XSS',7),('Traversal',6),('Command',5),('Scanner',4)]
    for key,action,field in [('blacklist_ips','blacklist','ip'),('attacks','attacks','threat_type')]:
        for item in result['rankings'][key]:
            assert store.events_page(action,**{field:item['value'],'since':result['since'],'until':result['until']})['total']==item['count']
    with store.connect() as db:
        db.execute('UPDATE events SET created_at=? WHERE request_id=?',((datetime.now(timezone.utc)-timedelta(days=40)).isoformat(),'mirror-black'))
    assert overview(store,'24h')['rankings']['blacklist_ips'][0]['count']==8


def test_blacklist_and_attack_rankings(tmp_path):
    store=Store(tmp_path/'threats.db');assert_threat_rankings(store)
    assert overview(Store(tmp_path/'threats.db'))['rankings']['blacklist_ips'][0]['count']==9


def test_blacklist_category_is_not_inferred_from_any_custom_rule(tmp_path):
    from waf.custom_rules import CustomRule
    store=Store(tmp_path/'custom.db')
    for name,value in [('path',CustomRule(name='path block',path='/admin')),('monitor',CustomRule(name='IP monitor',source_ip='203.0.113.1',action='monitor'))]:
        identifier='CUSTOM-'+name
        store.change_custom_rule(identifier,value.model_dump(mode='json'),create=True)
        store.event(name,'203.0.113.1','GET','/admin','detected',identifier,200)
    result=overview(store)
    assert result['rankings']['blacklist_ips']==[]
    assert result['rankings']['attacks'][0]['value']=='Custom' and result['rankings']['attacks'][0]['count']==2


def test_top5_deterministic_empty_and_missing_geo(tmp_path,monkeypatch):
    store=Store(tmp_path/'empty.db');assert overview(store)['counts']['total']==0
    for i in range(7):store.event(str(i),'127.0.0.1','GET','/'+str(i),'allowed','',200,f'a{i}.example.com')
    assert [r['value'] for r in overview(store)['rankings']['domains']]==[f'a{i}.example.com' for i in range(5)]
    assert not overview(store)['rankings']['countries']
    import waf.geoip as geo
    with monkeypatch.context() as context:
        context.setattr(geo,'DATA',tmp_path/'missing.bin');geo.index.cache_clear();geo.source.cache_clear()
        assert geo.source('8.8.8.8')['country']=='ZZ'
        assert not overview(store)['geoip_available']
    geo.index.cache_clear();geo.source.cache_clear()


@pytest.mark.parametrize('ip,external,country',[
    ('8.8.8.8',True,'US'),('223.5.5.5',True,'CN'),('2606:4700:4700::1111',True,'US'),
    ('::ffff:8.8.8.8',True,'US'),('192.168.1.2',False,''),('127.0.0.1',False,''),
    ('100.64.0.1',False,''),('224.0.0.1',False,''),('::1',False,''),('not-an-ip',False,'')])
def test_offline_country_and_public_sources(ip,external,country):
    value=source(ip);assert (value['external'],value['country'])==(external,country)


def test_upgrade_old_schema_backfills_country_without_inventing_domain(tmp_path):
    path=tmp_path/'legacy.db'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE events(id INTEGER PRIMARY KEY,created_at TEXT,request_id TEXT,ip TEXT,method TEXT,path TEXT,action TEXT,rule_id TEXT,status INTEGER)')
        db.execute("INSERT INTO events VALUES(1,?,'legacy','8.8.8.8','GET','/','allowed','',200)",(datetime.now(timezone.utc).isoformat(),))
    store=Store(path);row=store.events()[0]
    assert row['domain']=='' and row['country']=='US' and row['source_scope']=='external'
    assert overview(store)['missing_domains']==1


def test_old_hits_backfill_once(tmp_path):
    path=tmp_path/'old.db';store=Store(path)
    store.event('old','8.8.8.8','GET','/','blocked','SQLI-001',403)
    with store.connect() as db:db.execute("UPDATE events SET threat_type=''")
    restored=Store(path)
    assert restored.events()[0]['threat_type']=='SQLi'
    assert overview(restored)['rankings']['attacks'][0]['count']==1


def test_proxy_and_cc_record_domain_and_actual_peer(tmp_path):
    from waf.traffic_protection import ProtectionConfig,CCConfig,save
    app=create_app(database=tmp_path/'proxy.db',transport=httpx.MockTransport(lambda request:httpx.Response(200,stream=httpx.ByteStream(b'OK'))))
    app.state.store.save({**app.state.store.settings(),'upstream':'http://origin.test'})
    save(app.state.store,ProtectionConfig(cc=CCConfig(enabled=True,max_requests=1)))
    with TestClient(app,client=('8.8.8.8',12345)) as client:
        for status in (200,429):
            assert client.get('/',headers={'Host':'App.Example.com:8300','X-Forwarded-For':'223.5.5.5'}).status_code==status
    rows=app.state.store.events()
    assert len(rows)==2
    assert all(row['domain']=='app.example.com' and row['ip']=='8.8.8.8' and row['country']=='US' for row in rows)


def test_mirror_records_request_domain(tmp_path):
    from waf.dataplane import Inspector
    store=Store(tmp_path/'mirror.db')
    payload=b'GET / HTTP/1.1\r\nHost: mirror.example.com\r\n\r\n'
    Inspector(store,passive=True).feed(('8.8.8.8',12345,'192.168.1.1',80),0,payload)
    row=store.events()[0]
    assert row['domain']=='mirror.example.com' and row['action']=='observed'


def test_overview_api_filters_and_permissions(tmp_path,monkeypatch):
    monkeypatch.setenv('WAF_ADMIN_PASSWORD','test-password')
    app=create_app('admin',database=tmp_path/'api.db');seed(app.state.store)
    with TestClient(app) as client:
        assert client.get('/api/stats/overview').status_code==401
        client.auth=('admin','test-password')
        snapshot=client.get('/api/stats/overview?period=24h').json()
        assert client.get('/api/events?paginated=true&action=blacklist').json()['total']==0
        assert client.get('/api/events?paginated=true&action=attacks&threat_type=XSS').json()['total']==1
        result=client.get('/api/events',params={'paginated':'true','action':'business','country':'US','external':'true','since':snapshot['since'],'until':snapshot['until'],'page_size':2,'page':99}).json()
        assert result['total']==7 and result['pages']==4 and result['page']==4
        assert client.get('/api/events',params={'paginated':'true','domain':"' OR 1=1 --"}).json()['total']==0
        for query in ('period=invalid',):assert client.get('/api/stats/overview?'+query).status_code==422
        for query in ('since=invalid','since=2026-01-01','status=-1','status=900','country=INVALID'):
            assert client.get('/api/events?paginated=true&'+query).status_code==422
        from waf import accounts
        accounts.change(app.state.store,'summary',accounts.UserInput(username='summary',password='summary-password',role='custom',permissions=['overview'],enabled=True),create=True)
        client.auth=('summary','summary-password')
        assert client.get('/api/stats/overview').status_code==200
        assert client.get('/api/events?paginated=true').status_code==403
