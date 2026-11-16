from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from waf.main import create_app
from waf.traffic_protection import (CCConfig, ProtectionConfig, TrafficGuard,
    change_rule, configuration, policy_rules, save)


def test_multi_crud_preserves_legacy_and_concurrent_updates(tmp_path):
    app=create_app('admin',database=tmp_path/'multi.db')
    store=app.state.store
    save(store,ProtectionConfig(cc=CCConfig(enabled=True,max_requests=7)))
    def add(i):
        return change_rule(store,'cc',{'name':f'rule {i}','target_type':'domain','target':f'a{i}.example.com','enabled':True})
    with ThreadPoolExecutor(max_workers=4) as pool: list(pool.map(add,range(6)))
    config=configuration(store)
    assert len(config.cc_rules)==7
    legacy=policy_rules(config,'cc')[0]
    assert legacy.max_requests==7 and legacy.enabled
    identifier=config.cc_rules[-1].id
    change_rule(store,'cc',{'name':'edited','enabled':False},identifier)
    assert configuration(store).cc_rules[-1].name=='edited'
    change_rule(store,'cc',identifier=identifier,delete=True)
    assert len(configuration(store).cc_rules)==6
    assert configuration(store).ports==config.ports


def test_multi_cc_isolation_overlap_and_disable(tmp_path):
    store=create_app('admin',database=tmp_path/'guard.db').state.store
    # Delete the legacy default then create two independently counted domains.
    change_rule(store,'cc',identifier=policy_rules(configuration(store),'cc')[0].id,delete=True)
    for host in ['a.example.com','b.example.com']:
        config=change_rule(store,'cc',{'name':host,'target_type':'domain','target':host,'enabled':True,'max_requests':1})
    guard=TrafficGuard()
    for host in ['a.example.com','b.example.com']:
        assert not guard.enter('192.0.2.1',config,host)[0]
        assert guard.enter('192.0.2.1',config,host)[1]==429
    a=config.cc_rules[0]
    config=change_rule(store,'cc',{**a.model_dump(),'enabled':False},a.id)
    assert not guard.enter('192.0.2.1',config,'a.example.com')[0]
    config=change_rule(store,'cc',a.model_dump(),a.id)
    assert not guard.enter('192.0.2.1',config,'a.example.com')[0]
    config=change_rule(store,'cc',{'name':'all','enabled':True,'max_requests':1})
    assert not guard.enter('192.0.2.2',config,'a.example.com')[0]
    assert guard.enter('192.0.2.2',config,'b.example.com')[1]==429


def test_multi_ports_filters_rollback_and_delete_inflight(tmp_path):
    store=create_app('admin',database=tmp_path/'ports.db').state.store
    config=change_rule(store,'ports',{'name':'first','enabled':True,'protocol':'https','destination_port':8443,'max_concurrent_per_ip':1})
    first=config.port_rules[-1]
    config=change_rule(store,'ports',{'name':'second','enabled':True,'target_type':'domain','target':'a.example.com','protocol':'https','destination_port':8443,'blocked_sources':['192.0.2.1']})
    guard=TrafficGuard()
    def enter(host='a.example.com',port=8443,scheme='https'):
        return guard.enter('192.0.2.1',config,host,'192.0.2.10',port,scheme)
    assert not enter(port=9443)[0]
    assert not enter(scheme='http')[0]
    assert enter()[1]==403
    assert guard.children[first.id].total==0  # Later denial releases earlier admission.
    admitted=enter(host='b.example.com')
    assert not admitted[0] and admitted[3]
    assert enter(host='b.example.com')[1]==429
    change_rule(store,'ports',{**first.model_dump(),'enabled':False},first.id)
    config=change_rule(store,'ports',identifier=first.id,delete=True)
    assert not enter(host='b.example.com')[0]
    guard.leave('192.0.2.1',admitted[3])  # Deleted policies still release safely.


def test_multi_api_crud_and_legacy_write_protection(tmp_path,monkeypatch):
    monkeypatch.setenv('WAF_ADMIN_PASSWORD','test-password')
    app=create_app('admin',database=tmp_path/'api.db')
    with TestClient(app,headers={'Origin':'http://testserver','Content-Type':'application/json'}) as client:
        client.auth=('admin','test-password')
        for section in ['cc','ports']:
            url='/api/traffic-protection/rules/'+section
            before=len(client.get('/api/traffic-protection/rules').json()[section])
            for i in range(2):
                response=client.post(url,json={'name':f'policy {i}','config':{'enabled':True}})
                assert response.status_code==200,response.text
            rules=response.json()[section]
            assert len(rules)==before+2
            identifier=rules[-1]['id']
            assert client.delete(url+'/'+identifier).status_code==409
            assert len(client.get('/api/traffic-protection/rules').json()[section])==before+2
            assert client.put(url+'/'+identifier,json={'name':'changed','config':{'enabled':False}}).status_code==200
            assert client.put('/api/traffic-protection?section='+section,json={section:{}}).status_code==422
            assert client.delete(url+'/'+identifier).status_code==200
            assert client.delete(url+'/'+identifier).status_code==404
            assert client.post(url,json={'name':'bad','config':{'target_type':'ip','target':'invalid'}}).status_code==422
