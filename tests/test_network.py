# ============================================================
# 文件名称：test_network.py
# 生成日期：2026-10-27
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：验证 network 相关功能。
#           文件用途：用于开发验证及功能回归。
#           注意事项：使用隔离测试环境，避免操作正式业务数据。
# ============================================================
from copy import deepcopy
import time

import pytest
from fastapi.testclient import TestClient
from waf.main import create_app
from waf.network import NetworkConfig, apply_management, resolve, validate_bindings, network_status
from waf.store import Store
from waf.dataplane import Inspector, fingerprint


@pytest.fixture
def inventory():
    return [{'id':f'test:{i}','name':f'NIC {i}','mac':str(i),'status':'Up', 'ipv4':[], 'index':i} for i in range(3)]


def bound_config():
    value=NetworkConfig().model_dump()
    for i,nic in enumerate(value['interfaces']): nic['physical_id']=f'test:{i}'
    return NetworkConfig(**value)


def test_default_and_persistence(tmp_path):
    store=Store(tmp_path/'test.db')
    assert store.network().management_cidr=='192.168.1.1/24'
    config=bound_config();store.save_network(config)
    assert Store(tmp_path/'test.db').network()==config
    assert fingerprint(config)==fingerprint(store.network())


@pytest.mark.parametrize('change',[
    {'nic_count':2}, {'management_cidr':'192.168.1.0/24'}, {'management_cidr':'224.0.0.1/24'},
    {'management_cidr':'127.0.0.1/8'}, {'deployment_mode':'inline','egress_alias':'port1'},
    {'deployment_mode':'bypass','mirror_alias':'mgmt0'}, {'deployment_mode':'oops'}])
def test_invalid_config(change):
    value=NetworkConfig().model_dump();value.update(change)
    with pytest.raises(ValueError):NetworkConfig(**value)


def test_unique_bindings_and_management():
    for field,value in [('physical_id','test:0'),('alias','mgmt0'),('role','management')]:
        config=bound_config().model_dump();config['interfaces'][1][field]=value
        with pytest.raises(ValueError): NetworkConfig(**config)


def test_alias_survives_os_rename_and_replacement(inventory):
    config=bound_config()
    inventory[0]['name']='renamed hardware'
    assert resolve(config,inventory)['mgmt0']['name']=='renamed hardware'
    inventory[0]['id']='replacement'
    assert resolve(config,inventory)['mgmt0'] is None
    validate_bindings(config,inventory,config)  # Retaining a missing binding is permitted.
    value=config.model_dump();value['interfaces'][0]['physical_id']='replacement'
    replacement=NetworkConfig(**value)
    validate_bindings(replacement,inventory,config)
    assert resolve(replacement,inventory)['mgmt0']['id']=='replacement'
    assert replacement.management_cidr==config.management_cidr
    value['interfaces'][0]['physical_id']='invented'
    with pytest.raises(ValueError):validate_bindings(NetworkConfig(**value),inventory,config)


def test_management_no_privileges_or_binding(monkeypatch,inventory):
    monkeypatch.setattr('waf.network.privileged',lambda:False)
    with pytest.raises(PermissionError):apply_management(bound_config(),inventory)
    monkeypatch.setattr('waf.network.privileged',lambda:True)
    with pytest.raises(ValueError):apply_management(NetworkConfig(),inventory)


def test_management_idempotence_and_conflict(monkeypatch,inventory):
    monkeypatch.setattr('waf.network.privileged',lambda:True)
    inventory[0]['ipv4']=['192.168.1.1/24']
    assert apply_management(bound_config(),inventory)['changed'] is False
    inventory[0]['ipv4']=[];inventory[1]['ipv4']=['192.168.1.1/24']
    with pytest.raises(ValueError):apply_management(bound_config(),inventory)


def test_network_api_auth_validation_and_status(tmp_path,monkeypatch,inventory):
    monkeypatch.setenv('WAF_ADMIN_PASSWORD','test-password')
    monkeypatch.setattr('waf.main.adapters',lambda:inventory)
    app=create_app('admin',database=tmp_path/'test.db')
    with TestClient(app) as client:
        assert client.get('/api/system').status_code==401
        client.auth=('admin','test-password')
        config=bound_config()
        assert client.put('/api/system',json=config.model_dump()).status_code==403
        headers={'Origin':'http://testserver'}
        assert client.put('/api/system',json=config.model_dump(),headers=headers).status_code==200
        assert client.get('/api/system').json()['interfaces'][0]['alias']=='mgmt0'
        assert client.get('/api/system/status').json()['management_ip_applied'] is False
        app.state.store.agent_state({'state':'running','heartbeat':time.time(),'fingerprint':fingerprint(config)})
        assert client.get('/api/system/status').json()['data_plane_running'] is True
        app.state.store.agent_state({'state':'running','heartbeat':time.time()-20,'fingerprint':fingerprint(config)})
        assert client.get('/api/system/status').json()['data_plane_running'] is False
        value=config.model_dump();value['interfaces'][0]['physical_id']='bad'
        assert client.put('/api/system',json=value,headers=headers).status_code==422


def test_stream_reassembly_and_block(tmp_path):
    store=Store(tmp_path/'test.db');engine=Inspector(store)
    key=('10.0.0.2',1234,'10.0.0.1',80)
    prefix=b'GET /?q=union%20sel'
    suffix=b'ect%20password HTTP/1.1\r\nHost: origin\r\n\r\n'
    assert not engine.feed(key,100,b'',syn=True)
    assert not engine.feed(key,101+len(prefix),suffix) # Out of order
    assert engine.feed(key,101,prefix)
    assert store.events()[0]['rule_id']=='SQLI-001'
    assert store.events()[0]['path']=='/'
    assert 'password' not in str(store.events())
    assert engine.feed(key,101,prefix) # Retransmission is still blocked.


def test_passive_and_monitor_never_block(tmp_path):
    store=Store(tmp_path/'test.db')
    for passive in (True,False):
        settings=store.settings();settings['mode']='block' if passive else 'monitor';store.save(settings)
        engine=Inspector(store,passive=passive)
        assert not engine.feed(('client',1,'server',80),1,b'GET /?q=<script> HTTP/1.1\r\nHost: origin\r\n\r\n')
        assert store.events()[0]['action']=='detected'


def test_chunked_body_and_keepalive(tmp_path):
    store=Store(tmp_path/'test.db');engine=Inspector(store)
    key=('client',1,'server',80)
    payload=b'GET /normal HTTP/1.1\r\nHost: origin\r\n\r\nPOST / HTTP/1.1\r\nHost: origin\r\nTransfer-Encoding: chunked\r\n\r\n8\r\n<script>\r\n0\r\n\r\n'
    assert engine.feed(key,1,payload)
    assert {event['action'] for event in store.events()}=={'allowed','blocked'}


def test_body_limit_and_flow_expiration(tmp_path,monkeypatch):
    store=Store(tmp_path/'test.db');settings=store.settings();settings['max_body_bytes']=1024;store.save(settings)
    engine=Inspector(store)
    assert engine.feed(('client',1,'server',80),1,b'POST / HTTP/1.1\r\nHost: origin\r\nContent-Length: 1025\r\n\r\n'+b'a'*1025)
    assert store.events()[0]['rule_id']=='BODY'
    engine.flows[next(iter(engine.flows))].seen=0
    monkeypatch.setattr('waf.dataplane.time.monotonic',lambda:121)
    assert not engine.feed(('other',1,'server',80),1,b'GET / HTTP/1.1\r\nHost: origin\r\n\r\n')
    assert len(engine.flows)==1
