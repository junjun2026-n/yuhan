# ============================================================
# 文件名称：test_database_config.py
# 生成日期：2026-10-27
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：验证 database_config 相关功能。
#           文件用途：用于开发验证及功能回归。
#           注意事项：使用隔离测试环境，避免操作正式业务数据。
# ============================================================
import json

import pytest
from fastapi.testclient import TestClient

from waf import database_config as config
from waf.database import config_path
from waf.main import create_app
from waf.store import Store


@pytest.fixture
def client(tmp_path,monkeypatch):
    monkeypatch.setattr(config,'ROOT',tmp_path)
    monkeypatch.setenv('WAF_DATABASE_CONFIG',str(tmp_path/'runtime/database.env'))
    monkeypatch.setenv('WAF_DATABASE',str(tmp_path/'runtime/active.sqlite3'))
    monkeypatch.setenv('WAF_DB_ENGINE','sqlite')
    monkeypatch.setenv('WAF_ADMIN_PASSWORD','test-password')
    monkeypatch.delenv('WAF_DEV_MODE',raising=False)
    app=create_app('admin',database=tmp_path/'runtime/active.sqlite3')
    with TestClient(app,headers={'Origin':'http://testserver'}) as client:
        client.auth=('admin','test-password')
        yield client,app.state.store,tmp_path


def test_database_dropdown_stages_without_switching_live_storage(client):
    client,store,root=client
    value={'engine':'sqlite','sqlite_path':'runtime/new.sqlite3'}
    assert client.post('/api/system/database/probe',json=value).json()['ok']
    assert client.put('/api/system/database',json=value).status_code==200
    state=client.get('/api/system/database').json()
    assert state['active_engine']=='sqlite' and state['pending']
    assert state['selected']['sqlite_path']==str(root/'runtime/new.sqlite3')
    assert 'password' not in state['selected']
    assert not config_path().exists()
    assert store.events()[0]['rule_id']=='DATABASE_CONFIG'
    assert client.request('DELETE','/api/system/database/pending',json={}).status_code==200
    assert not client.get('/api/system/database').json()['pending']


def test_status_uses_running_connection_instead_of_changed_file(client):
    from types import SimpleNamespace
    client,store,root=client
    config_path().write_text('WAF_DB_ENGINE=sqlite\nWAF_DATABASE=runtime/different.sqlite3\n',encoding='utf-8')
    status=config.configuration_status(store)
    assert status['active']['sqlite_path']==store.path
    assert status['selected']==status['active']
    postgres=SimpleNamespace(engine='postgresql',path='host=db.example.test port=5433 dbname=waf user=wafuser password=secret sslmode=require')
    status=config.configuration_status(postgres)
    assert status['selected']['engine']=='postgresql'
    assert status['active']['host']=='db.example.test'
    assert status['active']['port']==5433
    assert status['active']['password_set']
    assert 'secret' not in json.dumps(status)


@pytest.mark.parametrize('value',[{'engine':'mysql'}, {'engine':'sqlite','sqlite_path':'../outside.sqlite3'},
    {'engine':'sqlite','sqlite_path':'runtime/admin.env'}, {'engine':'postgresql','host':'a;id'},
    {'engine':'postgresql','host':'127.0.0.1','name':'waf','user':'wafuser'}])
def test_invalid_database_configs_leave_active_file_untouched(client,value):
    client,store,root=client
    assert client.put('/api/system/database',json=value).status_code==422
    assert not config.pending_path().exists()
    assert not config_path().exists()


def test_database_secret_preservation_and_escaping(client,monkeypatch):
    client,store,root=client
    monkeypatch.setattr(config,'probe',lambda *_:{'ok':True})
    value={'engine':'postgresql','host':'db.example.test','name':'waf','user':'wafuser','password':"a'\\$word\nnext"}
    response=client.put('/api/system/database',json=value)
    assert response.status_code==200
    assert value['password'] not in response.text
    assert config.read_config(config.pending_path()).password.get_secret_value()==value['password']
    assert client.put('/api/system/database',json={**value,'password':''}).status_code==200
    assert config.read_config(config.pending_path()).password.get_secret_value()==value['password']
    assert value['password'] not in json.dumps(store.events())
    revealed=client.post('/api/system/database/password',json={**value,'password':''})
    assert revealed.json()['password']==value['password']
    assert revealed.headers['cache-control']=='no-store'
    assert store.events()[0]['rule_id']=='DATABASE_PASSWORD_VIEW'
    assert value['password'] not in json.dumps(store.events())
    assert client.post('/api/system/database/password',json={**value,'password':''},headers={'Origin':'http://evil'}).status_code==403
    client.auth=('admin','wrong')
    assert client.post('/api/system/database/password',json={**value,'password':''}).status_code==401


def test_dev_mode_rejects_postgres_switch(client,monkeypatch):
    client,_,_=client
    monkeypatch.setenv('WAF_DEV_MODE','1')
    value={'engine':'postgresql','host':'db.example.test','name':'waf','user':'wafuser','password':'secret'}
    assert client.put('/api/system/database',json=value).status_code==422
    assert not config.pending_path().exists()


def test_postgres_profile_survives_cancel_and_switching_to_sqlite(client,monkeypatch):
    client,store,root=client
    monkeypatch.setattr(config,'probe',lambda *_:{'ok':True})
    value={'engine':'postgresql','host':'db.example.test','name':'waf','user':'wafuser','password':'saved-secret'}
    client.put('/api/system/database',json=value).raise_for_status()
    client.request('DELETE','/api/system/database/pending',json={}).raise_for_status()
    state=client.get('/api/system/database').json()
    assert state['active_engine']=='sqlite'
    assert state['profiles']['postgresql']['host']==value['host']
    assert state['profiles']['postgresql']['password_set']
    assert 'saved-secret' not in json.dumps(state)
    client.put('/api/system/database',json={'engine':'sqlite','sqlite_path':'runtime/new.sqlite3'}).raise_for_status()
    client.put('/api/system/database',json={**value,'password':''}).raise_for_status()
    assert config.read_config(config.pending_path()).password.get_secret_value()=='saved-secret'


def test_database_csrf_and_auth(client):
    client,_,_=client
    assert client.put('/api/system/database',json={'engine':'sqlite'},headers={'Origin':'http://evil'}).status_code==403
    client.auth=('admin','wrong')
    assert client.get('/api/system/database').status_code==401


def test_initialize_selected_empty_database_and_preserve_data(client):
    client,active,root=client
    value={'engine':'sqlite','sqlite_path':'runtime/initialized.sqlite3'}
    response=client.post('/api/system/database/initialize',json=value)
    assert response.status_code==200 and response.json()['ok']
    assert response.json()['tables']['settings']==1
    assert response.json()['tables']['events']==0
    target=Store(root/'runtime/initialized.sqlite3')
    target.save({**target.settings(),'upstream':'http://keep.example'})
    target.event('keep','127.0.0.1','GET','/','allowed','',200)
    assert client.post('/api/system/database/initialize',json=value).status_code==200
    assert target.settings()['upstream']=='http://keep.example'
    assert target.events()[0]['request_id']=='keep'
    assert not config_path().exists() and not config.pending_path().exists()
    assert active.events()[0]['rule_id']=='DATABASE_INITIALIZE'
    assert client.post('/api/system/database/initialize',json=value,headers={'Origin':'http://evil'}).status_code==403
    assert client.post('/api/system/database/initialize',json={**value,'sqlite_path':'../outside.sqlite3'}).status_code==422
    client.auth=('admin','wrong')
    assert client.post('/api/system/database/initialize',json=value).status_code==401


def test_offline_switch_copies_data_before_activation(client,monkeypatch):
    client,source,root=client
    from waf import switch_database
    def stopped(*args,**kwargs): raise ConnectionRefusedError()
    monkeypatch.setattr(switch_database.socket,'create_connection',stopped)
    source.save({**source.settings(),'upstream':'http://example.org'})
    assert client.put('/api/system/database',json={'engine':'sqlite','sqlite_path':'runtime/new.sqlite3'}).status_code==200
    switch_database.main()
    assert not config.pending_path().exists()
    assert config_path().exists()
    restored=Store(root/'runtime/new.sqlite3')
    assert restored.settings()==source.settings()
    assert restored.events()==source.events()


def test_switch_refuses_existing_target_without_changing_active_config(client,monkeypatch):
    client,source,root=client
    from waf import switch_database
    def stopped(*args,**kwargs): raise ConnectionRefusedError()
    monkeypatch.setattr(switch_database.socket,'create_connection',stopped)
    target=Store(root/'runtime/existing.sqlite3')
    target.event('keep','admin','GET','/','allowed','',200)
    client.put('/api/system/database',json={'engine':'sqlite','sqlite_path':'runtime/existing.sqlite3'}).raise_for_status()
    with pytest.raises(ValueError): switch_database.main()
    assert not config_path().exists() and config.pending_path().exists()
    assert target.events()[0]['request_id']=='keep'
