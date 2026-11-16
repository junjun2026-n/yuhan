import json
import pytest
from fastapi.testclient import TestClient
from waf.main import create_app
from waf import accounts
from waf.store import Store
from waf.migrate import migrate


@pytest.fixture
def management(tmp_path,monkeypatch):
    monkeypatch.setenv('WAF_ADMIN_PASSWORD','bootstrap-password')
    app=create_app('admin',database=tmp_path/'accounts.db')
    with TestClient(app,headers={'Origin':'http://testserver'}) as client:
        client.auth=('admin','bootstrap-password')
        yield client,app.state.store


def test_roles_enforced_for_every_existing_api(management):
    client,store=management
    for role in ('operator','auditor','custom'):
        assert client.post('/api/users',json={'username':role,'role':role,'password':'new-user-password','permissions':['audit'] if role=='custom' else []}).status_code==200
    app=client.app
    for role in ('operator','auditor','custom'):
        client.auth=(role,'new-user-password')
        granted=accounts.ROLES[role] if role!='custom' else ['audit']
        for route in app.routes:
            if not route.path.startswith('/api/') or route.path.startswith('/api/me'): continue
            for method in route.methods:
                required=accounts.required(route.path,method)
                if not required or (any(key in granted for key in required) if isinstance(required,tuple) else required in granted): continue
                # Permission checks run even for malformed mutations and arbitrary resource IDs.
                response=client.request(method,route.path.replace('{username}','admin').replace('{identifier}','CUSTOM-test'),json={} if method!='GET' else None)
                assert response.status_code==403,(role,method,route.path,response.text)
        assert client.get('/api/me').status_code==200
    client.auth=('admin','bootstrap-password')
    users=client.get('/api/users').json()
    assert 'password_hash' not in json.dumps(users)
    assert 'new-user-password' not in json.dumps(users)


def test_password_change_invalidates_old_credentials_and_survives_restart(management,monkeypatch):
    client,store=management
    assert client.post('/api/me/password',json={'current_password':'wrong','new_password':'replacement-password'}).status_code==422
    assert client.post('/api/me/password',json={'current_password':'bootstrap-password','new_password':'replacement-password'}).status_code==200
    assert client.get('/api/me').status_code==401
    client.auth=('admin','replacement-password')
    assert client.get('/api/me').status_code==200
    restarted=create_app('admin',database=store.path)
    with TestClient(restarted) as fresh:
        assert fresh.get('/api/me',auth=('admin','bootstrap-password')).status_code==401
        assert fresh.get('/api/me',auth=('admin','replacement-password')).status_code==200
    target=Store(store.path+'.copy')
    migrate(store,target)
    assert accounts.read(target)==accounts.read(store)
    assert accounts.verify('replacement-password',accounts.read(target)[0]['password_hash'])


def test_last_admin_disable_delete_reset_and_permission_updates(management):
    client,store=management
    assert client.put('/api/users/admin',json={'username':'admin','role':'auditor'}).status_code==422
    assert client.put('/api/users/admin',json={'username':'admin','role':'administrator','enabled':False}).status_code==422
    assert client.request('DELETE','/api/users/admin',json={}).status_code==422
    assert client.post('/api/users',json={'username':'staff','role':'custom','permissions':['audit'],'password':'staff-password'}).status_code==200
    client.auth=('staff','staff-password')
    assert client.get('/api/events').status_code==200
    assert client.get('/api/stats').status_code==403
    client.auth=('admin','bootstrap-password')
    assert client.put('/api/users/staff',json={'username':'staff','role':'operator','password':'reset-password','enabled':False}).status_code==200
    client.auth=('staff','reset-password')
    assert client.get('/api/me').status_code==401
    client.auth=('admin','bootstrap-password')
    assert client.put('/api/users/staff',json={'username':'staff','role':'operator','enabled':True}).status_code==200
    client.auth=('staff','staff-password')
    assert client.get('/api/me').status_code==401
    client.auth=('staff','reset-password')
    assert client.get('/api/me').status_code==200
    assert client.get('/api/events').status_code==403


def test_rule_permission_cannot_edit_site_and_probe_cannot_auth_remote(management):
    client,store=management
    client.post('/api/users',json={'username':'rules','role':'custom','permissions':['rules'],'password':'rules-password'})
    client.auth=('rules','rules-password')
    value=client.get('/api/settings').json()
    assert client.put('/api/settings',json={**value,'upstream':'http://example.com'}).status_code==403
    assert client.put('/api/settings',json={**value,'disabled_rules':['SQLI-001']}).status_code==200
    assert store.events('admin')[0]['ip']=='rules'
    client.auth=('missing','wrong')
    assert client.get('/api/settings',headers={'X-WAF-Probe':'bootstrap-password'}).status_code==401


def test_internal_probe_survives_password_change_but_cannot_manage_accounts(management):
    client,store=management
    assert client.post('/api/me/password',json={'current_password':'bootstrap-password','new_password':'replacement-password'}).status_code==200
    with TestClient(client.app,client=('127.0.0.1',12345),headers={'X-WAF-Probe':'bootstrap-password'}) as probe:
        probe.auth=('admin','bootstrap-password')
        assert probe.get('/api/tls').status_code==200
        assert probe.get('/api/users').status_code==401
        assert probe.get('/api/me').status_code==401
