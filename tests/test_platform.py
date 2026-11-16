import base64
import pytest
from fastapi.testclient import TestClient
from waf.main import create_app
from waf.store import Store


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv('WAF_ADMIN_PASSWORD', 'test-password')
    app = create_app('admin', database=tmp_path/'waf.db')
    with TestClient(app, headers={'Origin': 'http://testserver', 'Authorization':
                    'Basic '+base64.b64encode(b'admin:test-password').decode()}) as client:
        yield client, app.state.store


def test_platform_persistence_and_live_database_parameters(client):
    client, store = client
    value = {'platform_name': '测试防火墙', 'hostname': 'waf-office',
             'database_timeout': 25, 'wal_autocheckpoint': 2000}
    assert client.put('/api/system/platform', json=value).status_code == 200
    assert Store(store.path).platform_config().model_dump() == value
    assert client.get('/api/system/platform').json()['config'] == value
    result = client.post('/api/system/database/test', json={}).json()
    assert result['ok'] and result['busy_timeout_ms'] == 25000
    assert result['wal_autocheckpoint'] == 2000
    assert result['journal_mode'] == 'wal'
    with store.connect() as db:
        assert db.execute("SELECT name FROM sqlite_master WHERE name='connection_probe'").fetchone() is None
    assert store.events()[0]['rule_id'] == 'PLATFORM_CONFIG'


@pytest.mark.parametrize('change', [{'hostname':'bad;id'}, {'hostname':'UPPER'},
    {'hostname':'-bad'}, {'platform_name':'   '}, {'database_timeout':0},
    {'wal_autocheckpoint':99}, {'database_password':'secret'}])
def test_invalid_platform_config(client, change):
    client, store = client
    original = store.platform_config().model_dump()
    assert client.put('/api/system/platform', json={**original, **change}).status_code == 422
    assert store.platform_config().model_dump() == original


def test_platform_auth_and_origin(client):
    client, store = client
    bad = {'Authorization': 'Basic '+base64.b64encode(b'admin:wrong').decode()}
    assert client.get('/api/system/platform', headers=bad).status_code == 401
    assert client.post('/api/system/database/test', json={}, headers={'Origin':'http://evil'}).status_code == 403
    assert client.post('/api/system/database/test', json={}, headers=bad).status_code == 401
