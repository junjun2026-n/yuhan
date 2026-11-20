# ============================================================
# 文件名称：test_waf.py
# 生成日期：2026-10-27
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：验证 waf 相关功能。
#           文件用途：用于开发验证及功能回归。
#           注意事项：使用隔离测试环境，避免操作正式业务数据。
# ============================================================
import httpx
import pytest
from fastapi.testclient import TestClient

from waf.main import SettingsInput, create_app
from waf.rules import inspect, RateLimiter


@pytest.fixture
def proxy(tmp_path):
    requests = []
    def upstream(request):
        requests.append(request)
        return httpx.Response(200, headers=[('set-cookie','a=1'),('set-cookie','b=2')],
                              stream=httpx.ByteStream(b'upstream ok'))
    app = create_app(database=tmp_path/'test.db', transport=httpx.MockTransport(upstream))
    app.state.store.save(SettingsInput(upstream='http://origin.test').model_dump())
    with TestClient(app) as client:
        yield client, app.state.store, requests


def test_proxy_forward_and_headers(proxy):
    client, store, requests = proxy
    response = client.get('/hello?key=private', headers={'X-Forwarded-For':'evil','Connection':'X-Remove', 'X-Remove':'gone'})
    assert response.status_code == 200
    assert response.text == 'upstream ok'
    assert response.headers.get_list('set-cookie') == ['a=1', 'b=2']
    assert str(requests[0].url) == 'http://origin.test/hello?key=private'
    assert requests[0].headers['x-forwarded-for'] == 'testclient'
    assert 'x-remove' not in requests[0].headers
    assert store.events()[0]['path'] == '/hello'
    assert 'private' not in str(store.events())


@pytest.mark.parametrize('path', ['/search?q=1%20union%20select%20password', '/?q=%3Cscript%3E',
                                  '/?file=%252e%252e%252fetc/passwd', '/.env', '/?q=;whoami'])
def test_block_attacks(proxy, path):
    client, store, requests = proxy
    assert client.get(path).status_code == 403
    assert not requests
    assert store.events()[0]['action'] == 'blocked'


def test_monitor_and_disable_rule(proxy):
    client, store, requests = proxy
    settings = store.settings()
    settings['mode'] = 'monitor'
    store.save(settings)
    assert client.get('/?q=<script>').status_code == 200
    assert store.events()[0]['action'] == 'detected'
    settings.update(mode='block', disabled_rules=['XSS-001'])
    store.save(settings)
    assert client.get('/?q=<script>').status_code == 200
    assert store.events()[0]['action'] == 'allowed'


def test_limits(proxy):
    client, store, requests = proxy
    settings = store.settings()
    settings.update(max_body_bytes=1024, rate_limit=2)
    store.save(settings)
    assert client.post('/', content=b'a'*1025).status_code == 413
    assert client.request('TRACE','/').status_code == 405
    assert client.get('/').status_code == 200
    assert client.get('/',headers={'X-Forwarded-For':'another'}).status_code == 429


def test_no_upstream(proxy):
    client, store, requests = proxy
    settings = store.settings(); settings['upstream'] = ''; store.save(settings)
    assert client.get('/').status_code == 503


def test_upstream_error(tmp_path):
    def failed(request): raise httpx.ConnectError('unavailable')
    app=create_app(database=tmp_path/'test.db', transport=httpx.MockTransport(failed))
    app.state.store.save(SettingsInput(upstream='http://origin.test').model_dump())
    with TestClient(app) as client:
        assert client.get('/').status_code == 502
    assert app.state.store.stats()['errors'] == 1


def test_management_auth_and_csrf(tmp_path, monkeypatch):
    monkeypatch.setenv('WAF_ADMIN_USER','admin')
    monkeypatch.setenv('WAF_ADMIN_PASSWORD','test-password')
    app=create_app('admin', database=tmp_path/'admin.db')
    with TestClient(app) as client:
        assert client.get('/').status_code == 401
        assert client.get('/api/settings',auth=('admin','wrong')).status_code == 401
        client.auth=('admin','test-password')
        assert '安全控制台' in client.get('/').text
        assert client.get('/app.js').status_code == 200
        assert client.get('/app.css').status_code == 200
        settings=SettingsInput(upstream='http://origin.test').model_dump()
        assert client.put('/api/settings',json=settings).status_code == 403
        assert client.put('/api/settings',json=settings,headers={'Origin':'http://evil.test'}).status_code == 403
        assert client.put('/api/settings',json=settings,headers={'Origin':'http://testserver'}).status_code == 200
        assert client.get('/api/settings').json()['upstream'] == 'http://origin.test'
        assert client.get('/api/stats').json()['total'] == 0


@pytest.mark.parametrize('url',['file:///etc/passwd','http://user:pass@origin.test','http://origin.test/path',
                                'http://origin.test:8300','http://origin.test?q=1','http://origin.test:99999'])
def test_upstream_validation(url):
    with pytest.raises(ValueError): SettingsInput(upstream=url)


def test_limiter_window(monkeypatch):
    now=[0]
    monkeypatch.setattr('waf.rules.time.monotonic',lambda:now[0])
    limiter=RateLimiter()
    assert limiter.allow('client',1)
    assert not limiter.allow('client',1)
    now[0]=61
    assert limiter.allow('client',1)


def test_encoded_rules():
    assert inspect(['%253Cscript%253E']) == 'XSS-001'
    assert inspect(['ordinary search']) == ''
