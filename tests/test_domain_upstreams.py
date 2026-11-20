# ============================================================
# 文件名称：test_domain_upstreams.py
# 生成日期：2026-11-15
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：验证 domain_upstreams 相关功能。
#           文件用途：用于开发验证及功能回归。
#           注意事项：使用隔离测试环境，避免操作正式业务数据。
# ============================================================
import httpx
import pytest
from fastapi.testclient import TestClient

from waf.main import SettingsInput, create_app


def setup_proxy(tmp_path, handler):
    app = create_app(database=tmp_path/'origins.db', transport=httpx.MockTransport(handler))
    settings = SettingsInput(upstream='http://fallback.test',
        protected_domains=['one.example.com', 'two.example.com', '*.example.com'],
        domain_upstreams={'*.example.com':['http://wild.test'],
            'one.example.com':['http://first.test:8080', 'http://second.test:8080'],
            'two.example.com':['https://other.test']}).model_dump()
    app.state.store.save(settings)
    return app


def test_domain_rotation_wildcard_headers_and_rejection(tmp_path):
    requests = []
    def handle(request):
        requests.append(request)
        return httpx.Response(200, stream=httpx.ByteStream(b'ok'))
    app = setup_proxy(tmp_path, handle)
    with TestClient(app) as client:
        for domain in ['one.example.com', 'one.example.com', 'one.example.com',
                       'two.example.com', 'sub.example.com']:
            assert client.get('/a%20b?value=1', headers={'Host':domain.upper()+':8300'}).status_code == 200
        assert [request.url.host for request in requests] == ['first.test','second.test','first.test','other.test','wild.test']
        assert str(requests[0].url) == 'http://first.test:8080/a%20b?value=1'
        assert requests[0].headers['host'] == 'ONE.EXAMPLE.COM:8300'
        assert client.get('/', headers={'Host':'evil.test'}).status_code == 403
        assert len(requests) == 5
        settings = app.state.store.settings()
        settings['domain_upstreams'] = {}
        app.state.store.save(settings)
        assert client.get('/', headers={'Host':'one.example.com'}).status_code == 200
        assert requests[-1].url.host == 'fallback.test'
        settings['upstream'] = ''
        app.state.store.save(settings)
        assert client.get('/', headers={'Host':'one.example.com'}).status_code == 503


@pytest.mark.parametrize('method,error,expected', [
    ('GET', httpx.ConnectError, 200), ('HEAD', httpx.ConnectTimeout, 200),
    ('POST', httpx.ConnectError, 502), ('PUT', httpx.ConnectError, 502),
    ('GET', httpx.ReadTimeout, 502), ('GET', httpx.ReadError, 502)])
def test_failover_only_safe_requests_and_connect_failures(tmp_path, method, error, expected):
    hosts = []
    def handle(request):
        hosts.append(request.url.host)
        if request.url.host == 'first.test':
            raise error('failed', request=request)
        return httpx.Response(200, stream=httpx.ByteStream(b'ok'))
    with TestClient(setup_proxy(tmp_path, handle)) as client:
        assert client.request(method, '/', headers={'Host':'one.example.com'}).status_code == expected
        assert hosts == (['first.test','second.test'] if expected == 200 else ['first.test'])


@pytest.mark.parametrize('bindings', [
    {'evil.test':['http://origin.test']}, {'one.example.com':[]},
    {'one.example.com':['']}, {'one.example.com':['file:///tmp/data']},
    {'one.example.com':['http://user:pass@origin.test']},
    {'one.example.com':['http://origin.test/path']},
    {'one.example.com':['http://origin.test:8301']},
    {'one.example.com':['http://origin.test:0']},
    {'one.example.com':['http://origin.test?q=1']},
    {'one.example.com':['http://origin.test?']},
    {'one.example.com':['http://origin.test#frag']},
    {'one.example.com':['http://origin.test']*17}])
def test_invalid_origin_pools(bindings):
    with pytest.raises(ValueError):
        SettingsInput(protected_domains=['one.example.com'], domain_upstreams=bindings)


def test_save_and_reload_domain_pools(tmp_path, monkeypatch):
    monkeypatch.setenv('WAF_ADMIN_PASSWORD', 'test-password')
    path = tmp_path/'admin.db'
    app = create_app('admin', database=path)
    value = SettingsInput(protected_domains=['ONE.example.com'],
        domain_upstreams={'ONE.example.com':['http://origin.test/','http://origin.test/','https://other.test']}).model_dump()
    with TestClient(app, headers={'Origin':'http://testserver'}) as client:
        client.auth = ('admin','test-password')
        assert client.put('/api/settings', json=value).status_code == 200
        assert client.get('/api/settings').json()['domain_upstreams'] == {'one.example.com':['http://origin.test','https://other.test']}
    assert create_app('admin', database=path).state.store.settings()['domain_upstreams'] == value['domain_upstreams']
