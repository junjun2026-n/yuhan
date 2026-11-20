# ============================================================
# 文件名称：test_honeypot.py
# 生成日期：2026-11-18
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：验证 honeypot 相关功能。
#           文件用途：用于开发验证及功能回归。
#           注意事项：使用隔离测试环境，避免操作正式业务数据。
# ============================================================
import httpx
import pytest
from fastapi.testclient import TestClient
from waf.main import SettingsInput, create_app


@pytest.mark.parametrize('url', ['file:///tmp/a', 'http://user:pass@decoy.test', 'http://decoy.test/path', 'http://decoy.test:8300'])
def test_invalid_honeypot(url):
    with pytest.raises(ValueError):
        SettingsInput(honeypot_url=url)


def test_enabled_requires_address():
    with pytest.raises(ValueError):
        SettingsInput(honeypot_enabled=True)


@pytest.mark.parametrize('failed', [False, True])
def test_attack_diversion_and_normal_routing(tmp_path, failed):
    requests = []
    def handler(request):
        requests.append(request)
        if failed and request.url.host == 'decoy.test':
            raise httpx.ConnectError('offline')
        return httpx.Response(200, stream=httpx.ByteStream(request.url.host.encode()), headers={'set-cookie': 'decoy=1'})
    app = create_app(database=tmp_path/'waf.db', transport=httpx.MockTransport(handler))
    app.state.store.save(SettingsInput(upstream='http://origin.test', honeypot_enabled=True, honeypot_url='http://decoy.test').model_dump())
    with TestClient(app) as client:
        attack = client.post('/.env?q=123', content=b'sample', headers={'Authorization': 'secret', 'Cookie': 'session=secret', 'X-WAF-Rule': 'forged'})
        assert attack.status_code == (403 if failed else 200)
        assert len(requests) == 1
        assert str(requests[0].url) == 'http://decoy.test/.env?q=123'
        assert requests[0].content == b'sample'
        assert 'authorization' not in requests[0].headers and 'cookie' not in requests[0].headers
        assert requests[0].headers['x-waf-rule'] != 'forged'
        assert 'set-cookie' not in attack.headers
        event = app.state.store.events()[0]
        assert event['action'] == 'blocked'
        assert event['rule_id'].endswith(':HONEYPOT_FAILED' if failed else ':HONEYPOT')
        assert client.get('/normal').text == 'origin.test'
        assert client.get('/', headers={'Host': 'bad.test'}).status_code == 200


def test_default_disabled_and_monitor(tmp_path):
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(200, stream=httpx.ByteStream(request.url.host.encode()))
    app = create_app(database=tmp_path/'waf.db', transport=httpx.MockTransport(handler))
    with TestClient(app) as client:
        assert client.get('/.env').status_code == 403
        assert not requests
        app.state.store.save(SettingsInput(upstream='http://origin.test', mode='monitor', honeypot_enabled=True, honeypot_url='http://decoy.test').model_dump())
        assert client.get('/.env').text == 'origin.test'
