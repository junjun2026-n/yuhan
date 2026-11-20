# ============================================================
# 文件名称：test_origin_rules.py
# 生成日期：2026-11-15
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：验证 origin_rules 相关功能。
#           文件用途：用于开发验证及功能回归。
#           注意事项：使用隔离测试环境，避免操作正式业务数据。
# ============================================================
import httpx
import pytest
from fastapi.testclient import TestClient
from waf.main import SettingsInput, create_app


def test_complex_domain_port_path_rules(tmp_path):
    seen=[]
    def upstream(request):
        seen.append(request.url.host)
        return httpx.Response(200,stream=httpx.ByteStream(b'ok'))
    app=create_app(database=tmp_path/'rules.db',transport=httpx.MockTransport(upstream))
    app.state.store.save(SettingsInput(protected_domains=['api.example.com','*.example.com'],
        domain_upstreams={'api.example.com':['http://legacy.test']}, origin_rules=[
        {'domain':'*.example.com','path_prefix':'/v2','origins':['http://path.test']},
        {'domain':'api.example.com','port':8300,'path_prefix':'/v2','priority':200,'origins':['http://first.test','http://second.test']},
        {'domain':'api.example.com','port':8300,'path_prefix':'/v2/deep','priority':200,'origins':['http://deep.test']},
    ]).model_dump())
    with TestClient(app) as client:
        for path,host in [('/v2/a','api.example.com:8300'),('/v2/a','api.example.com:8300'),
                          ('/v2/deep/a','api.example.com:8300'),('/v2/a','api.example.com:8301'),('/other','api.example.com:8300')]:
            assert client.get(path,headers={'Host':host}).status_code==200
    assert seen==['first.test','second.test','deep.test','path.test','legacy.test']


@pytest.mark.parametrize('change',[{'path_prefix':'x'},{'port':0},{'domain':'evil.test'},{'origins':['file:///tmp/a']}])
def test_complex_rule_validation(change):
    with pytest.raises(ValueError):
        SettingsInput(protected_domains=['a.example.com'],origin_rules=[{'domain':'a.example.com','origins':['http://a.test'],**change}])
