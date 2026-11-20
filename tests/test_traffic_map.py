# ============================================================
# 文件名称：test_traffic_map.py
# 生成日期：2026-11-05
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：验证 traffic_map 相关功能。
#           文件用途：用于开发验证及功能回归。
#           注意事项：使用隔离测试环境，避免操作正式业务数据。
# ============================================================
from datetime import datetime,timedelta,timezone

import pytest
from fastapi.testclient import TestClient

from waf.main import create_app
from waf.store import Store
from waf.traffic_map import traffic_map,coordinates


def assert_map(store):
    for i in range(5):store.event(str(i),'8.8.8.8','GET','/','blocked','SQLI-001',403,'app.example.com')
    store.event('cn','223.5.5.5','GET','/','allowed','',200,'app.example.com')
    store.event('v6','2606:4700:4700::1111','GET','/','detected','XSS-001',200,'other.example.com')
    store.event('local','192.168.1.1','GET','/','allowed','',200)
    store.event('admin','admin','PUT','/','admin','CONFIG',200)
    store.event('unknown','1.1.1.1','GET','/','error','UPSTREAM',502)
    store.event('old','9.9.9.9','GET','/','allowed','',200)
    with store.connect() as db:
        db.execute("UPDATE events SET country='ZZ' WHERE request_id='unknown'")
        db.execute('UPDATE events SET created_at=? WHERE request_id=?',((datetime.now(timezone.utc)-timedelta(days=40)).isoformat(),'old'))
    result=traffic_map(store,'24h')
    assert result['totals']['requests']==8 and result['totals']['sources']==4
    assert result['totals']['unlocated_requests']==1 and result['totals']['mapped_sources']==3
    assert result['nodes'][0]['ip']=='8.8.8.8' and result['nodes'][0]['blocked']==5
    assert result['nodes'][0]['longitude']==coordinates()['US'][0]
    assert result['nodes'][0]['latitude']==coordinates()['US'][1]
    assert next(n for n in result['nodes'] if n['ip']=='1.1.1.1')['latitude'] is None
    assert {n['ip'] for n in result['nodes']}=={'8.8.8.8','223.5.5.5','2606:4700:4700::1111','1.1.1.1'}
    assert result['domains']==[{'domain':'app.example.com','requests':6},{'domain':'other.example.com','requests':1}]
    assert result['location_precision']=='country' and result['metric']=='requests'
    for node in result['nodes']:
        assert store.events_page('business',ip=node['ip'],external=True,since=result['since'],until=result['until'])['total']==node['requests']
    assert traffic_map(store,'all')['totals']['requests']==9


def test_map_totals_geography_and_drilldown(tmp_path):
    assert_map(Store(tmp_path/'map.db'))


def test_map_empty_and_limit(tmp_path):
    store=Store(tmp_path/'limit.db');empty=traffic_map(store)
    assert empty['nodes']==[] and empty['totals']['requests']==0
    for i in range(25):store.event(str(i),f'8.8.8.{i+1}','GET','/','allowed','',200)
    result=traffic_map(store,limit=10)
    assert len(result['nodes'])==10 and result['totals']['sources']==25
    assert result['totals']['shown_requests']==10 and result['totals']['requests']==25
    assert [n['ip'] for n in result['nodes']]==sorted(n['ip'] for n in result['nodes'])


def test_map_api_authorization_validation_and_static_assets(tmp_path,monkeypatch):
    monkeypatch.setenv('WAF_ADMIN_PASSWORD','map-test-password')
    app=create_app('admin',database=tmp_path/'api.db')
    with TestClient(app) as client:
        assert client.get('/api/stats/traffic-map').status_code==401
        client.auth=('admin','map-test-password')
        assert client.get('/api/stats/traffic-map').status_code==200
        for query in ('period=invalid','limit=0','limit=301'):
            assert client.get('/api/stats/traffic-map?'+query).status_code==422
        assert len(client.get('/world-map.json').json()['features'])>150
        assert client.get('/traffic-map.js').status_code==200
        from waf import accounts
        for name,permissions in [('summary',['overview']),('no-overview',['audit'])]:
            accounts.change(app.state.store,name,accounts.UserInput(username=name,password='map-user-password',role='custom',permissions=permissions),create=True)
            client.auth=(name,'map-user-password')
            expected=200 if name=='summary' else 403
            assert client.get('/api/stats/traffic-map').status_code==expected
            assert client.get('/world-map.json').status_code==expected
        assert {'HK','SG','CN','US','GB','FR','TW','MO'}<=coordinates().keys()
