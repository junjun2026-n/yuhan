"""Opt-in real PostgreSQL tests in an isolated disposable schema."""
import os
import uuid

import pytest

from waf.store import Store
from waf.migrate import migrate
from waf.platform_config import PlatformConfig, test_database as probe_database, status


@pytest.fixture
def pgstore():
    if not os.getenv('WAF_TEST_POSTGRES_CONFIG'): pytest.skip('PostgreSQL integration not configured')
    from dotenv import dotenv_values
    import psycopg
    from psycopg.conninfo import make_conninfo
    values = dotenv_values(os.environ['WAF_TEST_POSTGRES_CONFIG'])
    conninfo = make_conninfo(host=values['WAF_DB_HOST'], port=values['WAF_DB_PORT'],
        dbname=values['WAF_DB_NAME'], user=values['WAF_DB_USER'], password=values['WAF_DB_PASSWORD'], connect_timeout=10)
    schema = 'waf_test_'+uuid.uuid4().hex
    with psycopg.connect(conninfo, autocommit=True) as db:
        db.execute(f'CREATE SCHEMA {schema}')
        try:
            yield Store(make_conninfo(conninfo, options=f'-c search_path={schema}'))
        finally:
            db.execute(f'DROP SCHEMA {schema} CASCADE')


def test_postgres_overview_and_drilldown(pgstore):
    from test_reporting import seed,assert_overview
    seed(pgstore);assert_overview(pgstore)


def test_postgres_threat_rankings(pgstore):
    from test_reporting import assert_threat_rankings
    assert_threat_rankings(pgstore)
    with pgstore.connect() as db:db.execute("UPDATE events SET threat_type='' WHERE rule_id='SQLI-001'")
    assert Store(pgstore.path).events_page('attacks',threat_type='SQLi')['total']==8


def test_postgres_traffic_map(pgstore):
    from test_traffic_map import assert_map
    assert_map(pgstore)


def test_postgres_storage_and_verified_migration(pgstore, tmp_path):
    source = Store(tmp_path/'source.sqlite3')
    from waf.traffic_protection import ProtectionConfig, CCConfig, save as save_protection, configuration
    save_protection(source,ProtectionConfig(cc=CCConfig(enabled=True,target_type='domain',target='app.example.com',max_requests=35)))
    source.save({**source.settings(), 'upstream':'http://example.org'})
    source.save_platform_config(PlatformConfig(platform_name='迁移测试'))
    source.save_network(source.network())
    source.save_bootstrap_state({'state':'completed'})
    source.agent_state({'state':'stopped'})
    from waf.custom_rules import CustomRule
    source.change_custom_rule('CUSTOM-migration',CustomRule(name='migration policy',source_ip='203.0.113.0/24').model_dump(mode='json'),create=True)
    for index in range(3): source.event(str(index), '127.0.0.1','GET','/test','blocked','TEST',403)
    report = migrate(source, pgstore)
    assert report['events']['rows'] == 3
    assert pgstore.settings() == source.settings()
    assert pgstore.network() == source.network()
    assert pgstore.platform_config().platform_name == '迁移测试'
    assert pgstore.bootstrap_state() == source.bootstrap_state()
    assert pgstore.agent_state() == source.agent_state()
    assert pgstore.events() == source.events()
    assert configuration(pgstore)==configuration(source)
    from waf.traffic_protection import PortConfig
    save_protection(pgstore,ProtectionConfig(ports=PortConfig(enabled=True,allowed_sources=['192.0.2.0/24'])),section='ports')
    assert configuration(pgstore).cc==configuration(source).cc
    assert configuration(pgstore).ports.enabled
    from waf.traffic_protection import change_rule
    for section in ('cc','ports'):
        for index in range(2):
            change_rule(pgstore,section,{'name':f'policy {index}','enabled':True})
    assert len(configuration(pgstore).cc_rules)==3
    assert len(configuration(pgstore).port_rules)==3
    identifier=configuration(pgstore).cc_rules[-1].id
    change_rule(pgstore,'cc',{'name':'edited','enabled':False},identifier)
    assert not configuration(pgstore).cc_rules[-1].enabled
    change_rule(pgstore,'cc',identifier=identifier,delete=True)
    assert len(configuration(pgstore).cc_rules)==2
    save_protection(pgstore,configuration(source))
    result = pgstore.events_page('blocked', 99, 2)
    assert (result['total'], result['pages'], result['page'], len(result['items'])) == (3, 2, 2, 1)
    assert pgstore.settings()['custom_rules']==source.settings()['custom_rules']
    pgstore.event('next', 'admin', 'PUT', '/api/settings', 'admin','CONFIG',200)
    assert pgstore.events()[0]['id'] == 4
    assert pgstore.stats()['blocked'] == 3
    assert pgstore.stats()['total'] == 3
    assert probe_database(pgstore)['ok']
    assert status(pgstore)['database']['engine'] == 'PostgreSQL'
    assert 'password' not in str(status(pgstore))
    with pytest.raises(ValueError): migrate(source, pgstore)
    pgstore.import_bootstrap_network(pgstore.network(), pgstore.network(), {'state':'completed'})
    restored=Store(tmp_path/'restored.sqlite3')
    reverse=migrate(pgstore,restored)
    assert reverse['events']['rows']==4
    assert restored.events()==pgstore.events()
    assert restored.settings()==pgstore.settings()


def test_postgres_admin_api(pgstore, monkeypatch):
    from waf import database_config
    monkeypatch.setattr(database_config,'database_target',lambda *_: pgstore.path)
    initialized=database_config.initialize_database(database_config.DatabaseConfig(engine='postgresql',host='test.example',name='test',user='test',password='test'))
    assert initialized['ok'] and initialized['tables']['settings']==1
    from fastapi.testclient import TestClient
    from waf.main import create_app
    monkeypatch.setenv('WAF_ADMIN_PASSWORD', 'pg-api-test')
    app = create_app('admin', database=pgstore.path)
    with TestClient(app, headers={'Origin':'http://testserver'}) as client:
        client.auth = ('admin', 'pg-api-test')
        result = client.get('/api/system/platform')
        assert result.status_code == 200
        assert result.json()['database']['engine'] == 'PostgreSQL'
        assert 'password' not in result.text
        assert client.put('/api/system/platform', json=PlatformConfig(platform_name='PG 平台').model_dump()).status_code == 200
        assert client.post('/api/system/database/test', json={}).json()['ok']
        assert client.get('/api/events').json()[0]['rule_id'] == 'PLATFORM_CONFIG'
        assert client.get('/api/stats').status_code == 200
        stale=client.get('/api/settings').json()
        created=client.post('/api/custom-rules',json={'name':'PG blacklist','source_ip':'203.0.113.0/24'})
        assert created.status_code==200
        identifier=created.json()['id']
        assert client.put('/api/settings',json=stale).status_code==200
        assert client.get('/api/custom-rules').json()[0]['id']==identifier
        assert client.put('/api/custom-rules/'+identifier,json={'name':'PG whitelist','source_ip':'203.0.113.0/24','action':'allow'}).status_code==200
        assert client.request('DELETE','/api/custom-rules/'+identifier,json={}).status_code==200
        assert client.get('/api/custom-rules').json()==[]
