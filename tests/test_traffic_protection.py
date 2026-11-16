import asyncio
import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from waf.main import create_app
from waf.store import Store
from waf.migrate import migrate
from waf.traffic_protection import CCConfig, PortConfig, ProtectionConfig, TrafficGuard, configuration, save


def test_cc_window_ban_expiry_capacity_and_policy_reset():
    now=[0.0]
    guard=TrafficGuard(clock=lambda:now[0],capacity=2)
    config=ProtectionConfig(cc=CCConfig(enabled=True,window_seconds=5,max_requests=2,ban_seconds=10))
    assert not guard.enter('a',config)[0]
    assert not guard.enter('a',config)[0]
    assert guard.enter('a',config)[:3]==('CC_RATE',429,10)
    now[0]=6
    assert guard.enter('a',config)[:3]==('CC_BAN',429,4)
    assert not guard.enter('b',config)[0]
    assert guard.enter('c',config)[0]=='CC_CAPACITY'
    now[0]=10
    assert not guard.enter('a',config)[0]
    now[0]=16
    assert not guard.enter('c',config)[0]
    config.cc.max_requests=3
    assert not guard.enter('a',config)[0]
    config.cc.enabled=False
    for _ in range(10): assert not guard.enter('a',config)[0]


def test_port_cidr_precedence_and_concurrency_survives_config_change():
    guard=TrafficGuard()
    config=ProtectionConfig(ports=PortConfig(enabled=True,allowed_sources=['192.0.2.0/24','2001:db8::/32'],blocked_sources=['192.0.2.1/32'],max_concurrent_per_ip=1,max_concurrent_total=2))
    assert guard.enter('192.0.2.1',config)[0]=='PORT_DENY'
    assert guard.enter('198.51.100.1',config)[0]=='PORT_ALLOW'
    assert guard.enter('2001:db8::1',config)[3]
    assert guard.enter('2001:db8::1',config)[0]=='PORT_CONCURRENT'
    assert guard.enter('192.0.2.2',config)[3]
    assert guard.enter('192.0.2.3',config)[0]=='PORT_CAPACITY'
    config.ports.enabled=False
    assert not guard.enter('192.0.2.2',config)[3]
    guard.leave('192.0.2.2',True)
    config.ports.enabled=True
    assert guard.enter('192.0.2.3',config)[3]
    guard.leave('2001:db8::1',True);guard.leave('192.0.2.3',True)
    assert guard.total==0 and not guard.active


@pytest.mark.parametrize('value',[
    {'cc':{'window_seconds':0}}, {'cc':{'max_requests':0}}, {'cc':{'ban_seconds':86401}},
    {'ports':{'max_concurrent_per_ip':0}}, {'ports':{'allowed_sources':['bad; drop']}},
    {'ports':{'blocked_sources':['192.0.2.1/99']}}])
def test_invalid_config(value):
    with pytest.raises(ValidationError): ProtectionConfig(**value)


@pytest.mark.parametrize('kind,target',[
    ('domain',''),('domain','http://example.com'),('domain','192.0.2.10'),('domain','example.com:8443'),
    ('ip','example.com'),('ip','192.0.2.0/24'),('ip','0.0.0.0'),('ip','::'),('invalid','example.com')])
def test_invalid_cc_binding(kind,target):
    with pytest.raises(ValidationError): CCConfig(target_type=kind,target=target)


def test_cc_bound_domains_are_isolated_and_nonmatching_requests_do_not_count():
    guard=TrafficGuard()
    config=ProtectionConfig(cc=CCConfig(enabled=True,target_type='domain',target='*.Example.COM.',max_requests=1))
    assert config.cc.target=='*.example.com'
    for _ in range(4):
        assert not guard.enter('192.0.2.1',config,host='unrelated.example.net')[0]
        assert not guard.enter('192.0.2.1',config,host='deep.app.example.com')[0]
        assert not guard.enter('192.0.2.1',config,host='example.com')[0]
    assert not guard.clients
    assert not guard.enter('192.0.2.1',config,host='app.example.com')[0]
    assert guard.enter('192.0.2.1',config,host='app.example.com')[0]=='CC_RATE'
    assert not guard.enter('192.0.2.1',config,host='other.example.com')[0]
    assert guard.enter('192.0.2.1',config,host='app.example.com')[0]=='CC_BAN'
    config.cc=CCConfig(enabled=True,target_type='domain',target='new.example.com',max_requests=1)
    assert not guard.enter('192.0.2.1',config,host='app.example.com')[0]
    assert not guard.enter('192.0.2.1',config,host='new.example.com')[0]


@pytest.mark.parametrize('destination',['192.0.2.10','2001:db8::10'])
def test_cc_binding_uses_socket_destination_and_not_spoofed_host(tmp_path,destination):
    async def exercise():
        app=create_app(database=tmp_path/'ip.db')
        save(app.state.store,ProtectionConfig(cc=CCConfig(enabled=True,target_type='ip',target=destination,max_requests=1)))
        async with app.router.lifespan_context(app):
            transport=httpx.ASGITransport(app=app,client=('198.51.100.3',456))
            # The ASGI server destination comes from the connected socket in Uvicorn.
            urlhost=f'[{destination}]' if ':' in destination else destination
            async with httpx.AsyncClient(transport=transport,base_url=f'https://{urlhost}:8443') as client:
                assert (await client.get('/',headers={'Host':'unrelated.example.com'})).status_code==503
                assert (await client.get('/',headers={'Host':'unrelated.example.com'})).status_code==429
            async with httpx.AsyncClient(transport=transport,base_url='http://192.0.2.11:8300') as client:
                for _ in range(3):
                    assert (await client.get('/',headers={'Host':destination,'X-Forwarded-Host':destination})).status_code==503
    asyncio.run(exercise())


def test_domain_binding_through_http_host_normalization(tmp_path):
    app=create_app(database=tmp_path/'host.db')
    save(app.state.store,ProtectionConfig(cc=CCConfig(enabled=True,target_type='domain',target='app.example.com',max_requests=1)))
    with TestClient(app,client=('192.0.2.1',123)) as client:
        assert client.get('/',headers={'Host':'APP.EXAMPLE.COM.:8443'}).status_code==503
        assert client.get('/',headers={'Host':'app.example.com'}).status_code==429
        assert client.get('/',headers={'Host':'other.example.com','X-Forwarded-Host':'app.example.com'}).status_code==503


def test_real_proxy_enforcement_audit_admin_isolation_and_migration(tmp_path,monkeypatch):
    monkeypatch.setenv('WAF_ADMIN_PASSWORD','test-password')
    path=tmp_path/'waf.db'
    admin=create_app('admin',database=path)
    proxy=create_app(database=path,transport=httpx.MockTransport(lambda request:httpx.Response(200,stream=httpx.ByteStream(b'ok'))))
    store=admin.state.store
    store.save({**store.settings(),'upstream':'http://origin.example','enabled':False,'mode':'monitor'})
    with TestClient(admin,headers={'Origin':'http://testserver'}) as management, TestClient(proxy,client=('192.0.2.1',1234)) as traffic:
        management.auth=('admin','test-password')
        assert management.get('/api/traffic-protection').json()['cc']['enabled'] is False
        assert management.put('/api/traffic-protection?section=cc',json={'cc':{'enabled':True,'max_requests':1}}).status_code==200
        assert traffic.get('/').status_code==200
        blocked=traffic.get('/')
        assert blocked.status_code==429 and int(blocked.headers['Retry-After'])>0
        assert store.events()[0]['rule_id']=='CC_RATE'
        assert blocked.headers['X-WAF-Request-ID']==store.events()[0]['request_id']
        assert management.get('/api/me').status_code==200
        assert management.put('/api/traffic-protection?section=ports',json={'ports':{'enabled':True,'allowed_sources':['198.51.100.0/24']}}).status_code==200
        assert management.get('/api/traffic-protection').json()['cc']['enabled'] is True
        assert traffic.get('/',headers={'X-Forwarded-For':'198.51.100.1'}).status_code==403
        assert store.events()[0]['rule_id']=='PORT_ALLOW'
        assert management.put('/api/traffic-protection',json={'cc':{'enabled':False},'ports':{'enabled':False}}).status_code==200
        assert traffic.get('/').status_code==200
        assert proxy.state.traffic_guard.total==0
        assert management.put('/api/traffic-protection?section=other',json={}).status_code==422
        # Rule permission is enforced independently from system/site permissions.
        management.post('/api/users',json={'username':'auditor','role':'auditor','password':'auditor-password'})
        management.auth=('auditor','auditor-password')
        assert management.get('/api/traffic-protection').status_code==403
        assert management.put('/api/traffic-protection',json={}).status_code==403
    target=Store(tmp_path/'copy.db');migrate(store,target)
    assert configuration(target)==configuration(store)


def test_concurrent_requests_hold_admission_until_completion_and_release_on_error(tmp_path):
    async def exercise():
        started=asyncio.Event();release=asyncio.Event()
        async def upstream(request):
            started.set();await release.wait()
            return httpx.Response(200,stream=httpx.ByteStream(b'ok'))
        app=create_app(database=tmp_path/'concurrent.db',transport=httpx.MockTransport(upstream))
        store=app.state.store
        store.save({**store.settings(),'upstream':'http://origin.example'})
        save(store,ProtectionConfig(ports=PortConfig(enabled=True,max_concurrent_per_ip=1)))
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app,client=('192.0.2.5',123)),base_url='http://testserver') as client:
                first=asyncio.create_task(client.get('/'))
                try:
                    await asyncio.wait_for(started.wait(),5)
                    assert (await client.get('/')).status_code==429
                finally: release.set()
                assert (await first).status_code==200
                assert (await client.get('/')).status_code==200
                assert app.state.traffic_guard.total==0
                async def failed(request): raise httpx.ConnectError('failed')
                app.state.client._transport=httpx.MockTransport(failed)
                assert (await client.get('/')).status_code==502
                assert app.state.traffic_guard.total==0
    asyncio.run(exercise())
