import pytest
from fastapi.testclient import TestClient
from waf.main import create_app
from waf import accounts, sessions


@pytest.fixture
def app(tmp_path,monkeypatch):
    monkeypatch.setenv('WAF_ADMIN_PASSWORD','test-password')
    return create_app('admin',database=tmp_path/'sessions.db')


def login(client):
    return client.post('/api/login',json={'username':'admin','password':'test-password'})


def test_logout_revokes_replay_and_blocks_cached_basic(app):
    with TestClient(app,headers={'Origin':'http://testserver'}) as client:
        assert login(client).status_code==200
        token=client.cookies.get(sessions.COOKIE)
        assert client.get('/api/me').status_code==200
        assert client.post('/api/logout',json={}).status_code==200
        assert client.get('/api/me',auth=('admin','test-password')).status_code==401
        assert client.get('/',headers={'Accept':'text/html'},follow_redirects=False).headers['location']=='/login'
        client.cookies.clear()
        client.cookies.set(sessions.COOKIE,token,domain='testserver.local')
        response=client.get('/api/me',auth=('admin','test-password'))
        assert response.status_code==401 and 'www-authenticate' not in response.headers
        assert login(client).status_code==200
        assert client.cookies.get(sessions.COOKIE)!=token
        assert client.get('/api/me').status_code==200


def test_login_errors_csrf_and_cookie_flags(app):
    with TestClient(app,headers={'Origin':'http://testserver'}) as client:
        assert client.post('/api/login',json={'username':'admin','password':'wrong'}).status_code==401
        assert login(client).status_code==200
        token=client.cookies.get(sessions.COOKIE)
        assert client.post('/api/logout',json={},headers={'Origin':'http://evil.test'}).status_code==403
        assert client.cookies.get(sessions.COOKIE)==token
        assert client.get('/api/me').status_code==200
        response=login(client)
        cookie=next(value for value in response.headers.get_list('set-cookie') if value.startswith(sessions.COOKIE+'='))
        assert 'HttpOnly' in cookie
        assert 'SameSite=strict' in cookie


def test_sessions_shared_between_apps_and_invalidated_by_password(app):
    with TestClient(app,headers={'Origin':'http://testserver'}) as client:
        login(client).raise_for_status()
        token=client.cookies.get(sessions.COOKIE)
        other=create_app('admin',database=app.state.store.path)
        with TestClient(other) as second:
            second.cookies.set(sessions.COOKIE,token)
            assert second.get('/api/me').status_code==200
            assert client.post('/api/me/password',json={'current_password':'test-password','new_password':'new-test-password'}).status_code==200
            assert second.get('/api/me').status_code==401


def test_expired_session_and_disabled_account(app,monkeypatch):
    with TestClient(app,headers={'Origin':'http://testserver'}) as client:
        login(client).raise_for_status()
        with app.state.store.connect() as db:
            db.execute('UPDATE web_sessions SET expires=0')
        assert client.get('/api/me').status_code==401
        login(client).raise_for_status()
        accounts.mutate(app.state.store,lambda users: users[0].update(enabled=False))
        assert client.get('/api/me').status_code==401


def test_web_redirect_login_and_public_assets(app):
    with TestClient(app) as client:
        assert client.get('/',headers={'Accept':'text/html'}).url.path=='/login'
        assert client.get('/login.js').status_code==200
        assert client.get('/login.css').status_code==200
        assert client.get('/api/settings').status_code==401


def test_browser_cached_basic_cannot_bypass_login(app):
    with TestClient(app) as client:
        client.auth=('admin','test-password')
        response=client.get('/',headers={'Accept':'text/html'},follow_redirects=False)
        assert response.status_code==303 and response.headers['location']=='/login'
        response=client.get('/api/me',headers={'Sec-Fetch-Mode':'cors'})
        assert response.status_code==401 and 'www-authenticate' not in response.headers
        assert client.get('/api/me').status_code==200


def test_proxy_does_not_forward_management_session(tmp_path):
    import httpx
    seen=[]
    def upstream(request):
        seen.append(request.headers.get('cookie'))
        return httpx.Response(200,stream=httpx.ByteStream(b'ok'))
    proxy=create_app(database=tmp_path/'proxy.db',transport=httpx.MockTransport(upstream))
    proxy.state.store.save({**proxy.state.store.settings(),'upstream':'http://origin.test'})
    with TestClient(proxy) as client:
        assert client.get('/',headers={'Cookie':'waf_session=secret; business=value; waf_logged_out=1'}).status_code==200
        assert seen==['business=value']
