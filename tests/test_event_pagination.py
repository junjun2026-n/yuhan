from fastapi.testclient import TestClient

from waf.main import create_app


def test_event_pagination_and_validation(tmp_path, monkeypatch):
    monkeypatch.setenv('WAF_ADMIN_PASSWORD', 'test-password')
    app = create_app('admin', database=tmp_path/'events.sqlite3')
    store = app.state.store
    with TestClient(app) as client:
        client.auth = ('admin', 'test-password')
        empty = client.get('/api/events?paginated=true&action=blocked').json()
        assert empty == {'items': [], 'total': 0, 'page': 1, 'page_size': 100, 'pages': 0}
        for index in range(100):
            store.event(str(index), '127.0.0.1', 'GET', '/', 'blocked', 'TEST', 403)
        for index in range(5):
            store.event(str(index), '127.0.0.1', 'GET', '/', 'allowed', '', 200)
        first = client.get('/api/events?paginated=true&action=blocked&page_size=50').json()
        last = client.get('/api/events?paginated=true&action=blocked&page_size=50&page=99').json()
        assert (first['total'], first['pages'], len(first['items'])) == (100, 2, 50)
        assert (last['page'], len(last['items'])) == (2, 50)
        assert not ({row['id'] for row in first['items']} & {row['id'] for row in last['items']})
        assert all(row['action'] == 'blocked' for row in first['items'] + last['items'])
        all_events = client.get('/api/events?paginated=true&page_size=50').json()
        assert (all_events['total'], all_events['pages']) == (105, 3)
        assert len(client.get('/api/events').json()) == 100
        for query in ('page_size=0', 'page_size=501', 'page=0', 'action=unknown', 'page_size=x'):
            assert client.get('/api/events?paginated=true&' + query).status_code == 422
