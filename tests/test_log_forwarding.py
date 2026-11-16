import json
import socket
import threading

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from waf import log_forwarding as logs
from waf.main import create_app
from waf.store import Store
from waf.migrate import migrate


def test_udp_backlog_and_persistent_cursor(tmp_path):
    store = Store(tmp_path/'source.db')
    store.event('one', '127.0.0.1', 'GET', '/example', 'blocked', 'SQL', 403)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        receiver.bind(('127.0.0.1', 0)); receiver.settimeout(2)
        logs.save_config(store, logs.LogConfig(enabled=True, host='127.0.0.1', port=receiver.getsockname()[1]))
        assert logs.forward_batch(store)
        event = json.loads(receiver.recv(65535))
        assert event['request_id']=='one' and event['action']=='blocked'
        assert not logs.forward_batch(Store(tmp_path/'source.db'))
        assert logs.public_status(store)['pending']==0
    target = Store(tmp_path/'target.db')
    assert migrate(store, target)['log_forwarding']['rows']==1
    assert logs.configuration(target)==logs.configuration(store)


def test_retry_keeps_failed_record_and_does_not_overwrite_config(tmp_path, monkeypatch):
    store = Store(tmp_path/'source.db')
    store.event('one', 'ip', 'GET', '/', 'allowed', '', 200)
    config = logs.LogConfig(enabled=True, host='127.0.0.1', protocol='tcp')
    logs.save_config(store, config)
    def fail(*args): raise OSError('offline')
    monkeypatch.setattr(logs, 'send', fail)
    assert not logs.forward_batch(store)
    assert logs.configuration(store)[1]['cursor']==0
    assert logs.public_status(store)['pending']==1
    sent=[]
    monkeypatch.setattr(logs, 'send', lambda *args: sent.append(args[1]))
    assert logs.forward_batch(store) and len(sent)==1
    assert not logs.configuration(store)[1]['last_error']


def test_tcp_framing_and_custom_escape(tmp_path):
    with socket.socket() as receiver:
        receiver.bind(('127.0.0.1',0)); receiver.listen(); receiver.settimeout(3)
        received=[]
        def collect():
            connection,_=receiver.accept()
            with connection:
                received.append(connection.recv(65535))
        thread=threading.Thread(target=collect);thread.start()
        config=logs.LogConfig(host='127.0.0.1',port=receiver.getsockname()[1],protocol='tcp',format='custom',template='{ip}|{path}|{status}')
        store=Store(tmp_path/'source.db')
        payload=logs.render(config,dict(ip='client',path='/a\nforged',status=200),store.platform_config())
        logs.send(config,payload);thread.join(4)
        assert received==[b'client|/a\\nforged|200\n']
        syslog=logs.render(logs.LogConfig(format='syslog'),dict(created_at='2026-10-28T00:00:00Z',action='blocked'),store.platform_config())
        assert syslog.startswith(b'<134>1 ')


@pytest.mark.parametrize('value', [dict(enabled=True),dict(host='bad'),dict(port=0),dict(protocol='http'),dict(template='{ip.__class__}'),dict(template='{status:90000}'),dict(template='{missing}'),dict(template='line\nbreak')])
def test_reject_invalid_configuration(value):
    with pytest.raises(ValidationError): logs.LogConfig(**value)


def test_logging_api_authorization_and_test_send(tmp_path,monkeypatch):
    monkeypatch.setenv('WAF_ADMIN_PASSWORD','test-password')
    app=create_app('admin',database=tmp_path/'source.db')
    with TestClient(app,headers={'Origin':'http://testserver'}) as client:
        assert client.get('/api/system/logging').status_code==401
        client.auth=('admin','test-password')
        config=dict(host='127.0.0.1',format='custom',template='{method}:{rule_id}')
        assert client.put('/api/system/logging',json=config,headers={'Origin':'http://evil'}).status_code==403
        assert client.put('/api/system/logging',json=config).status_code==200
        sent=[]
        monkeypatch.setattr(logs,'send',lambda *args:sent.append(args[1]))
        # Main imports send when creating the app, patch before creating another app.
        second=create_app('admin',database=tmp_path/'source.db')
        with TestClient(second,headers={'Origin':'http://testserver'}) as test_client:
            test_client.auth=('admin','test-password')
            response=test_client.post('/api/system/logging/test',json=config)
            assert response.status_code==200 and sent==[b'TEST:LOG_TEST']
            assert test_client.get('/api/system/logging').json()['config']['template']=='{method}:{rule_id}'
