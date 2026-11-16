from datetime import datetime, timedelta, timezone
import socket

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from waf.main import SettingsInput, create_app
from waf.tls import install_certificate, normalize_domain, domain_matches, TLSSupervisor, public_status


def test_per_domain_assignment_and_certificate_library(admin):
    client, store = admin
    first, first_key = make_certificate(('one.example.com',))
    second, second_key = make_certificate(('two.example.com',))
    one = client.post('/api/tls/certificate', json={'certificate':first,'private_key':first_key}).json()['id']
    assert store.settings()['tls_certificate']==''
    original = {**store.settings(), 'protected_domains':['one.example.com'], 'tls_enabled':True, 'tls_certificate':one}
    assert client.put('/api/settings',json=original).status_code==200
    two = client.post('/api/tls/certificate', json={'certificate':second,'private_key':second_key}).json()['id']
    assert store.settings()['tls_certificate']==one
    settings={**store.settings(), 'protected_domains':['one.example.com','two.example.com'], 'domain_certificates':{'two.example.com':two}}
    assert client.put('/api/settings',json=settings).status_code==200
    status=client.get('/api/tls').json()
    assert len(status['certificates'])==2 and status['domain_certificates']=={'two.example.com':two}
    assert first_key not in str(status) and second_key not in str(status)
    for bindings in [{'two.example.com':one},{'other.example.com':two},{'two.example.com':'../private.key'}]:
        assert client.put('/api/settings',json={**settings,'domain_certificates':bindings}).status_code==422
        assert store.settings()['domain_certificates']=={'two.example.com':two}
    assert client.put('/api/settings',json={**settings,'tls_certificate':'','domain_certificates':{'one.example.com':one,'two.example.com':two}}).status_code==200


def test_real_tls_sni_handshake_selects_different_certificates(admin):
    import ssl
    import threading
    from waf.tls import certificate_paths, configure_sni, validate_https, selected_certificate, listener_fingerprint
    client, store = admin
    wildcard, wildcard_key=make_certificate(('*.example.com',))
    exact, exact_key=make_certificate(('one.example.com',))
    wild=install_certificate(wildcard,wildcard_key)['id']
    one=install_certificate(exact,exact_key)['id']
    settings={**store.settings(),'tls_enabled':True,'protected_domains':['*.example.com','one.example.com'],
              'tls_certificate':wild,'domain_certificates':{'one.example.com':one}}
    validate_https(settings)
    assert selected_certificate(settings,'one.example.com')==one
    assert selected_certificate(settings,'two.example.com')==wild
    assert selected_certificate(settings,'deep.two.example.com')==''
    assert listener_fingerprint(settings)!=listener_fingerprint({**settings,'domain_certificates':{}})
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(*certificate_paths(wild))
    configure_sni(context,settings)
    errors=[]
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(5)
        def serve():
            try:
                for _ in range(3):
                    connection,_=listener.accept()
                    with connection:
                        connection.settimeout(3)
                        try:
                            with context.wrap_socket(connection,server_side=True): pass
                        except OSError: pass
            except Exception as exc: errors.append(str(exc))
        thread=threading.Thread(target=serve);thread.start()
        client_context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_context.check_hostname=False;client_context.verify_mode=ssl.CERT_NONE
        try:
            for hostname,pem in [('one.example.com',exact),('two.example.com',wildcard)]:
                with socket.create_connection(listener.getsockname(),timeout=3) as connection:
                    with client_context.wrap_socket(connection,server_hostname=hostname) as secure:
                        assert secure.getpeercert(binary_form=True)==ssl.PEM_cert_to_DER_cert(pem)
            with socket.create_connection(listener.getsockname(),timeout=3) as connection:
                with pytest.raises(ssl.SSLError): client_context.wrap_socket(connection,server_hostname='unknown.test')
        finally: thread.join(6)
        assert not errors and not thread.is_alive()


def test_https_runner_serves_sni_and_audits_requests(admin, monkeypatch, tmp_path):
    import os
    import ssl
    import subprocess
    import sys
    import time
    client, store = admin
    identifiers=[]
    pems=[]
    for domain in ['one.example.com','two.example.com']:
        pem,key=make_certificate((domain,))
        identifiers.append(install_certificate(pem,key)['id']);pems.append(pem)
    with socket.socket() as probe:
        probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
    store.save({**store.settings(),'tls_enabled':True,'tls_port':port,'protected_domains':['one.example.com','two.example.com'],
        'domain_certificates':dict(zip(['one.example.com','two.example.com'],identifiers))})
    env=dict(os.environ,WAF_DATABASE=store.path,WAF_DB_ENGINE='sqlite',WAF_DATABASE_CONFIG=str(tmp_path/'unused.env'),WAF_ENV_FILE=str(tmp_path/'unused.env'))
    process=subprocess.Popen([sys.executable,'-m','waf.https'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
    try:
        deadline=time.monotonic()+15
        while True:
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=0.3): break
            except OSError:
                assert process.poll() is None, 'HTTPS runner exited during startup'
                if time.monotonic()>deadline: pytest.fail('HTTPS runner startup timed out')
                time.sleep(0.05)
        for domain,pem in zip(['one.example.com','two.example.com'],pems):
            with socket.create_connection(('127.0.0.1',port),timeout=3) as connection:
                with context.wrap_socket(connection,server_hostname=domain) as secure:
                    assert secure.getpeercert(binary_form=True)==ssl.PEM_cert_to_DER_cert(pem)
                    secure.sendall(f'GET /sni-check HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n'.encode())
                    assert b'503 Service Unavailable' in secure.recv(65535)
        assert len([event for event in store.events() if event['path']=='/sni-check' and event['rule_id']=='UPSTREAM'])==2
    finally:
        process.terminate()
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired: process.kill();process.wait(timeout=5)


def make_certificate(domains=('www.example.com','*.example.org'), expired=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=2))
        .not_valid_after(now+timedelta(days=-1 if expired else 30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain) for domain in domains]), critical=False)
        .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode(), key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()


@pytest.fixture
def admin(tmp_path, monkeypatch):
    monkeypatch.setenv('WAF_ADMIN_PASSWORD','test-password')
    monkeypatch.setenv('WAF_TLS_RUNTIME',str(tmp_path/'tls'))
    app=create_app('admin', database=tmp_path/'waf.db')
    with TestClient(app, headers={'Origin':'http://testserver'}) as client:
        client.auth=('admin','test-password')
        yield client,app.state.store


def test_upload_enable_and_secrets(admin):
    client,store=admin
    cert,key=make_certificate()
    result=client.post('/api/tls/certificate',json={'certificate':cert,'private_key':key})
    assert result.status_code==200
    info=result.json()
    assert info['domains']==['www.example.com','*.example.org']
    assert 'PRIVATE' not in str(info)
    settings={**store.settings(),'protected_domains':['www.example.com','app.example.org'],'tls_enabled':True,'tls_certificate':info['id']}
    assert client.put('/api/settings',json=settings).status_code==200
    assert client.get('/api/tls').json()['certificate']['id']==info['id']
    assert key not in str(store.events())+str(store.settings())
    assert client.put('/api/settings',json={**settings,'protected_domains':['evil.example.net']}).status_code==422
    assert client.put('/api/settings',json={**settings,'protected_domains':[]}).status_code==422
    assert client.put('/api/settings',json={**settings,'tls_port':8301}).status_code==422
    assert client.put('/api/settings',json={**settings,'tls_port':443,'upstream':'https://origin.example.net'}).status_code==200
    assert client.put('/api/settings',json={**settings,'tls_port':443,'upstream':'https://www.example.com'}).status_code==422
    assert client.put('/api/settings',json={**settings,'tls_port':443,'domain_upstreams':{'www.example.com':['https://www.example.com']}}).status_code==422
    assert client.put('/api/settings',json={**settings,'tls_port':443,'domain_upstreams':{'www.example.com':['http://10.0.0.11:8080','http://10.0.0.12:8080']}}).status_code==200
    assert client.post('/api/tls/certificate',json={'certificate':cert,'private_key':key},headers={'Origin':'http://evil'}).status_code==403


def test_invalid_certificates_do_not_replace_active(admin):
    client,store=admin
    cert,key=make_certificate()
    client.post('/api/tls/certificate',json={'certificate':cert,'private_key':key}).raise_for_status()
    original=store.settings()['tls_certificate']
    expired,expired_key=make_certificate(expired=True)
    _,otherkey=make_certificate()
    for c,k in [('garbage',key),(cert,otherkey),(expired,expired_key)]:
        assert client.post('/api/tls/certificate',json={'certificate':c,'private_key':k}).status_code==422
        assert store.settings()['tls_certificate']==original


@pytest.mark.parametrize('host,allowed', [('www.example.com',True),('WWW.EXAMPLE.COM:8300',True),
    ('a.example.org',True),('a.b.example.org',False),('example.org',False),
    ('www.example.com.evil.org',False),('127.0.0.1',False)])
def test_domain_enforcement_and_original_host(tmp_path,host,allowed):
    requests=[]
    def upstream(request):
        requests.append(request)
        return httpx.Response(200,stream=httpx.ByteStream(b'ok'))
    app=create_app(database=tmp_path/'proxy.db',transport=httpx.MockTransport(upstream))
    app.state.store.save(SettingsInput(upstream='http://origin.test',protected_domains=['www.example.com','*.example.org']).model_dump())
    with TestClient(app) as client:
        response=client.get('/',headers={'Host':host,'X-Forwarded-Host':'spoof.test'})
        assert response.status_code==(200 if allowed else 403)
        if allowed:
            assert requests[0].headers['host']==host
            assert requests[0].headers['x-forwarded-host']==host
        else:
            assert not requests
            assert app.state.store.events()[0]['rule_id']=='DOMAIN'


@pytest.mark.parametrize('domain',['https://example.com','example.com:443','bad/path','127.0.0.1','*.*.example.com','-a.example.com'])
def test_invalid_domain(domain):
    with pytest.raises(ValueError): normalize_domain(domain)


def test_occupied_https_port_keeps_supervisor_alive(admin):
    client,store=admin
    cert,key=make_certificate()
    info=install_certificate(cert,key)
    with socket.socket() as occupied:
        occupied.bind(('0.0.0.0',0));occupied.listen()
        value={**store.settings(),'tls_enabled':True,'tls_port':occupied.getsockname()[1],
               'tls_certificate':info['id'],'protected_domains':['www.example.com']}
        supervisor=TLSSupervisor()
        try:
            supervisor.tick(value)
            assert supervisor.state=='error'
            assert not public_status(value)['running']
        finally: supervisor.stop()
