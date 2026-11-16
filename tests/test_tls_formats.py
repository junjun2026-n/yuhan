import base64
from datetime import datetime,timedelta,timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7,pkcs12
from cryptography.x509.oid import NameOID

from test_tls import admin,make_certificate
from waf.tls import certificate_paths,install_certificate


def request(client,data,key=b'',password=''):
    return client.post('/api/tls/certificate',json={'certificate':base64.b64encode(data).decode(),
        'private_key':base64.b64encode(key).decode(),'password':password,'encoding':'base64'})


@pytest.mark.parametrize('format',['der','p7b-pem','p7b-der','pfx','pfx-encrypted','combined-pem','encrypted-pem-key','encrypted-der-key'])
def test_automatic_detection_and_canonical_storage(admin,format):
    client,store=admin
    pem,key_pem=make_certificate(('formats.example.com',))
    cert=x509.load_pem_x509_certificate(pem.encode())
    key=serialization.load_pem_private_key(key_pem.encode(),None)
    canonical=install_certificate(pem,key_pem)['id']
    data=pem.encode();key_data=key_pem.encode();password=''
    if format=='der':
        data=cert.public_bytes(serialization.Encoding.DER)
        key_data=key.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    elif format.startswith('p7b'):
        data=pkcs7.serialize_certificates([cert],serialization.Encoding.PEM if format.endswith('pem') else serialization.Encoding.DER)
    elif format.startswith('pfx'):
        password='temporary-import-password' if format.endswith('encrypted') else ''
        data=pkcs12.serialize_key_and_certificates(b'waf',key,cert,None,serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption())
        key_data=b''
    elif format=='combined-pem': data+=key_data;key_data=b''
    elif format.startswith('encrypted'):
        password='temporary-import-password'
        key_data=key.private_bytes(serialization.Encoding.DER if format=='encrypted-der-key' else serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,serialization.BestAvailableEncryption(password.encode()))
    result=request(client,data,key_data,password)
    assert result.status_code==200,result.json()
    info=result.json()
    assert info['id']==canonical and info['domains']==['formats.example.com']
    assert info['source_format']
    assert 'PRIVATE KEY' not in result.text and 'temporary-import-password' not in result.text
    assert store.settings()['tls_certificate']=='' and store.settings()['domain_certificates']=={}
    assert 'temporary-import-password' not in str(store.events())
    cert_file,key_file=certificate_paths(info['id'])
    assert cert_file.read_text().startswith('-----BEGIN CERTIFICATE-----')
    assert key_file.read_text().startswith('-----BEGIN PRIVATE KEY-----')


def test_unordered_pkcs7_chain_is_sorted_leaf_first(admin):
    client,_=admin
    now=datetime.now(timezone.utc)
    ca_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    ca_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'WAF Test CA')])
    ca=(x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).sign(ca_key,hashes.SHA256()))
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    leaf=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'chain.example.com')]))
        .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=7))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('chain.example.com')]),critical=False).sign(ca_key,hashes.SHA256()))
    data=pkcs7.serialize_certificates([ca,leaf],serialization.Encoding.DER)
    key_data=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    response=request(client,data,key_data)
    assert response.status_code==200,response.json()
    cert_path,_=certificate_paths(response.json()['id'])
    chain=x509.load_pem_x509_certificates(cert_path.read_bytes())
    assert chain==[leaf,ca]


def test_wrong_password_missing_key_and_malformed_input_preserve_settings(admin):
    client,store=admin
    pem,key_pem=make_certificate()
    cert=x509.load_pem_x509_certificate(pem.encode());key=serialization.load_pem_private_key(key_pem.encode(),None)
    pfx=pkcs12.serialize_key_and_certificates(b'waf',key,cert,None,serialization.BestAvailableEncryption(b'correct-password'))
    before=store.settings()
    for data,key_data,password in [(pfx,b'','wrong-password'),(pem.encode(),b'',''),(b'garbage',b'','')]:
        response=request(client,data,key_data,password)
        assert response.status_code==422
        assert 'wrong-password' not in response.text
        assert store.settings()==before
    assert client.post('/api/tls/certificate',json={'certificate':'not-base64!','encoding':'base64'}).status_code==422
