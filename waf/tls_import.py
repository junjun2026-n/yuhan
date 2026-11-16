"""Detect certificate containers by content and normalize them for OpenSSL."""
import base64
import binascii
import re

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12


def decode(value, encoding, limit):
    try:
        data = base64.b64decode(value, validate=True) if encoding == 'base64' else value.encode('utf-8-sig').removeprefix(b'\xef\xbb\xbf')
    except (ValueError, UnicodeError, binascii.Error): raise ValueError('证书文件编码无效，请重新选择文件上传')
    if len(data)>limit: raise ValueError('证书文件上限 1 MiB，私钥文件上限 64 KiB')
    return data


def load_key(data, password):
    if b'-----BEGIN ' in data:
        match = re.search(rb'-----BEGIN (?P<label>(?:ENCRYPTED |RSA |EC |DSA |)PRIVATE KEY)-----.*?-----END (?P=label)-----',data,re.S)
        if not match: raise ValueError('缺少有效私钥，请选择私钥文件或包含私钥的 PFX/P12 文件')
        data = match.group(0)
        loader = serialization.load_pem_private_key
    else: loader = serialization.load_der_private_key
    try: return loader(data,password=password)
    except TypeError:
        if password: return loader(data,password=None)
        raise


def normalize(certificate, private_key='', password=None, encoding='text'):
    data = decode(certificate,encoding,1048576)
    key_data = decode(private_key,encoding,65536) if private_key else b''
    if password and len(password)>1024: raise ValueError('证书密码过长')
    password_bytes = password.encode('utf-8') if password else None
    key = None
    certificates = []
    detected = ''
    try:
        blocks = re.findall(rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',data,re.S)
        if blocks:
            certificates = [x509.load_pem_x509_certificate(block) for block in blocks]
            detected = 'PEM'
        elif b'-----BEGIN PKCS7-----' in data:
            certificates = pkcs7.load_pem_pkcs7_certificates(data)
            detected = 'PKCS#7 (PEM)'
        else:
            try:
                certificates = [x509.load_der_x509_certificate(data)]
                detected = 'DER'
            except ValueError:
                try:
                    certificates = pkcs7.load_der_pkcs7_certificates(data)
                    detected = 'PKCS#7 (DER)'
                except ValueError:
                    key, leaf, additional = pkcs12.load_key_and_certificates(data,password_bytes)
                    certificates = ([leaf] if leaf else []) + list(additional or [])
                    detected = 'PKCS#12 (PFX/P12)'
        if key_data:
            external = load_key(key_data,password_bytes)
            if key and public(key)!=public(external): raise ValueError('PFX 内私钥与另外上传的私钥不匹配')
            key = external
        elif key is None and b'PRIVATE KEY-----' in data: key = load_key(data,password_bytes)
        if key is None: raise ValueError('缺少私钥：请提供独立私钥文件，或上传包含私钥的 PFX/P12、合并 PEM 文件')
        # Identify the leaf by its key, rather than assuming a bundle is ordered.
        unique = {cert.public_bytes(serialization.Encoding.DER):cert for cert in certificates}
        matches = [cert for cert in unique.values() if public(cert.public_key())==public(key)]
        if len(matches)!=1: raise ValueError('证书与私钥不匹配，或证书包中包含多个相同密钥的叶证书')
        chain = [matches[0]]
        remaining = [cert for cert in unique.values() if cert!=chain[0]]
        while remaining:
            issuers=[]
            for cert in remaining:
                if cert.subject!=chain[-1].issuer: continue
                try: chain[-1].verify_directly_issued_by(cert)
                except (ValueError, TypeError, InvalidSignature): continue
                issuers.append(cert)
            if not issuers: raise ValueError('证书包中有无关证书或证书链不匹配，请提供对应的证书链')
            if len(issuers)!=1: raise ValueError('证书链有多个候选签发者，请提供明确的证书链')
            chain.append(issuers[0]);remaining.remove(issuers[0])
        pem = b''.join(cert.public_bytes(serialization.Encoding.PEM) for cert in chain).decode('ascii')
        key_pem = key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode('ascii')
        return pem,key_pem,detected
    except ValueError as exc:
        # Keep our actionable errors, never expose cryptography internals or file content.
        if str(exc).startswith(('缺少私钥','缺少有效私钥','证书与私钥','PFX 内私钥','证书包中','证书链有')): raise
        raise ValueError('无法识别或解密证书：支持 PEM、DER、PKCS#7、PFX/P12，请检查文件和证书密码') from None
    except Exception:
        raise ValueError('无法读取证书或私钥，请检查格式、算法与证书密码') from None


def public(key):
    if hasattr(key,'public_key'): key=key.public_key()
    return key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
