# ============================================================
# 文件名称：tls.py
# 生成日期：2026-10-27
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 tls 模块相关功能。
#           文件用途：供WAF的 yuhan/waf/tls.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Certificate validation, protected host names and optional HTTPS listener."""
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def runtime():
    return Path(os.getenv('WAF_TLS_RUNTIME', str(ROOT/'runtime/tls')))


def normalize_domain(value, wildcard=True):
    value = value.strip().lower().rstrip('.')
    prefix = '*.' if wildcard and value.startswith('*.') else ''
    host = value[2:] if prefix else value
    try: host = host.encode('idna').decode('ascii')
    except UnicodeError: raise ValueError('域名格式无效')
    if len(host) > 253 or '.' not in host or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.')):
        raise ValueError('请填写完整域名，不包含协议、端口或路径')
    try: ipaddress.ip_address(host)
    except ValueError: return prefix+host
    raise ValueError('请填写域名，不能填写 IP 地址')


def domain_matches(host, pattern):
    return host == pattern or (pattern.startswith('*.') and host.count('.') == pattern.count('.') and host.endswith(pattern[1:]))


def request_hostname(headers):
    values = headers.getlist('host')
    if len(values) != 1: return ''
    value = values[0]
    if not re.fullmatch(r'[^\s:/\\@?#]+(?::[0-9]{1,5})?', value): return ''
    try: return normalize_domain(value.split(':')[0], wildcard=False)
    except ValueError: return ''


def certificate_paths(identifier):
    if not re.fullmatch(r'[0-9a-f]{64}', identifier): raise ValueError('尚未上传有效 HTTPS 证书')
    folder = runtime()/identifier
    return folder/'fullchain.pem', folder/'private.key'


def certificate_info(identifier):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    cert_path, _ = certificate_paths(identifier)
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    return {'id': identifier, 'domains': names, 'subject': cert.subject.rfc4514_string(),
            'not_before': cert.not_valid_before_utc.isoformat(), 'not_after': cert.not_valid_after_utc.isoformat(),
            'expired': cert.not_valid_after_utc <= datetime.now(timezone.utc),
            'sha256': cert.fingerprint(hashes.SHA256()).hex()}


def install_certificate(certificate, private_key='', password=None, encoding='text'):
    from .tls_import import normalize
    certificate, private_key, detected = normalize(certificate, private_key, password, encoding)
    from cryptography import x509
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import serialization
    try:
        certificates = x509.load_pem_x509_certificates(certificate.encode('ascii'))
        cert = certificates[0]
        key = serialization.load_pem_private_key(private_key.encode('ascii'), password=None)
        public = lambda k: k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if public(cert.public_key()) != public(key.public_key()): raise ValueError()
        now = datetime.now(timezone.utc)
        if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc: raise ValueError()
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        if not names: raise ValueError()
        for name in names: normalize_domain(name)
    except (ValueError, IndexError, UnicodeError, TypeError, x509.ExtensionNotFound, UnsupportedAlgorithm):
        raise ValueError('证书或私钥无效：须密钥匹配、证书在有效期内且包含域名 SAN')
    identifier = hashlib.sha256(certificate.encode()+private_key.encode()).hexdigest()
    folder = runtime()/identifier
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    cert_path, key_path = certificate_paths(identifier)
    # Immutable content-addressed files: active listeners never read partially replaced keys.
    for path, content in [(cert_path, certificate), (key_path, private_key)]:
        if not path.exists():
            with path.open('x', encoding='ascii') as output:
                if os.name != 'nt': os.chmod(path, 0o600)
                output.write(content)
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert_path, key_path)
    except ssl.SSLError: raise ValueError('OpenSSL 无法加载证书链或私钥，请检查算法与证书链')
    return {**certificate_info(identifier), 'source_format':detected}


def validate_https(settings):
    bindings = settings.get('domain_certificates', {})
    domains = settings.get('protected_domains', [])
    if set(bindings) - set(domains): raise ValueError('证书绑定只能使用已配置的受保护域名')
    for domain, identifier in bindings.items():
        validate_domain_certificate(domain, identifier)
    if not settings.get('tls_enabled'): return
    if not domains: raise ValueError('启用 HTTPS 前请配置受保护域名')
    for domain in domains:
        identifier = bindings.get(domain) or settings.get('tls_certificate', '')
        if not identifier: raise ValueError(f'请为域名选择要加载的 HTTPS 证书：{domain}')
        validate_domain_certificate(domain, identifier)


def validate_domain_certificate(domain, identifier):
    info = certificate_info(identifier)
    now = datetime.now(timezone.utc)
    if info['expired'] or datetime.fromisoformat(info['not_before']) > now: raise ValueError('HTTPS 证书已过期或尚未生效')
    if not any(domain_matches(domain, name.lower()) for name in info['domains']):
        raise ValueError(f'HTTPS 证书不覆盖域名：{domain}')
    return info


def certificate_inventory():
    result = []
    for folder in runtime().glob('*'):
        if not folder.is_dir(): continue
        try: result.append(certificate_info(folder.name))
        except (ValueError, OSError): continue
    return sorted(result, key=lambda item: (item['domains'], item['id']))


def selected_certificate(settings, host):
    bindings = settings.get('domain_certificates', {})
    domains = settings.get('protected_domains', [])
    if host in domains: return bindings.get(host) or settings.get('tls_certificate', '')
    for domain in domains:
        if domain_matches(host, domain): return bindings.get(domain) or settings.get('tls_certificate', '')
    return ''


def default_certificate(settings):
    domains = settings.get('protected_domains', [])
    if domains: return selected_certificate(settings, domains[0])
    return settings.get('tls_certificate', '')


def configure_sni(context, settings):
    contexts = {}
    for domain in settings['protected_domains']:
        identifier = selected_certificate(settings, domain)
        if identifier in contexts: continue
        cert, key = certificate_paths(identifier)
        child = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        child.minimum_version = ssl.TLSVersion.TLSv1_2
        child.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20')
        child.load_cert_chain(cert, key)
        contexts[identifier] = child
    def select(connection, server_name, initial):
        if not server_name: return
        try: identifier = selected_certificate(settings, normalize_domain(server_name, wildcard=False))
        except ValueError: return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        if identifier not in contexts: return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        connection.context = contexts[identifier]
    context.set_servername_callback(select)
    return contexts


def public_status(settings):
    info = None
    try:
        if settings.get('tls_certificate'): info = certificate_info(settings['tls_certificate'])
    except (ValueError, OSError): pass
    try: state = json.loads((runtime()/'listener.json').read_text())
    except (ValueError, OSError): state = {}
    import time
    expected = listener_fingerprint(settings)
    running = state.get('fingerprint') == expected and state.get('state') == 'running' and 0 <= time.time()-state.get('heartbeat', 0) < 15
    return {'certificate': info, 'certificates': certificate_inventory(), 'domain_certificates': settings.get('domain_certificates', {}), 'running': running, 'enabled': settings.get('tls_enabled', False),
            'port': settings.get('tls_port', 8443), 'state': state.get('state', 'stopped'), 'detail': state.get('detail', '')}


def listener_fingerprint(settings):
    return hashlib.sha256(json.dumps({key: settings.get(key) for key in ('tls_enabled','tls_port','tls_certificate','protected_domains','domain_certificates')}, sort_keys=True).encode()).hexdigest()


class TLSSupervisor:
    def __init__(self, root=ROOT):
        self.root = root
        self.worker = None
        self.fingerprint = None
        self.state = 'stopped'
        self.detail = ''

    def stop(self):
        if self.worker is not None:
            if self.worker.poll() is None:
                self.worker.terminate()
                try: self.worker.wait(timeout=10)
                except subprocess.TimeoutExpired: self.worker.kill(); self.worker.wait(timeout=5)
            self.worker = None

    def tick(self, settings):
        desired = listener_fingerprint(settings)
        if desired != self.fingerprint:
            self.stop()
            self.fingerprint, self.state, self.detail = desired, 'stopped', ''
            if settings.get('tls_enabled'):
                try:
                    validate_https(settings)
                    certificate_paths(default_certificate(settings))
                    # Refuse to compete with an existing host service.
                    with socket.socket() as probe: probe.bind(('0.0.0.0', settings['tls_port']))
                    self.worker = subprocess.Popen([sys.executable, '-m', 'waf.https'], cwd=self.root)
                    self.state = 'starting'
                except (ValueError, OSError): self.state, self.detail = 'error', 'HTTPS 启动失败，请检查端口占用及证书配置'
        if self.worker:
            if self.worker.poll() is not None: self.state, self.detail = 'error', 'HTTPS 进程已退出，请检查日志并重新保存配置或重启服务'
            else:
                try:
                    with socket.create_connection(('127.0.0.1', settings['tls_port']), timeout=0.2): self.state = 'running'
                except OSError: self.state = 'starting'
        import time
        runtime().mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = runtime()/'listener.next'
        temporary.write_text(json.dumps({'fingerprint': self.fingerprint, 'state':self.state,
            'detail':self.detail, 'heartbeat':time.time()}))
        try:
            temporary.replace(runtime()/'listener.json')
        except PermissionError:
            # Windows readers can briefly prevent atomic replacement. Retry on
            # the next supervisor tick instead of terminating every service.
            if os.name != 'nt': raise
