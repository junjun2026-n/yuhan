"""HTTPS proxy with per-domain certificate selection via TLS SNI."""
import uvicorn

from .store import Store
from .tls import validate_https, default_certificate, certificate_paths, configure_sni


def main():
    settings = Store().settings()
    validate_https(settings)
    cert, key = certificate_paths(default_certificate(settings))
    config = uvicorn.Config('waf.main:create_proxy', factory=True, host='0.0.0.0', port=settings['tls_port'],
        ssl_certfile=str(cert), ssl_keyfile=str(key), ssl_ciphers='ECDHE+AESGCM:ECDHE+CHACHA20',
        access_log=False, proxy_headers=False)
    config.load()
    configure_sni(config.ssl, settings)
    uvicorn.Server(config).run()


if __name__ == '__main__': main()
