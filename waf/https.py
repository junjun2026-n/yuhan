# ============================================================
# 文件名称：https.py
# 生成日期：2026-10-28
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 https 模块相关功能。
#           文件用途：供WAF的 yuhan/waf/https.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
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
