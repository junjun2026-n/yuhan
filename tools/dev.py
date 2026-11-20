# ============================================================
# 文件名称：dev.py
# 生成日期：2026-10-27
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 dev 模块相关功能。
#           文件用途：供WAF的 yuhan/tools/dev.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Local development launcher with an isolated database profile."""
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    folder = ROOT/'runtime/dev'
    folder.mkdir(parents=True, exist_ok=True)
    config = folder/'database.env'
    profile = folder/'database.postgresql.env'
    if not profile.exists():
        raise SystemExit('Configure runtime/dev/database.postgresql.env with an isolated development PostgreSQL database first.')
    config.write_text(profile.read_text(encoding='utf-8'), encoding='utf-8')
    env = dict(os.environ)
    for name in ('WAF_ADMIN_USER','WAF_ADMIN_PASSWORD','WAF_MANAGEMENT_LISTEN_IP','WAF_TEST_POSTGRES_CONFIG'):
        env.pop(name, None)
    env.update(WAF_DEV_MODE='1', WAF_ENV_FILE=str(folder/'admin.env'),
        WAF_DATABASE_CONFIG=str(config), WAF_DATABASE='runtime/dev/waf.sqlite3',
        WAF_DB_ENGINE='postgresql', WAF_DATAPLANE_AUTOSTART='0', WAF_TLS_RUNTIME=str(folder/'tls'))
    print('Development: http://127.0.0.1:8401 | Proxy: http://127.0.0.1:8400', flush=True)
    print('Private local credentials: runtime/dev/initial-admin.txt', flush=True)
    try:
        return subprocess.call([sys.executable,'-m','waf.cli','serve'], cwd=ROOT, env=env)
    except KeyboardInterrupt: return 0


if __name__ == '__main__': raise SystemExit(main())
