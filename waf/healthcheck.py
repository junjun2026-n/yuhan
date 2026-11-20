# ============================================================
# 文件名称：healthcheck.py
# 生成日期：2026-10-27
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 healthcheck 模块相关功能。
#           文件用途：供WAF的 yuhan/waf/healthcheck.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Container health probe. Never print authentication credentials."""
import os
from pathlib import Path
import socket

import httpx
from dotenv import load_dotenv


def check():
    root = Path(__file__).resolve().parents[1]
    load_dotenv(os.getenv('WAF_ENV_FILE', str(root/'.env')))
    password = os.getenv('WAF_ADMIN_PASSWORD','')
    if not password: return False
    with httpx.Client(trust_env=False, timeout=5, auth=(os.getenv('WAF_ADMIN_USER','admin'),password),headers={'X-WAF-Probe':password}) as client:
        response = client.get('http://127.0.0.1:8301/api/system/status')
        if response.status_code != 200: return False
        status = response.json()
        tls = client.get('http://127.0.0.1:8301/api/tls')
        if tls.status_code != 200: return False
        if tls.json().get('enabled') and not tls.json().get('running'): return False
        if (os.getenv('WAF_DATAPLANE_AUTOSTART')=='1' and
                status.get('agent_expected') and not status.get('data_plane_running')):
            return False
    with socket.create_connection(('127.0.0.1',8300),timeout=3): pass
    return True


if __name__=='__main__':
    try: healthy=check()
    except (OSError,ValueError,httpx.HTTPError): healthy=False
    raise SystemExit(0 if healthy else 1)
