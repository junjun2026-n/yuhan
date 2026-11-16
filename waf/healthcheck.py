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
