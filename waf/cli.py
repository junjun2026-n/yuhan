# ============================================================
# 文件名称：cli.py
# 生成日期：2026-10-27
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 cli 模块相关功能。
#           文件用途：供WAF的 yuhan/waf/cli.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Project initialization and two-process development launcher."""
import argparse
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def protect(path):
    if os.name == 'nt':
        account = subprocess.check_output(['whoami'], text=True).strip()
        rights = '(OI)(CI)(F)' if path.is_dir() else '(F)'
        subprocess.run(['icacls', str(path), '/inheritance:r', '/grant:r',
                        f'{account}:{rights}', f'SYSTEM:{rights}'], check=True, capture_output=True)
    else:
        path.chmod(0o600 if path.is_file() else 0o700)


def initialize():
    runtime = ROOT / ('runtime/dev' if os.getenv('WAF_DEV_MODE') == '1' else 'runtime')
    runtime.mkdir(parents=True, exist_ok=True)
    protect(runtime)
    env = Path(os.getenv('WAF_ENV_FILE', str(ROOT / '.env')))
    if env.exists():
        print('Existing credential configuration retained.')
    else:
        password = secrets.token_urlsafe(24)
        env.write_text(f'WAF_ADMIN_USER=admin\nWAF_ADMIN_PASSWORD={password}\n'
                       'WAF_DATABASE=runtime/waf.sqlite3\nWAF_TRUSTED_HOSTS=*\n', encoding='utf-8')
        protect(env)
        credentials = runtime / 'initial-admin.txt'
        port = 8401 if os.getenv('WAF_DEV_MODE') == '1' else 8301
        credentials.write_text(f'URL: http://127.0.0.1:{port}\nUsername: admin\nPassword: {password}\n', encoding='utf-8')
        protect(credentials)
        print('Initialized. Credentials: '+str(credentials.relative_to(ROOT)))
    return initialize_management()


def initialize_management():
    if os.getenv('WAF_DEV_MODE') == '1':
        print('Development mode: management NIC initialization disabled.', flush=True)
        return {'state':'development'}
    from dotenv import load_dotenv
    from .store import Store
    from .bootstrap import initialize_network
    load_dotenv(os.getenv('WAF_ENV_FILE', str(ROOT / '.env')))
    result = initialize_network(Store(), ROOT/'mgrnic.ini')
    print(f"Management initialization: {result['state']}", flush=True)
    if result.get('last_error'):
        print('Management initialization incomplete; check System Configuration for details.', flush=True)
    if result.get('business'):
        print('Business NIC initialization: '+result['business']['state'], flush=True)
    return result


def serve():
    initialize()
    from dotenv import load_dotenv
    from .store import Store
    load_dotenv(os.getenv('WAF_ENV_FILE', str(ROOT / '.env')))
    listen_host = '127.0.0.1' if os.getenv('WAF_DEV_MODE') == '1' else '0.0.0.0'
    os.environ['WAF_MANAGEMENT_LISTEN_IP'] = listen_host
    children = []
    stopped = False
    exit_code = 0
    def request_stop(*_):
        nonlocal stopped
        stopped = True
    previous_handlers = {sig:signal.signal(sig,request_stop) for sig in (signal.SIGTERM,signal.SIGINT)}
    supervisor = DataPlaneSupervisor(ROOT) if os.getenv('WAF_DATAPLANE_AUTOSTART') == '1' else None
    from .tls import TLSSupervisor
    tls_supervisor = TLSSupervisor(ROOT)
    try:
        dev = os.getenv('WAF_DEV_MODE') == '1'
        proxy_port, admin_port = ('8400','8401') if dev else ('8300','8301')
        proxy_host = listen_host
        services = [('proxy', proxy_host, proxy_port), ('admin', listen_host, admin_port)]
        for plane, host, port in services:
            child_env = dict(os.environ, WAF_LOG_SENDER='1' if plane == 'admin' else '0')
            children.append(subprocess.Popen([sys.executable, '-m', 'uvicorn',
                f'waf.main:create_{plane}', '--factory', '--host', host, '--port', port,
                '--no-access-log', '--no-proxy-headers'], cwd=ROOT, env=child_env))
        print(f'Proxy: http://{proxy_host}:{proxy_port} | Admin: http://{listen_host}:{admin_port}', flush=True)
        store = Store()
        while not stopped and all(child.poll() is None for child in children):
            tls_supervisor.tick(store.settings())
            if supervisor:
                supervisor.tick(store.network())
            time.sleep(0.5)
        exit_code = 0 if stopped else 1
    except KeyboardInterrupt:
        pass
    finally:
        tls_supervisor.stop()
        if supervisor:
            supervisor.stop()
        for child in children:
            if child.poll() is None:
                child.terminate()
        for child in children:
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        for sig,handler in previous_handlers.items():
            signal.signal(sig,handler)
    if exit_code:
        raise SystemExit(exit_code)


class DataPlaneSupervisor:
    """Run one optional data plane; an engine failure keeps the UI available.

    A failed configuration is not retried in a tight bridge creation / removal loop.
    Save a changed configuration or restart the container to retry it.
    """
    def __init__(self, root):
        self.root = root
        self.worker = None
        self.configuration = None

    def stop(self):
        if self.worker is not None:
            if self.worker.poll() is None:
                self.worker.terminate()
                try: self.worker.wait(timeout=40)
                except subprocess.TimeoutExpired:
                    self.worker.kill(); self.worker.wait(timeout=5)
            self.worker = None

    def tick(self, config):
        from .dataplane import fingerprint
        desired = fingerprint(config)
        if desired == self.configuration:
            return
        self.stop()
        self.configuration = desired
        if config.deployment_mode in ('bypass','inline'):
            self.worker = subprocess.Popen([sys.executable,'-m','waf.dataplane'],cwd=self.root)
            print('Data plane started for configured mode: '+config.deployment_mode,flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='WAF project tools')
    parser.add_argument('command', choices=['init', 'init-network', 'serve'])
    args = parser.parse_args()
    if args.command == 'serve': serve()
    elif args.command == 'init': initialize()
    else:
        result=initialize_management()
        if result['state'] not in ('completed','skipped_existing','skipped_changed'): raise SystemExit(1)
        if result.get('business',{}).get('state') in ('error','pending_link'): raise SystemExit(1)
