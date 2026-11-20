# ============================================================
# 文件名称：deploy.py
# 生成日期：2026-10-27
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：执行 deploy 对应的启动、构建或运维任务。
#           文件用途：供WAF的 yuhan/tools/deploy.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Test, package, upload and update the existing Ubuntu WAF deployment."""
import argparse
from datetime import datetime, timezone
import getpass
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
FILES = ('LICENSE','VERSION','COPYRIGHT.md','Dockerfile','compose.yaml','compose.stack.yaml','start-stack.sh','.dockerignore','README.md','requirements.txt',
         'requirements.lock','requirements-runtime.lock','requirements-linux.txt',
         'requirements-deploy.txt','start.sh','stop.sh','start.ps1','stop.ps1','start-dev.ps1','deploy.ps1')


def package(destination):
    paths = [ROOT/name for name in FILES]
    for directory in ('waf','static','docs','tools','tests'):
        paths.extend(path for path in (ROOT/directory).rglob('*') if path.is_file()
                     and '__pycache__' not in path.parts and path.suffix != '.pyc')
    with tarfile.open(destination, 'w:gz') as archive:
        for path in sorted(paths):
            data = path.read_bytes()
            if path.suffix == '.sh': data = data.replace(b'\r\n',b'\n')
            info = tarfile.TarInfo(path.relative_to(ROOT).as_posix())
            info.size, info.mode = len(data), 0o644
            archive.addfile(info,io.BytesIO(data))
    return hashlib.sha256(destination.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host',default='192.168.17.126')
    parser.add_argument('--user',default='jun')
    parser.add_argument('--prepare-only',action='store_true')
    args = parser.parse_args()
    # Default checks use isolated SQLite fixtures. PostgreSQL tests remain opt-in.
    env = dict(os.environ)
    env.pop('WAF_TEST_POSTGRES_CONFIG',None)
    subprocess.run([sys.executable,'-m','pytest','-q'],cwd=ROOT,env=env,check=True)
    release = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    folder = ROOT/'packages/releases'/release
    folder.mkdir(parents=True,exist_ok=False)
    archive = folder/'source.tar.gz'
    digest = package(archive)
    manifest = {'release':release,'source_sha256':digest,'host':args.host,'directory':'/opt/waf'}
    (folder/'release.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(f'Release {release}: {archive} (SHA256 {digest})',flush=True)
    if args.prepare_only: return
    import paramiko
    password = os.getenv('WAF_REMOTE_PASSWORD') or getpass.getpass('SSH/sudo password: ')
    known = ROOT/'runtime/remote-known-hosts'
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    if known.exists(): client.load_host_keys(str(known))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    with client:
        client.connect(args.host,username=args.user,password=password,allow_agent=False,look_for_keys=False,timeout=15)
        remote = f'/home/{args.user}/waf-release-{release}.tar.gz'
        with client.open_sftp() as sftp:
            sftp.put(str(archive),remote)
            sftp.chmod(remote,0o600)
        script = (ROOT/'tools/update-server.sh').read_text(encoding='utf-8')
        command = 'sudo -S -p "" bash -c '+shlex.quote(script)+' -- '+shlex.quote(remote)+' '+shlex.quote(digest)+' '+shlex.quote(release)
        stdin,stdout,stderr = client.exec_command(command)
        stdin.write(password+'\n');stdin.flush();stdin.channel.shutdown_write()
        channel = stdout.channel
        with (folder/'deployment.log').open('w',encoding='utf-8') as log:
            while not channel.exit_status_ready() or channel.recv_ready() or channel.recv_stderr_ready():
                for available,read in ((channel.recv_ready,channel.recv),(channel.recv_stderr_ready,channel.recv_stderr)):
                    if available():
                        text = read(65536).decode('utf-8','replace')
                        print(text,end='',flush=True);log.write(text);log.flush()
                time.sleep(.1)
        code = channel.recv_exit_status()
        if code: raise SystemExit(f'Deployment failed ({code}); see {folder / "deployment.log"}')
        manifest['deployed'] = True
        (folder/'release.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print('Deployment verified. Local development files and server runtime retained.')


if __name__ == '__main__': main()
