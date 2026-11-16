"""Deploy a previously tested package using the existing backup/rollback script."""
import hashlib
import os
import shlex
from datetime import datetime,timezone
from pathlib import Path
import paramiko

root=Path(__file__).resolve().parents[1]
archive=root/'runtime/multisource-release.tar.gz'
release=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
password=os.environ['WAF_REMOTE_PASSWORD']
client=paramiko.SSHClient();client.load_host_keys(str(root/'runtime/remote-known-hosts'))
client.set_missing_host_key_policy(paramiko.RejectPolicy())
with client:
    client.connect('192.168.17.126',username='jun',password=password,allow_agent=False,look_for_keys=False,timeout=15)
    remote='/home/jun/waf-release-'+release+'.tar.gz'
    with client.open_sftp() as sftp:sftp.put(str(archive),remote);sftp.chmod(remote,0o600)
    command='sudo -S -p "" bash -c '+shlex.quote((root/'tools/update-server.sh').read_text(encoding='utf-8'))+' -- '+shlex.quote(remote)+' '+hashlib.sha256(archive.read_bytes()).hexdigest()+' '+release
    stdin,stdout,stderr=client.exec_command(command)
    stdin.write(password+'\n');stdin.flush();stdin.channel.shutdown_write()
    import time
    channel=stdout.channel
    with (root/'runtime/multisource-deployment.log').open('w',encoding='utf-8') as log:
        while not channel.exit_status_ready() or channel.recv_ready() or channel.recv_stderr_ready():
            for ready,read in ((channel.recv_ready,channel.recv),(channel.recv_stderr_ready,channel.recv_stderr)):
                if ready():
                    value=read(65536).decode('utf-8','replace');log.write(value);log.flush();print(value,end='',flush=True)
            time.sleep(.1)
    raise SystemExit(channel.recv_exit_status())
