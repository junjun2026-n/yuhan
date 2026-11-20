# ============================================================
# 文件名称：link_remote_juxun.py
# 生成日期：2026-11-09
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 link_remote_juxun 模块相关功能。
#           文件用途：供WAF的 yuhan/tools/link_remote_juxun.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Link the deployed WAF to the configured Juxun collector without changing NICs."""
import os
import shlex
import paramiko
from pathlib import Path

root=Path(__file__).resolve().parents[1]
script='''import json,socket
from waf.store import Store
from waf.log_forwarding import configuration,save_config,LogConfig
s=Store();old,state=configuration(s)
if old.enabled and (old.host,old.port)!=('192.168.17.1',1514):raise SystemExit('Existing remote destination differs; left unchanged')
with socket.create_connection(('192.168.17.1',1514),timeout=5):pass
save_config(s,LogConfig(enabled=True,host='192.168.17.1',port=1514,protocol='tcp',format='json'))
print(json.dumps({'configured':True,'destination':'192.168.17.1:1514','protocol':'tcp','cursor':state.get('cursor',0),'engine':s.engine}))
'''
password=os.environ['WAF_REMOTE_PASSWORD']
client=paramiko.SSHClient();client.load_host_keys(str(root/'runtime/remote-known-hosts'))
client.set_missing_host_key_policy(paramiko.RejectPolicy())
with client:
    client.connect('192.168.17.126',username='jun',password=password,allow_agent=False,look_for_keys=False,timeout=15)
    command='sudo -S -p "" bash -c '+shlex.quote('cd /opt/waf && docker compose exec -T waf python -c '+shlex.quote(script))
    stdin,stdout,stderr=client.exec_command(command);stdin.write(password+'\n');stdin.flush();stdin.channel.shutdown_write()
    print(stdout.read().decode());print(stderr.read().decode());raise SystemExit(stdout.channel.recv_exit_status())
