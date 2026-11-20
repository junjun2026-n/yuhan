# ============================================================
# 文件名称：test_dataplane_lifecycle.py
# 生成日期：2026-10-27
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：验证 dataplane_lifecycle 相关功能。
#           文件用途：用于开发验证及功能回归。
#           注意事项：使用隔离测试环境，避免操作正式业务数据。
# ============================================================
"""Exercise host command lifecycle without changing this machine's network."""
import json
import sys
from types import SimpleNamespace

import pytest
from waf import dataplane
from waf.network import NetworkConfig
from waf.store import Store


@pytest.mark.parametrize('fail_rules',[False,True])
def test_inline_setup_and_cleanup(tmp_path,monkeypatch,fail_rules):
    config=NetworkConfig().model_dump();config['deployment_mode']='inline'
    for i,nic in enumerate(config['interfaces']):nic['physical_id']=f'test:{i}'
    config=NetworkConfig(**config)
    store=Store(tmp_path/'test.db')
    network_calls=[]
    def network():
        network_calls.append(True)
        return config if len(network_calls)==1 else NetworkConfig()
    monkeypatch.setattr(store,'network',network)
    monkeypatch.setattr(dataplane,'Store',lambda *_:store)
    monkeypatch.setattr(dataplane.platform,'system',lambda:'Linux')
    monkeypatch.setattr(dataplane,'privileged',lambda:True)
    monkeypatch.setattr(dataplane,'adapters',lambda:[{'id':f'test:{i}','name':f'eth{i}','ipv4':[]} for i in range(3)])
    monkeypatch.setattr(dataplane.signal,'signal',lambda *_:None)
    monkeypatch.setitem(sys.modules,'fcntl',SimpleNamespace(LOCK_EX=1,LOCK_NB=2,flock=lambda *_:None))
    monkeypatch.setitem(sys.modules,'scapy',SimpleNamespace())
    monkeypatch.setitem(sys.modules,'scapy.all',SimpleNamespace(IP=None,IPv6=None,TCP=None,Ether=None,AsyncSniffer=None))
    queue_calls=[]
    class Queue:
        def bind(self,number,callback,**kwargs):queue_calls.append(('bind',number))
        def unbind(self):queue_calls.append(('unbind',))
    monkeypatch.setitem(sys.modules,'netfilterqueue',SimpleNamespace(NetfilterQueue=Queue))
    commands=[]
    def command(args,**kwargs):
        commands.append((args,kwargs))
        if args==['nft','-f','-'] and fail_rules:raise RuntimeError('simulated nft failure')
        output='[]' if args[-1]=='bridge' else json.dumps([{'flags':['UP']}])
        return SimpleNamespace(stdout=output,returncode=0)
    def cleanup_command(args,**kwargs):
        commands.append((args,kwargs))
        return SimpleNamespace(returncode=1,stdout=b'')
    monkeypatch.setattr(dataplane,'run_command',command)
    monkeypatch.setattr(dataplane.subprocess,'run',cleanup_command)
    if fail_rules:
        with pytest.raises(RuntimeError,match='simulated'):dataplane.run()
    else:dataplane.run()
    args=[item[0] for item in commands]
    assert ['ip','link','set','dev','eth0','master','wafbr0'] not in args # Management is never bridged.
    assert ['ip','link','set','dev','eth1','master','wafbr0'] in args
    assert ['ip','link','set','dev','eth2','master','wafbr0'] in args
    assert ['ip','link','delete','dev','wafbr0'] in args
    assert queue_calls==[('bind',83),('unbind',)]
    assert store.agent_state()['state']=='stopped'
    if not fail_rules:
        assert ['nft','delete','table','bridge','waf_guard'] in args
        rules=next(kwargs['input'] for args,kwargs in commands if args==['nft','-f','-'])
        assert 'flush ruleset' not in rules
        assert 'bypass' not in rules
