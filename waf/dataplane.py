# ============================================================
# 文件名称：dataplane.py
# 生成日期：2026-10-27
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：运行旁挂采集及透明串联检测。
#           文件用途：供WAF的 yuhan/waf/dataplane.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Optional Linux mirror / transparent bridge data plane (cleartext HTTP/1.x)."""
import hashlib
import json
import os
import platform
import secrets
import signal
import subprocess
import time
import threading
from collections import OrderedDict
from pathlib import Path

import h11
from urllib.parse import urlsplit

from .network import adapters, privileged, resolve
from .rules import RateLimiter, inspect
from .custom_rules import evaluate as evaluate_custom
from .tls import request_hostname
from starlette.datastructures import Headers
from .store import Store


def fingerprint(config):
    return hashlib.sha256(config.model_dump_json().encode()).hexdigest()


class HTTPFlow:
    def __init__(self, sequence):
        self.next = sequence
        self.pending = {}
        self.parser = h11.Connection(h11.SERVER, max_incomplete_event_size=65536)
        self.request = None
        self.domain = ''
        self.body_size = 0
        self.tail = ''
        self.rule = ''
        self.blocked = False
        self.allow_rule = ''
        self.seen = time.monotonic()


class Inspector:
    """Bounded TCP reassembly plus HTTP framing. No payloads are persisted."""
    def __init__(self, store, passive=False):
        self.store = store
        self.passive = passive
        self.flows = OrderedDict()
        self.limiter = RateLimiter()

    def feed(self, key, sequence, payload, syn=False, fin=False):
        now = time.monotonic()
        settings = self.store.settings()
        enforce = not self.passive and settings['mode']=='block'
        while self.flows and next(iter(self.flows.values())).seen + 120 < now:
            self.flows.popitem(last=False)
        if syn:
            self.flows.pop(key, None)
            sequence = (sequence + 1) & 0xffffffff
        if key not in self.flows:
            if len(self.flows) >= 1024:
                # Do not evict an active flow and silently lose its parser state.
                self.store.event(secrets.token_hex(12),key[0],'TCP','/',
                    'blocked' if enforce else 'detected','FLOW_CAPACITY',0)
                return enforce
            self.flows[key] = HTTPFlow(sequence)
        flow = self.flows[key]
        self.flows.move_to_end(key)
        flow.seen = now
        if flow.blocked: return True
        def record(rule, action=None):
            request = flow.request or ('TCP', '/')
            self.store.event(secrets.token_hex(12), key[0], request[0], request[1],
                action or ('blocked' if enforce else 'detected'), rule, 0,flow.domain)
        def hit(rule):
            if flow.rule != rule: record(rule)
            flow.rule = rule
            flow.blocked = enforce
        # Signed modulo comparison handles TCP sequence wraparound.
        distance = ((sequence-flow.next + 2**31) % 2**32) - 2**31
        if distance < 0:
            payload = payload[min(-distance,len(payload)):]
            sequence = flow.next
        if payload and sequence != flow.next:
            flow.pending[sequence] = payload
            if len(flow.pending)>32 or sum(map(len,flow.pending.values()))>65536: hit('TCP_REASSEMBLY')
            return flow.blocked
        chunks = [payload] if payload else []
        flow.next = (flow.next+len(payload)) & 0xffffffff
        # Pending retransmissions may overlap; trim already assembled prefixes.
        while flow.pending:
            candidate = None
            for seq, data in flow.pending.items():
                offset = ((seq-flow.next+2**31)%2**32)-2**31
                if offset <= 0:
                    candidate = seq, data[min(-offset,len(data)):]
                    break
            if candidate is None: break
            del flow.pending[candidate[0]]
            chunks.append(candidate[1]); flow.next = (flow.next+len(candidate[1])) & 0xffffffff
        try:
            for chunk in chunks:
                flow.parser.receive_data(chunk)
                while not flow.blocked:
                    event = flow.parser.next_event()
                    if event is h11.NEED_DATA: break
                    if isinstance(event, h11.Request):
                        target = event.target.decode('latin1')
                        flow.request = (event.method.decode('ascii'), target.split('?',1)[0][:512])
                        flow.domain=request_hostname(Headers(raw=list(event.headers)))
                        flow.body_size=0; flow.tail=''; flow.rule=''; flow.allow_rule=''
                        if not self.limiter.allow(key[0],settings['rate_limit']): hit('RATE')
                        elif event.method in (b'TRACE',b'CONNECT'): hit('METHOD')
                        if not flow.blocked:
                            parsed=urlsplit(target)
                            host=request_hostname(Headers(raw=list(event.headers)))
                            custom=evaluate_custom(settings.get('custom_rules',[]),key[0],host,event.method.decode('ascii'),parsed.path,parsed.query)
                            if custom:
                                if custom['action']=='allow': flow.allow_rule=custom['id']
                                else:
                                    flow.rule=custom['id']
                                    record(custom['id'],'blocked' if custom['action']=='block' and not self.passive else 'detected')
                                    flow.blocked=custom['action']=='block' and not self.passive
                            if settings['enabled'] and not flow.allow_rule and not flow.blocked:
                                rule=inspect([target]+[v.decode('latin1') for k,v in event.headers if k.lower() not in (b'authorization',b'cookie')],settings['disabled_rules'])
                                if rule: hit(rule)
                    elif isinstance(event,h11.Data):
                        flow.body_size += len(event.data)
                        if flow.body_size>settings['max_body_bytes']: hit('BODY')
                        elif settings['enabled'] and not flow.allow_rule:
                            text=flow.tail+bytes(event.data).decode('utf-8','replace')
                            rule=inspect([text],settings['disabled_rules'])
                            flow.tail=text[-4096:]
                            if rule: hit(rule)
                    elif isinstance(event,h11.EndOfMessage):
                        if not flow.rule: record(flow.allow_rule, 'observed' if self.passive else 'allowed')
                        trailing=flow.parser.trailing_data[0]
                        flow.parser=h11.Connection(h11.SERVER,max_incomplete_event_size=65536)
                        flow.request=None
                        flow.domain=''
                        if trailing: flow.parser.receive_data(trailing)
                        else: break
                    elif isinstance(event,h11.ConnectionClosed): break
                    elif event is h11.PAUSED:
                        hit('HTTP_UPGRADE'); break
        except (h11.RemoteProtocolError, ValueError):
            hit('HTTP_PROTOCOL')
        result=flow.blocked
        if fin: self.flows.pop(key,None)
        return result


def run_command(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=15, **kwargs)


def run():
    if platform.system()!='Linux': raise SystemExit('Mirror / transparent inline data plane requires Linux.')
    if not privileged(): raise SystemExit('Data plane requires root / CAP_NET_ADMIN and CAP_NET_RAW.')
    try:
        from scapy.all import IP, IPv6, TCP, Ether, AsyncSniffer
    except ImportError: raise SystemExit('Install requirements-linux.txt first.')
    from dotenv import load_dotenv
    root=Path(__file__).resolve().parents[1]
    load_dotenv(os.getenv('WAF_ENV_FILE',str(root/'.env')))
    store=Store()
    import fcntl
    lock_dir = root/'runtime' if store.engine == 'postgresql' else Path(store.path).parent
    lock_dir.mkdir(parents=True,exist_ok=True)
    lock_path=lock_dir/'dataplane.lock'
    lock_file=lock_path.open('a')
    try: fcntl.flock(lock_file.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError: raise SystemExit('A data plane worker is already running.')
    config=store.network()
    if config.deployment_mode=='proxy': raise SystemExit('Select mirror or inline mode in System Configuration first.')
    inventory=adapters(); bound=resolve(config,inventory)
    aliases=[config.mirror_alias] if config.deployment_mode=='bypass' else [config.ingress_alias,config.egress_alias]
    for alias in aliases:
        if not bound.get(alias): raise SystemExit(f'Unbound / missing NIC: {alias}')
    management=next(nic for nic in config.interfaces if nic.role=='management')
    if not bound.get(management.alias): raise SystemExit('Bind a dedicated management NIC first.')
    names=[bound[alias]['name'] for alias in aliases]
    # Business ports must be dedicated; do not take over an active host-addressed NIC.
    for nic in inventory:
        if nic['name'] in names and (nic['ipv4'] or nic.get('ipv6_global')):
            raise SystemExit('Business NICs must have no host IP addresses: '+nic['name'])
    stopping=False
    def stop(*_):
        nonlocal stopping
        stopping=True
    signal.signal(signal.SIGTERM,stop); signal.signal(signal.SIGINT,stop)
    inspector=Inspector(store,passive=config.deployment_mode=='bypass')
    identity=fingerprint(config)
    def heartbeat(state='running'):
        store.agent_state({'state':state,'heartbeat':time.time(),'fingerprint':identity,
                           'mode':config.deployment_mode,'aliases':aliases,'pid':os.getpid()})
    def packet(raw):
        parsed=IP(raw) if raw and raw[0]>>4==4 else IPv6(raw) if raw and raw[0]>>4==6 else Ether(raw)
        if TCP not in parsed: return False
        tcp=parsed[TCP]
        if tcp.dport not in (80,8080): return False
        ip=parsed[IP] if IP in parsed else parsed[IPv6] if IPv6 in parsed else None
        if ip is None: return False
        # Encrypted application data is outside the cleartext HTTP parser's scope.
        return inspector.feed((ip.src,tcp.sport,ip.dst,tcp.dport),tcp.seq,bytes(tcp.payload),
                              syn=bool(tcp.flags&2),fin=bool(tcp.flags&5))
    queue=None; sniffer=None; capture_errors=[]; bridge_created=False; nft_created=False; raised=[]
    # Validate optional inline dependency before altering the host network.
    if config.deployment_mode=='inline':
        try:
            from netfilterqueue import NetfilterQueue
        except ImportError: raise SystemExit('Install NetfilterQueue and Linux netfilter libraries first.')
    heartbeat('starting')
    try:
        for name in names:
            link=json.loads(run_command(['ip','-j','link','show','dev',name]).stdout)[0]
            if link.get('master'): raise RuntimeError('Business NIC already belongs to a bridge / bond: '+name)
            if 'UP' not in link.get('flags',[]):
                run_command(['ip','link','set','dev',name,'up']); raised.append(name)
        if config.deployment_mode=='inline':
            # Only own these uniquely named resources; never flush an existing ruleset.
            if run_command(['ip','-j','link','show','type','bridge']).stdout.find('wafbr0')>=0:
                raise RuntimeError('wafbr0 already exists; inspect and remove stale resources manually')
            existing=subprocess.run(['nft','list','table','bridge','waf_guard'],capture_output=True)
            if existing.returncode==0: raise RuntimeError('bridge waf_guard table already exists')
            run_command(['ip','link','add','name','wafbr0','type','bridge']); bridge_created=True
            for name in names: run_command(['ip','link','set','dev',name,'master','wafbr0'])
            run_command(['ip','link','set','dev','wafbr0','up'])
            queue=NetfilterQueue()
            def verdict(item):
                try:
                    if packet(item.get_payload()): item.drop()
                    else: item.accept()
                except Exception:
                    item.drop()
                    capture_errors.append(RuntimeError('Inline packet inspection failed'))
            queue.bind(83,verdict,max_len=4096)
            # No queue bypass: worker loss drops queued HTTP packets instead of silently allowing them.
            devices=', '.join(json.dumps(name) for name in names)
            rules='table bridge waf_guard { chain forward { type filter hook forward priority -200; policy accept; '+f'iifname {{ {devices} }} tcp dport {{ 80, 8080 }} queue num 83; '+'} }'
            run_command(['nft','-f','-'],input=rules); nft_created=True
        else:
            started=threading.Event()
            def captured(value):
                try: packet(bytes(value))
                except Exception as exc: capture_errors.append(exc)
            sniffer=AsyncSniffer(iface=names[0],filter='tcp and (dst port 80 or dst port 8080)',store=False,
                                 prn=captured,promisc=True,started_callback=started.set)
            sniffer.start()
            if not started.wait(5): raise RuntimeError('Mirror capture did not start; check libpcap and NIC permissions')
        heartbeat()
        while not stopping:
            if fingerprint(store.network())!=identity: break
            if queue:
                queue.run(block=False)
                if capture_errors: raise capture_errors[0]
                time.sleep(.01)
            else:
                if capture_errors: raise RuntimeError('Mirror packet inspection failed') from capture_errors[0]
                if not sniffer.running: raise RuntimeError('Mirror capture stopped unexpectedly')
                time.sleep(.2)
            if time.time()-store.agent_state().get('heartbeat',0)>3: heartbeat()
    finally:
        heartbeat('stopped')
        if sniffer and sniffer.running: sniffer.stop()
        if nft_created: subprocess.run(['nft','delete','table','bridge','waf_guard'],capture_output=True)
        if queue: queue.unbind()
        if bridge_created:
            for name in names: subprocess.run(['ip','link','set','dev',name,'nomaster'],capture_output=True)
            subprocess.run(['ip','link','delete','dev','wafbr0'],capture_output=True)
        for name in raised: subprocess.run(['ip','link','set','dev',name,'down'],capture_output=True)


if __name__=='__main__': run()
