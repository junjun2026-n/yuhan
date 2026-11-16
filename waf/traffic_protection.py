"""Bounded per-process HTTP traffic protection for WAF business listeners."""
import ipaddress
import math
import threading
import time
import secrets
from collections import OrderedDict
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class CCConfig(BaseModel):
    enabled: bool = False
    target_type: Literal['all','domain','ip'] = 'all'
    target: str = Field(default='',max_length=253)
    window_seconds: int = Field(default=10, ge=1, le=3600)
    max_requests: int = Field(default=100, ge=1, le=100000)
    ban_seconds: int = Field(default=60, ge=1, le=86400)

    @model_validator(mode='after')
    def binding(self):
        if self.target_type=='all':
            self.target=''
        elif self.target_type=='domain':
            from .tls import normalize_domain
            self.target=normalize_domain(self.target)
        else:
            self.target=str(ipaddress.ip_address(self.target.strip()))
            if ipaddress.ip_address(self.target).is_unspecified:
                raise ValueError('目标 IP 须为实际业务入口 IP，不能使用 0.0.0.0 或 ::')
        return self


class PortConfig(BaseModel):
    enabled: bool = False
    target_type: Literal['all','domain','ip'] = 'all'
    target: str = Field(default='',max_length=253)
    protocol: Literal['all','http','https'] = 'all'
    destination_port: int | None = Field(default=None,ge=1,le=65535)
    allowed_sources: list[str] = Field(default_factory=list, max_length=200)
    blocked_sources: list[str] = Field(default_factory=list, max_length=200)
    max_concurrent_per_ip: int = Field(default=20, ge=1, le=10000)
    max_concurrent_total: int = Field(default=1000, ge=1, le=50000)

    @field_validator('allowed_sources', 'blocked_sources')
    @classmethod
    def addresses(cls, values):
        return sorted(set(str(ipaddress.ip_network(value.strip(), strict=False)) for value in values))

    @model_validator(mode='after')
    def binding(self):
        binding=CCConfig(target_type=self.target_type,target=self.target)
        self.target=binding.target
        return self


class CCRule(CCConfig):
    id: str = Field(pattern=r'^CC-[a-f0-9]{16}$')
    name: str = Field(min_length=1,max_length=80)


class PortRule(PortConfig):
    id: str = Field(pattern=r'^PORT-[a-f0-9]{16}$')
    name: str = Field(min_length=1,max_length=80)


class ProtectionConfig(BaseModel):
    cc: CCConfig = Field(default_factory=CCConfig)
    ports: PortConfig = Field(default_factory=PortConfig)
    cc_rules: list[CCRule] | None = Field(default=None,max_length=100)
    port_rules: list[PortRule] | None = Field(default=None,max_length=100)

    @model_validator(mode='after')
    def unique_ids(self):
        for rules in (self.cc_rules,self.port_rules):
            if rules is not None and len({rule.id for rule in rules})!=len(rules): raise ValueError('策略编号重复')
        return self


def policy_rules(config,section):
    rules=config.cc_rules if section=='cc' else config.port_rules
    if rules is not None: return rules
    value=config.cc if section=='cc' else config.ports
    model=CCRule if section=='cc' else PortRule
    return [model(**value.model_dump(),id=('CC-' if section=='cc' else 'PORT-')+'0000000000000000',name='原有 CC 策略' if section=='cc' else '原有业务端口策略')]


class PolicyConflict(ValueError):
    pass


def change_rule(store,section,value=None,identifier=None,delete=False):
    model=CCRule if section=='cc' else PortRule
    key='cc_rules' if section=='cc' else 'port_rules'
    with store.connect() as db:
        if store.engine=='sqlite': db.execute('BEGIN IMMEDIATE')
        else: db.execute('SELECT pg_advisory_xact_lock(830021)')
        row=db.execute('SELECT value FROM traffic_protection WHERE id=1').fetchone()
        config=ProtectionConfig.model_validate_json(row[0]) if row else ProtectionConfig()
        rules=policy_rules(config,section)
        existing=next((i for i,rule in enumerate(rules) if rule.id==identifier),None)
        if identifier and existing is None: raise KeyError('策略不存在')
        if delete:
            if rules[existing].enabled: raise PolicyConflict('启用中的策略不能删除，请先停用策略')
            rules.pop(existing)
        else:
            data=dict(value)
            data['id']=identifier or ('CC-' if section=='cc' else 'PORT-')+secrets.token_hex(8)
            rule=model(**data)
            if identifier: rules[existing]=rule
            else:
                if len(rules)>=100: raise ValueError('每类最多 100 条策略')
                rules.append(rule)
        setattr(config,key,rules)
        db.execute('INSERT INTO traffic_protection VALUES(1,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value',(config.model_dump_json(),))
        return config


def configuration(store):
    with store.connect() as db:
        row = db.execute('SELECT value FROM traffic_protection WHERE id=1').fetchone()
    return ProtectionConfig.model_validate_json(row[0]) if row else ProtectionConfig()


def save(store, config, section=None):
    with store.connect() as db:
        if store.engine=='sqlite': db.execute('BEGIN IMMEDIATE')
        else: db.execute('SELECT pg_advisory_xact_lock(830021)')
        if section:
            row=db.execute('SELECT value FROM traffic_protection WHERE id=1').fetchone()
            current=ProtectionConfig.model_validate_json(row[0]) if row else ProtectionConfig()
            setattr(current,section,getattr(config,section))
            # Legacy single-policy writes cannot silently disable multi-policy configuration.
            if getattr(current,'cc_rules' if section=='cc' else 'port_rules') is not None:
                raise ValueError('已使用多策略，请通过策略列表编辑')
            config=current
        db.execute('INSERT INTO traffic_protection VALUES(1,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value',
                   (config.model_dump_json(),))
        return config


def target_matches(kind,target,host,destination_ip):
    from .tls import domain_matches
    if kind=='all': return True
    if kind=='domain': return bool(host) and domain_matches(host,target)
    try: return ipaddress.ip_address(destination_ip)==ipaddress.ip_address(target)
    except ValueError: return False


class SingleTrafficGuard:
    """Window counter with timed bans, bounded clients, and in-flight admission."""
    def __init__(self, clock=time.monotonic, capacity=20000):
        self.clock = clock
        self.capacity = capacity
        self.clients = OrderedDict()
        self.active = {}
        self.total = 0
        self.fingerprint = None
        self.lock = threading.Lock()

    def enter(self, ip, config, host='', destination_ip=''):
        """Return (rule, status, retry_after, admission_token)."""
        now = self.clock()
        with self.lock:
            fingerprint = config.model_dump_json()
            if fingerprint != self.fingerprint:
                self.clients.clear()
                self.fingerprint = fingerprint
                self.allowed = [ipaddress.ip_network(item) for item in config.ports.allowed_sources]
                self.blocked = [ipaddress.ip_network(item) for item in config.ports.blocked_sources]
            ports = config.ports
            if ports.enabled:
                try: address = ipaddress.ip_address(ip)
                except ValueError: return 'PORT_SOURCE', 403, 0, False
                if any(address in network for network in self.blocked): return 'PORT_DENY', 403, 0, False
                if self.allowed and not any(address in network for network in self.allowed): return 'PORT_ALLOW', 403, 0, False
            cc = config.cc
            matches=target_matches(cc.target_type,cc.target,host,destination_ip)
            if cc.enabled and matches:
                # Wildcard domains keep independent counters for each actual host.
                key=(ip,host if cc.target_type=='domain' else cc.target)
                # Sorted by last_seen: expired idle clients can be reclaimed cheaply.
                while self.clients:
                    first = next(iter(self.clients.values()))
                    if first[3] + max(cc.window_seconds, cc.ban_seconds) > now: break
                    self.clients.popitem(last=False)
                state = self.clients.get(key)
                if state is None:
                    if len(self.clients) >= self.capacity: return 'CC_CAPACITY', 429, 1, False
                    state = [now, 0, 0, now]
                    self.clients[key] = state
                self.clients.move_to_end(key)
                state[3] = now
                if state[2] > now: return 'CC_BAN', 429, max(1, math.ceil(state[2]-now)), False
                if state[2] or state[0] + cc.window_seconds <= now:
                    state[0], state[1], state[2] = now, 0, 0
                state[1] += 1
                if state[1] > cc.max_requests:
                    state[2] = now + cc.ban_seconds
                    return 'CC_RATE', 429, cc.ban_seconds, False
            if ports.enabled:
                if self.total >= ports.max_concurrent_total: return 'PORT_CAPACITY', 503, 1, False
                if self.active.get(ip, 0) >= ports.max_concurrent_per_ip: return 'PORT_CONCURRENT', 429, 1, False
                self.total += 1
                self.active[ip] = self.active.get(ip, 0) + 1
                return '', 200, 0, True
            return '', 200, 0, False

    def leave(self, ip, token):
        if not token: return
        with self.lock:
            self.total -= 1
            count = self.active[ip] - 1
            if count: self.active[ip] = count
            else: del self.active[ip]


class TrafficGuard(SingleTrafficGuard):
    def __init__(self,clock=time.monotonic,capacity=20000):
        super().__init__(clock,capacity)
        self.children={}
        self.multi_lock=threading.Lock()

    def enter(self,ip,config,host='',destination_ip='',destination_port=None,scheme='http'):
        if config.cc_rules is None and config.port_rules is None:
            ports=config.ports
            if not (target_matches(ports.target_type,ports.target,host,destination_ip) and
                    (ports.protocol=='all' or ports.protocol==scheme) and
                    (ports.destination_port is None or ports.destination_port==destination_port)):
                config=config.model_copy(update={'ports':PortConfig()})
            return super().enter(ip,config,host,destination_ip)
        with self.multi_lock:
            tokens=[]
            all_rules=[('ports',rule) for rule in policy_rules(config,'ports')]+[('cc',rule) for rule in policy_rules(config,'cc')]
            valid={rule.id for _,rule in all_rules if rule.enabled}
            self.children={key:child for key,child in self.children.items() if key in valid}
            for section,rule in all_rules:
                if not rule.enabled or not target_matches(rule.target_type,rule.target,host,destination_ip): continue
                if section=='ports' and ((rule.protocol!='all' and rule.protocol!=scheme) or
                        (rule.destination_port is not None and rule.destination_port!=destination_port)): continue
                child=self.children.get(rule.id)
                if child is None:
                    child=SingleTrafficGuard(self.clock,self.capacity)
                    self.children[rule.id]=child
                effective=ProtectionConfig(**{section:rule.model_dump()})
                code,status,retry,token=child.enter(ip,effective,host,destination_ip)
                if code:
                    for prior,admitted in tokens: prior.leave(ip,admitted)
                    return code+':'+rule.id,status,retry,False
                if token: tokens.append((child,token))
            return '',200,0,tokens

    def leave(self,ip,token):
        if isinstance(token,list):
            for child,admitted in token: child.leave(ip,admitted)
        else: super().leave(ip,token)


class ProtectionMiddleware:
    """Wrap the whole HTTP response, including slow uploads and errors."""
    def __init__(self, app, store, guard):
        self.app, self.store, self.guard = app, store, guard

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http': return await self.app(scope, receive, send)
        import asyncio
        import secrets
        from starlette.responses import JSONResponse
        ip = (scope.get('client') or ('unknown', 0))[0]
        config = await asyncio.to_thread(configuration, self.store)
        from starlette.datastructures import Headers
        from .tls import request_hostname
        host=request_hostname(Headers(scope=scope))
        destination_ip=(scope.get('server') or ('',0))[0]
        destination_port=(scope.get('server') or ('',0))[1]
        rule, status, retry, token = self.guard.enter(ip, config, host, destination_ip,destination_port,scope.get('scheme','http'))
        if rule:
            identifier = secrets.token_hex(12)
            await asyncio.to_thread(self.store.event, identifier, ip, scope['method'], scope['path'], 'blocked', rule, status,host)
            headers = {'X-WAF-Request-ID': identifier}
            if retry: headers['Retry-After'] = str(retry)
            response = JSONResponse({'detail':'请求被 CC 或业务端口防护限制', 'request_id':identifier}, status_code=status, headers=headers)
            return await response(scope, receive, send)
        try: await self.app(scope, receive, send)
        finally: self.guard.leave(ip, token)
