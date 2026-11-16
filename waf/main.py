import asyncio
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, Query
from datetime import datetime,timezone
from fastapi.responses import FileResponse, JSONResponse, Response, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from typing import Literal
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .rules import RULES, RateLimiter, inspect
from .custom_rules import CustomRule, evaluate as evaluate_custom
from .store import Store
from .platform_config import PlatformConfig, status as platform_status, test_database
from .network import NetworkConfig, adapters, validate_bindings, apply_management, network_status
from .tls import normalize_domain, request_hostname, domain_matches, install_certificate, validate_https, public_status
from .database_config import DatabaseConfig, configuration_status, probe as probe_config, stage as stage_database
from .origins import OriginRouter, normalize_origin

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(os.getenv('WAF_ENV_FILE', str(ROOT / '.env')))
HOP = {'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te',
       'trailer', 'transfer-encoding', 'upgrade', 'content-length'}
basic = HTTPBasic(auto_error=False)


class CertificateInput(BaseModel):
    certificate: str = Field(min_length=1, max_length=1398104)
    private_key: str = Field(default='', max_length=87384)
    password: SecretStr = SecretStr('')
    encoding: Literal['text','base64'] = 'text'


class OriginRuleInput(BaseModel):
    domain: str
    port: int | None = Field(default=None, ge=1, le=65535)
    path_prefix: str = Field(default='/', min_length=1, max_length=1024)
    priority: int = Field(default=100, ge=0, le=10000)
    origins: list[str] = Field(min_length=1, max_length=16)

    @field_validator('domain')
    @classmethod
    def valid_domain(cls, value):
        return normalize_domain(value)

    @field_validator('path_prefix')
    @classmethod
    def valid_prefix(cls, value):
        if not value.startswith('/') or any(char in value for char in '\\?#'):
            raise ValueError('路径前缀必须以 / 开头且不能包含查询参数')
        return value

    @field_validator('origins')
    @classmethod
    def valid_origins(cls, value):
        result = list(dict.fromkeys(normalize_origin(item) for item in value))
        if not all(result): raise ValueError('规则源站地址不能为空')
        return result


class SettingsInput(BaseModel):
    upstream: str = ''
    mode: str = 'block'
    enabled: bool = True
    rate_limit: int = Field(default=120, ge=1, le=100000)
    max_body_bytes: int = Field(default=1048576, ge=1024, le=10485760)
    disabled_rules: list[str] = Field(default_factory=list)
    protected_domains: list[str] = Field(default_factory=list, max_length=100)
    tls_enabled: bool = False
    tls_port: int = Field(default=8443, ge=1, le=65535)
    tls_certificate: str = ''
    domain_certificates: dict[str, str] = Field(default_factory=dict, max_length=100)
    domain_upstreams: dict[str, list[str]] = Field(default_factory=dict, max_length=100)
    origin_rules: list[OriginRuleInput] = Field(default_factory=list, max_length=500)

    @field_validator('domain_upstreams')
    @classmethod
    def valid_domain_upstreams(cls, value):
        result = {}
        for domain, origins in value.items():
            domain = normalize_domain(domain)
            if domain in result:
                raise ValueError('源站绑定域名重复')
            if not 1 <= len(origins) <= 16:
                raise ValueError('每个域名须配置 1 至 16 个源站')
            normalized = list(dict.fromkeys(normalize_origin(origin) for origin in origins))
            if not all(normalized):
                raise ValueError('源站地址不能为空')
            result[domain] = normalized
        return result

    @model_validator(mode='after')
    def bound_domains(self):
        if set(self.domain_upstreams) - set(self.protected_domains):
            raise ValueError('请先将源站绑定域名加入受保护域名')
        if set(rule.domain for rule in self.origin_rules) - set(self.protected_domains):
            raise ValueError('复杂匹配规则域名必须加入受保护域名')
        if len({(rule.domain, rule.port, rule.path_prefix, rule.priority) for rule in self.origin_rules}) != len(self.origin_rules):
            raise ValueError('复杂匹配规则不能重复')
        return self

    @field_validator('domain_certificates')
    @classmethod
    def valid_domain_certificates(cls, value):
        import re
        result = {}
        for domain, identifier in value.items():
            domain = normalize_domain(domain)
            if domain in result: raise ValueError('证书绑定域名重复')
            if not re.fullmatch(r'[0-9a-f]{64}', identifier): raise ValueError('证书编号无效')
            result[domain] = identifier
        return result

    @field_validator('protected_domains')
    @classmethod
    def valid_domains(cls, value):
        return sorted(set(normalize_domain(domain) for domain in value))

    @field_validator('tls_port')
    @classmethod
    def valid_tls_port(cls, value):
        if value in (8300, 8301): raise ValueError('HTTPS 端口不能占用现有代理或管理端口')
        return value

    @field_validator('mode')
    @classmethod
    def valid_mode(cls, value):
        if value not in ('block', 'monitor'): raise ValueError('模式必须为 block 或 monitor')
        return value

    @field_validator('upstream')
    @classmethod
    def valid_upstream(cls, value):
        return normalize_origin(value)

    @field_validator('disabled_rules')
    @classmethod
    def valid_rules(cls, value):
        if set(value) - {rule['id'] for rule in RULES}: raise ValueError('未知规则编号')
        return sorted(set(value))


def create_app(plane='proxy', database=None, transport=None):
    if plane not in ('proxy', 'admin'): raise ValueError('Unknown plane')
    store = Store(database)
    limiter = RateLimiter()
    origin_router = OriginRouter()
    @asynccontextmanager
    async def lifespan(app):
        async with httpx.AsyncClient(timeout=httpx.Timeout(30, connect=5), follow_redirects=False,
                trust_env=False, transport=transport, limits=httpx.Limits(max_connections=100)) as client:
            app.state.client = client
            stop = asyncio.Event()
            run_sender = plane == 'admin' and os.getenv('WAF_LOG_SENDER', '1') == '1'
            if run_sender:
                from .log_forwarding import worker
                sender = asyncio.create_task(worker(store, stop))
            try:
                yield
            finally:
                if run_sender:
                    stop.set()
                    await sender
    app = FastAPI(title='WAF ' + plane, version='v0.261115', lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store = store
    from .traffic_protection import ProtectionConfig, TrafficGuard, ProtectionMiddleware, configuration as protection_config, save as save_protection
    if plane=='proxy':
        app.state.traffic_guard = TrafficGuard()
        app.add_middleware(ProtectionMiddleware,store=store,guard=app.state.traffic_guard)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=os.getenv('WAF_TRUSTED_HOSTS', '*').split(','))

    from . import accounts
    if plane=='admin': accounts.bootstrap(store)
    async def authenticate(request: Request, credentials: HTTPBasicCredentials | None = Depends(basic)):
        # The startup secret is only an internal probe credential after bootstrap.
        probe=os.getenv('WAF_ADMIN_PASSWORD','')
        if (request.method=='GET' and request.url.path in ('/api/system/status','/api/system','/api/tls','/api/settings')
                and request.client and request.client.host=='127.0.0.1' and probe
                and secrets.compare_digest(request.headers.get('x-waf-probe','').encode(),probe.encode())):
            return {'username':'internal-probe','role':'administrator','permissions':[],'enabled':True}
        users=await asyncio.to_thread(accounts.read,store)
        from . import sessions
        if request.cookies.get(sessions.BLOCK):
            raise HTTPException(401, '已退出，请重新登录')
        if sessions.COOKIE in request.cookies:
            user=await asyncio.to_thread(sessions.resolve,store,request.cookies[sessions.COOKIE],users)
            valid=bool(user)
        else:
            if request.headers.get('sec-fetch-mode') or 'text/html' in request.headers.get('accept',''):
                raise HTTPException(401, '请通过登录页面登录')
            user=next((item for item in users if credentials and item['username']==credentials.username),None)
            valid=user and user['enabled'] and await asyncio.to_thread(accounts.verify,credentials.password,user['password_hash'])
        if not valid:
            raise HTTPException(401, '账号或密码错误', headers={} if sessions.COOKIE in request.cookies else {'WWW-Authenticate':'Basic realm="WAF"'})
        required=accounts.required(request.url.path,request.method)
        granted=accounts.permissions(user)
        if required and not (any(item in granted for item in required) if isinstance(required,tuple) else required in granted):
            raise HTTPException(403,'没有此功能的访问权限')
        request.state.username=user['username']
        accounts.actor.set(user['username'])
        return user

    @app.middleware('http')
    async def security_headers(request, call_next):
        if plane == 'admin' and request.method not in ('GET', 'HEAD', 'OPTIONS'):
            # Basic auth is ambient browser authentication; require same-origin JSON.
            origin = request.headers.get('origin')
            expected = f'{request.url.scheme}://{request.headers.get("host", "")}'
            if origin != expected or request.headers.get('content-type', '').split(';')[0] != 'application/json':
                return JSONResponse({'detail':'请求来源或类型不匹配'}, status_code=403)
        response = await call_next(request)
        if plane == 'admin' and request.url.path == '/' and response.status_code == 401 and 'text/html' in request.headers.get('accept',''):
            response = RedirectResponse('/login',status_code=303)
        if plane == 'admin':
            response.headers.update({'Cache-Control':'no-store', 'X-Frame-Options':'DENY',
                'X-Content-Type-Options':'nosniff', 'Referrer-Policy':'no-referrer',
                'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'"})
        return response

    if plane == 'admin':
        from . import sessions
        class LoginInput(BaseModel):
            username: str = Field(max_length=64)
            password: SecretStr = Field(max_length=128)

        @app.get('/login')
        def login_page(): return FileResponse(ROOT/'static/login.html')

        @app.get('/login.js')
        def login_script(): return FileResponse(ROOT/'static/login.js',media_type='application/javascript')

        @app.get('/login.css')
        def login_style(): return FileResponse(ROOT/'static/login.css',media_type='text/css')

        @app.post('/api/login')
        async def login(value: LoginInput, request: Request):
            if not limiter.allow('login:'+(request.client.host if request.client else 'unknown'),30):
                raise HTTPException(429,'登录尝试过多，请稍后重试')
            users=await asyncio.to_thread(accounts.read,store)
            user=next((item for item in users if item['username']==value.username and item['enabled']),None)
            if not user or not await asyncio.to_thread(accounts.verify,value.password.get_secret_value(),user['password_hash']):
                raise HTTPException(401,'帐号或密码错误')
            if request.cookies.get(sessions.COOKIE):
                await asyncio.to_thread(sessions.revoke,store,request.cookies[sessions.COOKIE])
            token=await asyncio.to_thread(sessions.issue,store,user)
            await asyncio.to_thread(store.event,secrets.token_hex(8),user['username'],'POST','/api/login','admin','USER_LOGIN',200)
            response=JSONResponse({'ok':True})
            response.delete_cookie(sessions.BLOCK)
            response.set_cookie(sessions.COOKIE,token,max_age=sessions.TTL,httponly=True,secure=request.url.scheme=='https',samesite='strict')
            return response

        @app.post('/api/logout')
        async def logout(request: Request):
            if request.cookies.get(sessions.COOKIE):
                users=await asyncio.to_thread(accounts.read,store)
                user=await asyncio.to_thread(sessions.resolve,store,request.cookies[sessions.COOKIE],users)
                await asyncio.to_thread(sessions.revoke,store,request.cookies[sessions.COOKIE])
                if user:
                    await asyncio.to_thread(store.event,secrets.token_hex(8),user['username'],'POST','/api/logout','admin','USER_LOGOUT',200)
            response=JSONResponse({'ok':True})
            response.delete_cookie(sessions.COOKIE)
            response.set_cookie(sessions.BLOCK,'1',httponly=True,secure=request.url.scheme=='https',samesite='strict')
            return response

        accounts.install(app,store,authenticate)
        @app.get('/api/traffic-protection',dependencies=[Depends(authenticate)])
        def traffic_protection(): return protection_config(store)
        @app.put('/api/traffic-protection',dependencies=[Depends(authenticate)])
        def update_traffic_protection(value:ProtectionConfig,section:Literal['cc','ports']|None=None,user=Depends(authenticate)):
            try: result=save_protection(store,value,section)
            except ValueError as exc: raise HTTPException(422,str(exc))
            store.event(secrets.token_hex(8),user['username'],'PUT','/api/traffic-protection','admin','TRAFFIC_PROTECTION',200)
            return result
        from .traffic_protection import change_rule,policy_rules,CCRule,PortRule,PolicyConflict
        @app.get('/api/traffic-protection/rules',dependencies=[Depends(authenticate)])
        def traffic_rules():
            value=protection_config(store)
            return {section:policy_rules(value,section) for section in ('cc','ports')}
        class TrafficRuleInput(BaseModel):
            name: str = Field(min_length=1,max_length=80)
            config: dict
        def update_policy(section,value,identifier,user,delete=False):
            try: result=change_rule(store,section,{**value.config,'name':value.name} if value else None,identifier,delete)
            except KeyError as exc: raise HTTPException(404,'策略不存在')
            except PolicyConflict as exc: raise HTTPException(409,str(exc))
            except ValueError as exc: raise HTTPException(422,'策略参数无效：'+str(exc))
            store.event(secrets.token_hex(8),user['username'],'DELETE' if delete else 'PUT','/api/traffic-protection/rules','admin','TRAFFIC_PROTECTION',200)
            return {key:policy_rules(result,key) for key in ('cc','ports')}
        @app.post('/api/traffic-protection/rules/{section}',dependencies=[Depends(authenticate)])
        def create_traffic_rule(section:Literal['cc','ports'],value:TrafficRuleInput,user=Depends(authenticate)):
            return update_policy(section,value,None,user)
        @app.put('/api/traffic-protection/rules/{section}/{identifier}',dependencies=[Depends(authenticate)])
        def edit_traffic_rule(section:Literal['cc','ports'],identifier:str,value:TrafficRuleInput,user=Depends(authenticate)):
            return update_policy(section,value,identifier,user)
        @app.delete('/api/traffic-protection/rules/{section}/{identifier}',dependencies=[Depends(authenticate)])
        def delete_traffic_rule(section:Literal['cc','ports'],identifier:str,user=Depends(authenticate)):
            return update_policy(section,None,identifier,user,True)
        @app.get('/', dependencies=[Depends(authenticate)])
        def index(): return FileResponse(ROOT/'static/index.html')
        @app.get('/app.js', dependencies=[Depends(authenticate)])
        def script(): return FileResponse(ROOT/'static/app.js', media_type='application/javascript')
        @app.get('/app.css', dependencies=[Depends(authenticate)])
        def style(): return FileResponse(ROOT/'static/app.css', media_type='text/css')
        @app.get('/traffic-map.js', dependencies=[Depends(authenticate)])
        def traffic_map_script(): return FileResponse(ROOT/'static/traffic-map.js',media_type='application/javascript')
        @app.get('/world-map.json', dependencies=[Depends(authenticate)])
        def world_map_data(): return FileResponse(ROOT/'static/world-map.json',media_type='application/json')
        @app.get('/api/documentation/user-guide', dependencies=[Depends(authenticate)])
        def user_guide():
            return FileResponse(ROOT/'docs/USER_GUIDE.md', media_type='text/markdown; charset=utf-8', filename='WAF-USER-GUIDE.md')
        @app.get('/api/settings', dependencies=[Depends(authenticate)])
        def settings(): return store.settings()
        @app.put('/api/settings', dependencies=[Depends(authenticate)])
        def save_settings(value: SettingsInput, user=Depends(authenticate)):
            current=store.settings()
            granted=accounts.permissions(user)
            proposed=value.model_dump()
            if 'sites' not in granted and any(proposed.get(key)!=current.get(key) for key in proposed if key not in ('disabled_rules','custom_rules')):
                raise HTTPException(403,'没有修改站点配置的权限')
            if 'rules' not in granted and proposed['disabled_rules']!=current['disabled_rules']:
                raise HTTPException(403,'没有修改系统防护规则的权限')
            try:
                validate_https(value.model_dump())
                origins = ([value.upstream] if value.upstream else []) + [origin for pool in value.domain_upstreams.values() for origin in pool] + [origin for rule in value.origin_rules for origin in rule.origins]
                for address in origins if value.tls_enabled else []:
                    from ipaddress import IPv4Interface
                    origin = urlsplit(address)
                    port = origin.port or (443 if origin.scheme == 'https' else 80)
                    local_hosts = {'localhost','127.0.0.1','0.0.0.0','::1',str(IPv4Interface(store.network().management_cidr).ip)}
                    if port == value.tls_port and (origin.hostname in local_hosts or any(domain_matches(origin.hostname, domain) for domain in value.protected_domains)):
                        raise ValueError('上游不能指向 WAF 自身的 HTTPS 入口')
            except (ValueError, OSError) as exc: raise HTTPException(422, str(exc))
            allowed=set(proposed)-{'custom_rules'}
            if 'sites' not in granted: allowed={'disabled_rules'}
            if 'rules' not in granted: allowed.discard('disabled_rules')
            store.save(proposed,preserve_custom=True,allowed_keys=allowed)
            store.event(secrets.token_hex(8), 'admin', 'PUT', '/api/settings', 'admin', 'CONFIG', 200)
            return value
        @app.get('/api/tls', dependencies=[Depends(authenticate)])
        def tls_status(): return public_status(store.settings())

        @app.post('/api/tls/certificate', dependencies=[Depends(authenticate)])
        def upload_certificate(value: CertificateInput):
            try:
                info = install_certificate(value.certificate, value.private_key, value.password.get_secret_value(), value.encoding)
            except (ValueError, OSError) as exc: raise HTTPException(422, str(exc))
            store.event(secrets.token_hex(8), 'admin', 'POST', '/api/tls/certificate', 'admin', 'TLS_CERTIFICATE', 200)
            return info
        @app.get('/api/rules', dependencies=[Depends(authenticate)])
        def rules(): return RULES
        @app.get('/api/custom-rules', dependencies=[Depends(authenticate)])
        def custom_rules(): return store.settings().get('custom_rules',[])

        @app.post('/api/custom-rules', dependencies=[Depends(authenticate)])
        def create_custom_rule(value: CustomRule):
            identifier='CUSTOM-'+secrets.token_hex(6)
            try: store.change_custom_rule(identifier,value.model_dump(mode='json'),create=True)
            except ValueError as exc: raise HTTPException(422,str(exc))
            store.event(secrets.token_hex(8),'admin','POST','/api/custom-rules','admin',identifier,200)
            return {**value.model_dump(mode='json'),'id':identifier}

        @app.put('/api/custom-rules/{identifier}', dependencies=[Depends(authenticate)])
        def update_custom_rule(identifier: str,value: CustomRule):
            try: store.change_custom_rule(identifier,value.model_dump(mode='json'))
            except KeyError: raise HTTPException(404,'规则不存在')
            store.event(secrets.token_hex(8),'admin','PUT','/api/custom-rules','admin',identifier,200)
            return {**value.model_dump(mode='json'),'id':identifier}

        @app.delete('/api/custom-rules/{identifier}', dependencies=[Depends(authenticate)])
        def delete_custom_rule(identifier: str):
            try: store.change_custom_rule(identifier,delete=True)
            except KeyError: raise HTTPException(404,'规则不存在')
            store.event(secrets.token_hex(8),'admin','DELETE','/api/custom-rules','admin',identifier,200)
            return {'ok':True}
        @app.get('/api/events', dependencies=[Depends(authenticate)])
        def events(action: str = '', page: int = 1, page_size: int = 100, paginated: bool = False,
                   since:str=Query('',max_length=40),until:str=Query('',max_length=40),
                   domain:str=Query('',max_length=253),ip:str=Query('',max_length=64),country:str=Query('',max_length=2),
                   rule_id:str=Query('',max_length=128),method:str=Query('',max_length=32),path:str=Query('',max_length=512),
                   status:int|None=Query(None,ge=0,le=599),external:bool=False,threat_type:str=Query('',max_length=64)):
            if action not in ('', 'business','hits','blacklist','attacks','blocked', 'allowed', 'observed', 'detected', 'error', 'admin') or not 1 <= page <= 100000 or not 1 <= page_size <= 500:
                raise HTTPException(422, '筛选参数无效')
            try:
                dates=[datetime.fromisoformat(value.replace('Z','+00:00')) if value else None for value in (since,until)]
                if any(value and value.tzinfo is None for value in dates) or (all(dates) and dates[0]>dates[1]):raise ValueError()
                since,until=[value.astimezone(timezone.utc).isoformat() if value else '' for value in dates]
            except ValueError:raise HTTPException(422,'时间范围无效，请使用含时区的 ISO 时间')
            filters=dict(since=since,until=until,domain=domain,ip=ip,country=country,rule_id=rule_id,method=method,path=path,status=status,external=external,threat_type=threat_type)
            if paginated or any(value is not None and value is not False and value!='' for value in filters.values()) or action in ('business','hits','blacklist','attacks'):
                result=store.events_page(action,page,page_size,**filters)
                return result if paginated else result['items']
            return store.events(action, page)
        @app.get('/api/stats', dependencies=[Depends(authenticate)])
        def stats(): return store.stats()
        @app.get('/api/stats/overview',dependencies=[Depends(authenticate)])
        def overview_stats(period:Literal['all','24h','7d','30d']='all'):
            from .reporting import overview
            return overview(store,period)
        @app.get('/api/stats/traffic-map',dependencies=[Depends(authenticate)])
        def traffic_map_stats(period:Literal['all','24h','7d','30d']='24h',limit:int=Query(150,ge=10,le=300)):
            from .traffic_map import traffic_map
            return traffic_map(store,period,limit)

        from .log_forwarding import LogConfig, configuration as log_configuration, save_config as save_log_config, public_status as log_status, render as render_log, send as send_log

        @app.get('/api/system/logging', dependencies=[Depends(authenticate)])
        def logging_config(): return log_status(store)

        @app.put('/api/system/logging', dependencies=[Depends(authenticate)])
        def save_logging(value: LogConfig):
            save_log_config(store, value)
            store.event(secrets.token_hex(8), 'admin', 'PUT', '/api/system/logging', 'admin', 'LOG_CONFIG', 200)
            return log_status(store)

        @app.post('/api/system/logging/test', dependencies=[Depends(authenticate)])
        def test_logging(value: LogConfig):
            from datetime import datetime, timezone
            if not value.host: raise HTTPException(422, '请填写接收服务器 IP')
            event = dict(id=0, created_at=datetime.now(timezone.utc).isoformat(), request_id=secrets.token_hex(8),
                         ip='admin', method='TEST', path='/api/system/logging/test', action='admin', rule_id='LOG_TEST', status=200)
            payload = render_log(value, event, store.platform_config())
            try: send_log(value, payload)
            except (OSError, ValueError): raise HTTPException(422, '测试发送失败，请检查地址、端口、协议及 TLS 证书')
            store.event(event['request_id'], 'admin', 'POST', event['path'], 'admin', 'LOG_TEST', 200)
            return {'detail': '测试日志已发送，请在接收端核对。UDP 不提供送达确认。', 'preview': payload.decode('utf-8')}

        @app.get('/api/system/platform', dependencies=[Depends(authenticate)])
        def platform_config(): return platform_status(store)

        @app.put('/api/system/platform', dependencies=[Depends(authenticate)])
        def save_platform_config(value: PlatformConfig):
            store.save_platform_config(value)
            store.event(secrets.token_hex(8), 'admin', 'PUT', '/api/system/platform', 'admin', 'PLATFORM_CONFIG', 200)
            return platform_status(store)

        @app.post('/api/system/database/test', dependencies=[Depends(authenticate)])
        def database_test():
            import sqlite3
            import psycopg
            try: return test_database(store)
            except (sqlite3.Error, psycopg.Error, OSError): raise HTTPException(503, '数据库读写测试失败，请检查连接配置、权限或数据库状态')

        @app.get('/api/system/database', dependencies=[Depends(authenticate)])
        def database_config(): return configuration_status(store)

        @app.post('/api/system/database/probe', dependencies=[Depends(authenticate)])
        def probe_database_config(value: DatabaseConfig):
            import sqlite3, psycopg
            try: return probe_config(value)
            except ValueError as exc: raise HTTPException(422,str(exc))
            except (OSError,sqlite3.Error,psycopg.Error): raise HTTPException(422,'数据库连接或读写测试失败，请检查地址、账号、密码与权限')

        @app.post('/api/system/database/password', dependencies=[Depends(authenticate)])
        def reveal_database_password(value: DatabaseConfig):
            from .database_config import resolved
            try: selected = resolved(value)
            except ValueError as exc: raise HTTPException(422,str(exc))
            if selected.engine != 'postgresql': raise HTTPException(422,'SQLite 无需数据库密码')
            store.event(secrets.token_hex(8),'admin','POST','/api/system/database/password','admin','DATABASE_PASSWORD_VIEW',200)
            return {'password':selected.password.get_secret_value()}

        @app.post('/api/system/database/initialize', dependencies=[Depends(authenticate)])
        def initialize_selected_database(value: DatabaseConfig):
            import sqlite3, psycopg
            from .database_config import initialize_database
            try: result = initialize_database(value)
            except ValueError as exc: raise HTTPException(422,str(exc))
            except (OSError,sqlite3.Error,psycopg.Error):
                raise HTTPException(422,'数据初始化失败：请检查数据库是否已创建、连接参数，以及账号的建表和读写权限')
            store.event(secrets.token_hex(8),'admin','POST','/api/system/database/initialize','admin','DATABASE_INITIALIZE',200)
            return result

        @app.put('/api/system/database', dependencies=[Depends(authenticate)])
        def save_database_config(value: DatabaseConfig):
            import sqlite3, psycopg
            try: result = stage_database(value)
            except ValueError as exc: raise HTTPException(422,str(exc))
            except (OSError,sqlite3.Error,psycopg.Error): raise HTTPException(422,'配置未保存：数据库连接或读写测试失败')
            store.event(secrets.token_hex(8),'admin','PUT','/api/system/database','admin','DATABASE_CONFIG',200)
            return {'selected':result,'pending':True,'detail':'数据库配置已保存为待生效；须停服迁移后启用，当前数据库继续运行'}

        @app.delete('/api/system/database/pending', dependencies=[Depends(authenticate)])
        def discard_database_config():
            from .database_config import pending_path
            pending_path().unlink(missing_ok=True)
            return {'ok':True}

        @app.get('/api/system', dependencies=[Depends(authenticate)])
        def system_config():
            return store.network()

        @app.get('/api/system/adapters', dependencies=[Depends(authenticate)])
        def system_adapters():
            try: return adapters()
            except (RuntimeError, OSError, ValueError) as exc: raise HTTPException(503, str(exc))

        @app.get('/api/system/status', dependencies=[Depends(authenticate)])
        def system_status():
            try:
                import time
                from .dataplane import fingerprint
                value = store.network()
                inventory = adapters()
                status = network_status(value, inventory)
                status['adapters'] = inventory
                state = store.agent_state()
                status['agent'] = state
                status['data_plane_running'] = (state.get('fingerprint') == fingerprint(value) and
                    state.get('state') == 'running' and 0 <= time.time()-state.get('heartbeat',0) < 15)
                status['management_listener_ip'] = os.getenv('WAF_MANAGEMENT_LISTEN_IP', '')
                status['initialization'] = store.bootstrap_state()
                status['agent_expected'] = value.deployment_mode in ('bypass','inline')
                status['container'] = os.getenv('WAF_ENV_FILE') == '/app/runtime/admin.env'
                status['data_plane_autostart'] = os.getenv('WAF_DATAPLANE_AUTOSTART') == '1'
                return status
            except (RuntimeError, OSError, ValueError) as exc: raise HTTPException(503, str(exc))

        @app.put('/api/system', dependencies=[Depends(authenticate)])
        def save_system(value: NetworkConfig):
            try: validate_bindings(value, adapters(), store.network())
            except ValueError as exc: raise HTTPException(422, str(exc))
            except (RuntimeError, OSError) as exc: raise HTTPException(503, str(exc))
            store.save_network(value)
            store.event(secrets.token_hex(8), 'admin', 'PUT', '/api/system', 'admin', 'NETWORK_CONFIG', 200)
            return value

        @app.post('/api/system/apply-management', dependencies=[Depends(authenticate)])
        def apply_management_ip():
            if os.getenv('WAF_DEV_MODE') == '1': raise HTTPException(403, '本地开发模式不允许修改主机网卡 IP')
            try: result = apply_management(store.network(), adapters())
            except PermissionError as exc: raise HTTPException(403, str(exc))
            except ValueError as exc: raise HTTPException(422, str(exc))
            except (RuntimeError, OSError) as exc: raise HTTPException(503, str(exc))
            store.event(secrets.token_hex(8), 'admin', 'POST', '/api/system/apply-management', 'admin', 'MANAGEMENT_IP', 200)
            return {**result, 'detail':'管理 IP 已添加；重启 WAF 服务后开放该地址的管理监听。本机 127.0.0.1 入口保留。'}
        return app

    @app.api_route('/{path:path}', methods=['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS','TRACE','CONNECT'])
    async def proxy(request: Request, path: str):
        request_id = secrets.token_hex(12)
        ip = request.client.host if request.client else 'unknown'
        settings = await asyncio.to_thread(store.settings)
        async def audit(action, rule, status):
            listener=request.scope.get('server') or ('',0)
            await asyncio.to_thread(store.event, request_id, ip, request.method, request.url.path, action, rule, status,request_hostname(request.headers),
                                    dict(src_ip=ip,src_port=request.client.port if request.client else 0,
                                         dst_ip=listener[0],dst_port=listener[1],protocol='TCP'))
        async def reject(status, rule, message):
            await audit('blocked', rule, status)
            return JSONResponse({'detail':message, 'request_id':request_id}, status_code=status,
                                headers={'X-WAF-Request-ID':request_id})
        if request.method in ('TRACE','CONNECT'): return await reject(405, 'METHOD', '不支持的请求方法')
        if settings['protected_domains']:
            host = request_hostname(request.headers)
            if not host or not any(domain_matches(host, pattern) for pattern in settings['protected_domains']):
                return await reject(403, 'DOMAIN', '该域名未纳入 WAF 防护范围')
        if not limiter.allow(ip, settings['rate_limit']): return await reject(429, 'RATE', '请求频率超过限制')
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > settings['max_body_bytes']: return await reject(413, 'BODY', '请求体超过限制')
        custom=evaluate_custom(settings.get('custom_rules',[]),ip,request_hostname(request.headers),request.method,request.url.path,request.url.query)
        if custom and custom['action']=='block': return await reject(403,custom['id'],'请求被自定义防护规则拦截')
        rule = custom['id'] if custom and custom['action']=='monitor' else ''
        allowed_custom=custom and custom['action']=='allow'
        if settings['enabled'] and not allowed_custom:
            parts = [request.url.path, request.url.query, body.decode('utf-8', 'replace')]
            parts.extend(value for key, value in request.headers.items() if key.lower() not in ('authorization','cookie'))
            signature = inspect(parts, settings['disabled_rules'])
            if signature and settings['mode']=='block': return await reject(403, signature, '请求被 WAF 安全规则拦截')
            if signature: rule=signature
        raw_host = request.headers.get('host', '')
        request_port = int(raw_host.rsplit(':', 1)[1]) if ':' in raw_host and raw_host.rsplit(':', 1)[1].isdigit() else (443 if request.url.scheme == 'https' else 80)
        origins = origin_router.select(settings, request_hostname(request.headers), request_port, request.url.path)
        if not origins:
            await audit('error', 'UPSTREAM', 503)
            return JSONResponse({'detail':'尚未配置受保护站点的上游地址','request_id':request_id}, status_code=503)
        # Fixed configured origin, preserving the escaped path. Never proxy to client-provided hosts.
        raw_path = request.scope.get('raw_path', b'/').decode('ascii')
        suffix = raw_path + ('?' + request.url.query if request.url.query else '')
        connection_tokens = set(request.headers.get('connection','').lower().replace(' ','').split(','))
        headers = [(k,v) for k,v in request.headers.items() if k.lower() not in HOP|connection_tokens|{'host','forwarded'}
                   and not k.lower().startswith('x-forwarded-')]
        from .sessions import business_cookie
        headers = [(key, business_cookie(value) if key.lower()=='cookie' else value) for key,value in headers]
        headers = [(key,value) for key,value in headers if value]
        headers.extend([('X-Forwarded-For',ip),('X-Forwarded-Proto',request.url.scheme),('X-WAF-Request-ID',request_id)])
        if settings['protected_domains']:
            headers.extend([('Host',request.headers['host']),('X-Forwarded-Host',request.headers['host'])])
        attempts = origins if request.method in ('GET', 'HEAD', 'OPTIONS') else origins[:1]
        for address in attempts:
            try:
                async with app.state.client.stream(request.method, address + suffix, headers=headers, content=bytes(body)) as upstream:
                    payload = bytearray()
                    async for chunk in upstream.aiter_raw():
                        payload.extend(chunk)
                        if len(payload) > 20*1024*1024: raise ValueError('Response too large')
                    status = upstream.status_code
                    response = Response(bytes(payload), status_code=status)
                    tokens=set(upstream.headers.get('connection','').lower().replace(' ','').split(','))
                    response.raw_headers = [(k,v) for k,v in upstream.headers.raw if k.decode().lower() not in HOP|tokens]
                    response.headers['X-WAF-Request-ID']=request_id
                    await audit('detected' if rule else 'allowed', rule or (custom['id'] if allowed_custom else ''), status)
                    return response
            except (httpx.ConnectError, httpx.ConnectTimeout):
                continue
            except (httpx.HTTPError, ValueError):
                break
        await audit('error', 'UPSTREAM', 502)
        return JSONResponse({'detail':'上游连接失败、超时或响应超过 20 MiB','request_id':request_id},status_code=502)
    return app


def create_proxy(): return create_app('proxy')
def create_admin(): return create_app('admin')
