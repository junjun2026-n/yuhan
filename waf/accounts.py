# ============================================================
# 文件名称：accounts.py
# 生成日期：2026-10-28
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：管理用户账号及账号操作。
#           文件用途：供WAF的 yuhan/waf/accounts.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Database backed accounts and server-side permission enforcement."""
import hashlib
import hmac
import json
import os
import re
import secrets
from contextvars import ContextVar
from pydantic import BaseModel, Field, SecretStr, field_validator

PERMISSIONS = {'overview':'安全总览','sites':'站点与证书','rules':'防护规则','audit':'访问审计',
               'system':'系统配置（含数据库、日志和网卡）','users':'用户管理'}
ROLES = {'administrator':list(PERMISSIONS), 'operator':['overview','sites','rules'], 'auditor':['overview','audit'], 'custom':[]}
ROLE_NAMES = {'administrator':'管理员','operator':'运维人员','auditor':'审计人员','custom':'自定义权限'}
actor = ContextVar('waf_actor', default='')


def password_hash(password):
    salt=secrets.token_hex(16)
    return 'pbkdf2_sha256$600000$'+salt+'$'+hashlib.pbkdf2_hmac('sha256',password.encode(),salt.encode(),600000).hex()


def verify(password, encoded):
    try:
        _, rounds, salt, digest=encoded.split('$')
        return hmac.compare_digest(hashlib.pbkdf2_hmac('sha256',password.encode(),salt.encode(),int(rounds)).hex(),digest)
    except (ValueError,AttributeError): return False


class UserInput(BaseModel):
    username: str = Field(min_length=1,max_length=64)
    role: str = 'operator'
    permissions: list[str] = Field(default_factory=list)
    enabled: bool = True
    password: SecretStr = SecretStr('')

    @field_validator('username')
    @classmethod
    def valid_username(cls,value):
        if not re.fullmatch(r'[A-Za-z0-9_.@-]{1,64}',value): raise ValueError('用户名仅支持字母、数字及 _.@-')
        return value

    @field_validator('role')
    @classmethod
    def valid_role(cls,value):
        if value not in ROLES: raise ValueError('未知角色')
        return value

    @field_validator('permissions')
    @classmethod
    def valid_permissions(cls,value):
        if set(value)-PERMISSIONS.keys(): raise ValueError('未知权限')
        return sorted(set(value))


class PasswordInput(BaseModel):
    current_password: SecretStr
    new_password: SecretStr


def validate_password(value):
    if not 10 <= len(value) <= 128: raise ValueError('密码长度须为 10～128 个字符')


def public(user):
    return {key:value for key,value in user.items() if key!='password_hash'}


def permissions(user):
    return ROLES[user['role']] if user['role']!='custom' else user['permissions']


def read(store):
    with store.connect() as db:
        row=db.execute('SELECT value FROM accounts WHERE id=1').fetchone()
    return json.loads(row[0]) if row else []


def mutate(store, operation):
    with store.connect() as db:
        if store.engine=='sqlite': db.execute('BEGIN IMMEDIATE')
        else: db.execute('SELECT pg_advisory_xact_lock(830020)')
        row=db.execute('SELECT value FROM accounts WHERE id=1').fetchone()
        users=json.loads(row[0]) if row else []
        result=operation(users)
        db.execute('INSERT INTO accounts VALUES(1,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value',(json.dumps(users),))
        return result


def bootstrap(store):
    if read(store): return
    password=os.getenv('WAF_ADMIN_PASSWORD','')
    if not password or password=='CHANGE_ME': return
    digest=password_hash(password)
    def seed(users):
        if not users: users.append({'username':os.getenv('WAF_ADMIN_USER','admin'),'role':'administrator','permissions':[], 'enabled':True,'password_hash':digest})
    mutate(store,seed)


def change(store, username, value=None, delete=False, create=False, actor=''):
    digest=None
    if value and value.password.get_secret_value():
        validate_password(value.password.get_secret_value());digest=password_hash(value.password.get_secret_value())
    def update(users):
        existing=next((item for item in users if item['username']==username),None)
        if create and existing: raise ValueError('用户名已存在')
        if not create and not existing: raise ValueError('用户不存在')
        if delete:
            if username==actor: raise ValueError('不能删除当前登录用户')
            users.remove(existing)
        else:
            if value.username!=username: raise ValueError('用户名不能修改')
            if create and not digest: raise ValueError('新增用户须设置密码')
            item={'username':username,'role':value.role,'permissions':value.permissions if value.role=='custom' else [],'enabled':value.enabled,'password_hash':digest or existing['password_hash']}
            if existing: users[users.index(existing)]=item
            else: users.append(item)
        if not any(item['enabled'] and item['role']=='administrator' for item in users): raise ValueError('至少保留一名启用的管理员')
    mutate(store,update)


def required(path, method):
    if path in ('/','/app.js','/app.css','/traffic-map.js','/api/login','/api/logout','/api/me','/api/me/password','/api/documentation/user-guide'): return None
    if path.startswith('/api/users') or path=='/api/permissions': return 'users'
    if path in ('/api/stats','/api/stats/overview','/api/stats/traffic-map','/world-map.json'): return 'overview'
    if path.startswith('/api/events'): return 'audit'
    if path.startswith('/api/system'): return 'system'
    if path.startswith(('/api/custom-rules','/api/traffic-protection')) or path=='/api/rules': return 'rules'
    if path.startswith('/api/tls'): return 'sites'
    if path=='/api/settings': return ('sites','rules')
    return 'users'


def install(app, store, authenticate):
    from fastapi import Depends, HTTPException, Request
    def audit(request, actor, code):
        store.event(secrets.token_hex(8),actor,request.method,request.url.path,'admin',code,200)
    @app.get('/api/me')
    def me(user=Depends(authenticate)):
        value=store.settings()
        return {**public(user),'permissions':permissions(user),'platform_name':store.platform_config().platform_name,
                'protection':{'mode':value['mode'],'enabled':value['enabled'],'upstream_configured':bool(value['upstream'] or value.get('domain_upstreams') or value.get('origin_rules'))}}
    @app.get('/api/permissions')
    def catalog(user=Depends(authenticate)):
        return {'permissions':PERMISSIONS,'roles':ROLE_NAMES,'role_permissions':ROLES}
    @app.get('/api/users')
    def users(user=Depends(authenticate)): return [public(item) for item in read(store)]
    @app.post('/api/users')
    def create(value:UserInput,request:Request,user=Depends(authenticate)):
        try: change(store,value.username,value,create=True,actor=user['username'])
        except ValueError as exc: raise HTTPException(422,str(exc))
        audit(request,user['username'],'USER_CREATE');return {'ok':True}
    @app.put('/api/users/{username}')
    def update(username:str,value:UserInput,request:Request,user=Depends(authenticate)):
        try: change(store,username,value,actor=user['username'])
        except ValueError as exc: raise HTTPException(422,str(exc))
        audit(request,user['username'],'USER_UPDATE');return {'ok':True}
    @app.delete('/api/users/{username}')
    def delete(username:str,request:Request,user=Depends(authenticate)):
        try: change(store,username,delete=True,actor=user['username'])
        except ValueError as exc: raise HTTPException(422,str(exc))
        audit(request,user['username'],'USER_DELETE');return {'ok':True}
    @app.post('/api/me/password')
    def password(value:PasswordInput,request:Request,user=Depends(authenticate)):
        try: validate_password(value.new_password.get_secret_value())
        except ValueError as exc: raise HTTPException(422,str(exc))
        digest=password_hash(value.new_password.get_secret_value())
        def update(users):
            current=next(item for item in users if item['username']==user['username'])
            if not verify(value.current_password.get_secret_value(),current['password_hash']): raise ValueError('当前密码错误')
            current['password_hash']=digest
        try: mutate(store,update)
        except ValueError as exc: raise HTTPException(422,str(exc))
        audit(request,user['username'],'PASSWORD_CHANGE');return {'ok':True}
