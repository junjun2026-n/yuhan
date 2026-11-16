"""Validate and stage database changes; activation requires offline migration."""
import os
from pathlib import Path
import sqlite3
import time
from typing import Literal

from dotenv import dotenv_values
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from .database import ROOT, config_path, database_target


class DatabaseConfig(BaseModel):
    model_config = ConfigDict(extra='forbid')
    engine: Literal['sqlite','postgresql'] = 'sqlite'
    sqlite_path: str = Field(default='runtime/waf.sqlite3', min_length=1, max_length=500)
    host: str = Field(default='', max_length=253, pattern=r'^[a-zA-Z0-9.:-]*$')
    port: int = Field(default=5432, ge=1, le=65535)
    name: str = Field(default='', max_length=100, pattern=r'^[a-zA-Z0-9_-]*$')
    user: str = Field(default='', max_length=100, pattern=r'^[a-zA-Z0-9_-]*$')
    password: SecretStr = SecretStr('')
    sslmode: Literal['disable','prefer','require','verify-full'] = 'prefer'


def pending_path():
    return config_path().with_name('database.pending.env')


def profile_path(engine):
    return config_path().with_name(f'database.{engine}.env')


def read_config(path=None):
    values = {**os.environ, **dotenv_values(path or config_path())}
    return DatabaseConfig(engine=values.get('WAF_DB_ENGINE','sqlite'),
        sqlite_path=values.get('WAF_DATABASE','runtime/waf.sqlite3'),
        host=values.get('WAF_DB_HOST',''), port=int(values.get('WAF_DB_PORT','5432')),
        name=values.get('WAF_DB_NAME',''), user=values.get('WAF_DB_USER',''),
        password=values.get('WAF_DB_PASSWORD',''), sslmode=values.get('WAF_DB_SSLMODE','prefer'))


def public_config(value):
    result = value.model_dump(exclude={'password'})
    result['password_set'] = bool(value.password.get_secret_value())
    return result


def resolved(value):
    if value.engine == 'postgresql':
        if os.getenv('WAF_DEV_MODE') == '1':
            from psycopg.conninfo import conninfo_to_dict
            target = database_target()
            if not isinstance(target, str):
                raise ValueError('开发模式不能从 SQLite 切换至外部数据库')
            identity = conninfo_to_dict(target)
            if (value.host,str(value.port),value.name,value.user) != (identity['host'],identity['port'],identity['dbname'],identity['user']):
                raise ValueError('开发模式仅允许当前独立开发数据库，不能切换生产数据库')
        if not value.host or not value.name or not value.user: raise ValueError('请填写 PostgreSQL 主机、数据库名和用户名')
        if not value.password.get_secret_value():
            candidates = [read_config()]
            if profile_path('postgresql').exists(): candidates.insert(0,read_config(profile_path('postgresql')))
            if pending_path().exists(): candidates.insert(0,read_config(pending_path()))
            for old in candidates:
                if (old.host,old.port,old.name,old.user) == (value.host,value.port,value.name,value.user) and old.password.get_secret_value():
                    value = value.model_copy(update={'password':old.password})
                    break
        if not value.password.get_secret_value(): raise ValueError('请填写 PostgreSQL 密码')
    else:
        path = (ROOT/value.sqlite_path).resolve()
        allowed = (ROOT/('runtime/dev' if os.getenv('WAF_DEV_MODE') == '1' else 'runtime')).resolve()
        if not path.is_relative_to(allowed) or path.suffix != '.sqlite3':
            raise ValueError('SQLite 文件必须位于本系统 runtime 目录内，扩展名为 .sqlite3')
        value = value.model_copy(update={'sqlite_path':str(path)})
    return value


def values_for(value):
    return {'WAF_DB_ENGINE':value.engine,'WAF_DATABASE':value.sqlite_path,
        'WAF_DB_HOST':value.host,'WAF_DB_PORT':str(value.port),'WAF_DB_NAME':value.name,
        'WAF_DB_USER':value.user,'WAF_DB_PASSWORD':value.password.get_secret_value(), 'WAF_DB_SSLMODE':value.sslmode}


def probe(value):
    value = resolved(value)
    start = time.perf_counter()
    if value.engine == 'postgresql':
        import psycopg
        with psycopg.connect(database_target(values_for(value))) as db:
            db.execute("SELECT set_config('statement_timeout','10000',true)")
            db.execute('CREATE TEMP TABLE waf_config_probe (id INTEGER) ON COMMIT DROP')
            db.execute('INSERT INTO waf_config_probe VALUES (1)')
            assert db.execute('SELECT id FROM waf_config_probe').fetchone()[0] == 1
            db.rollback()
    else:
        path = Path(value.sqlite_path)
        path.parent.mkdir(parents=True,exist_ok=True)
        db = sqlite3.connect(path,timeout=10)
        try:
            db.execute('BEGIN')
            db.execute('CREATE TEMP TABLE waf_config_probe (id INTEGER)')
            db.execute('INSERT INTO waf_config_probe VALUES (1)')
            assert db.execute('SELECT id FROM waf_config_probe').fetchone()[0] == 1
            db.rollback()
        finally: db.close()
    return {'ok':True,'detail':'所选数据库连接及读写测试通过','elapsed_ms':round((time.perf_counter()-start)*1000,2)}


def stage(value):
    value = resolved(value)
    probe(value)
    write_config(profile_path(value.engine),value)
    write_config(pending_path(),value)
    return public_config(value)


def write_config(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    # dotenv single-quote escaping; never use a shell to write secrets.
    content = ''.join(key+"='"+str(item).replace('\\','\\\\').replace("'","\\'")+"'\n" for key,item in values_for(value).items())
    temporary = path.with_suffix('.tmp')
    with temporary.open('w',encoding='utf-8') as stream:
        if os.name != 'nt': os.chmod(temporary,0o600)
        stream.write(content)
    temporary.replace(path)


def initialize_database(value):
    """Idempotently install WAF schema in the selected, already-created database."""
    from .store import Store
    from .platform_config import test_database
    from .migrate import TABLES
    value = resolved(value)
    target = Store(database_target(values_for(value)))
    test_database(target)
    with target.connect() as db:
        tables = {table: db.execute(f'SELECT count(*) FROM {table}').fetchone()[0] for table in TABLES}
    return {'ok':True,'engine':target.engine,'tables':tables,
            'detail':'数据初始化完成：WAF 表结构及默认防护配置已就绪，已有配置和审计记录已保留。初始化不会切换当前数据库。'}


def configuration_status(store):
    pending = pending_path().exists()
    if store.engine == 'postgresql':
        from psycopg.conninfo import conninfo_to_dict
        info = conninfo_to_dict(store.path)
        active = DatabaseConfig(engine='postgresql',host=info.get('host',''),
            port=int(info.get('port','5432')),name=info.get('dbname',''),
            user=info.get('user',''),password=info.get('password',''),
            sslmode=info.get('sslmode','prefer'))
    else:
        active = DatabaseConfig(engine='sqlite',sqlite_path=store.path)
    selected = read_config(pending_path()) if pending else active
    profiles = {}
    for engine in ('sqlite','postgresql'):
        path = profile_path(engine)
        if path.exists(): profiles[engine] = public_config(read_config(path))
    configured = read_config()
    if configured.engine == 'postgresql' and configured.host and configured.name and configured.user:
        profiles['postgresql'] = public_config(configured)
    profiles[active.engine] = public_config(active)
    profiles[selected.engine] = public_config(selected)
    return {'active_engine':store.engine,'active':public_config(active),
            'selected':public_config(selected),'profiles':profiles,
            'environment':'development' if os.getenv('WAF_DEV_MODE') == '1' else 'service',
            'pending':pending}
