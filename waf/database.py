# ============================================================
# 文件名称：database.py
# 生成日期：2026-10-27
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：管理数据库连接及数据访问。
#           文件用途：供WAF的 yuhan/waf/database.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Resolve the active storage backend without exposing connection passwords."""
import os
from pathlib import Path

from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[1]


def config_path():
    return Path(os.getenv('WAF_DATABASE_CONFIG', str(ROOT/'runtime/database.env')))


def database_target(values=None):
    values = {**os.environ, **dotenv_values(config_path())} if values is None else values
    engine = values.get('WAF_DB_ENGINE', 'sqlite')
    if engine in ('postgresql','mysql'):
        if engine == 'mysql':
            from urllib.parse import quote
            return f"mysql+pymysql://{quote(values.get('WAF_DB_USER',''))}:{quote(values.get('WAF_DB_PASSWORD',''))}@{values.get('WAF_DB_HOST','')}:{values.get('WAF_DB_PORT','3306')}/{values.get('WAF_DB_NAME','')}"
        from psycopg.conninfo import make_conninfo
        return make_conninfo(host=values.get('WAF_DB_HOST', ''),
            port=values.get('WAF_DB_PORT', '5432'), dbname=values.get('WAF_DB_NAME', ''),
            user=values.get('WAF_DB_USER', ''), password=values.get('WAF_DB_PASSWORD', ''),
            sslmode=values.get('WAF_DB_SSLMODE', 'prefer'), connect_timeout=10,
            application_name='qionghai-waf')
    if engine != 'sqlite':
        raise ValueError('Unsupported database engine')
    return ROOT / values.get('WAF_DATABASE', 'runtime/waf.sqlite3')


class Record(dict):
    def __getitem__(self, key):
        return list(self.values())[key] if isinstance(key, int) else super().__getitem__(key)


def record_factory(cursor):
    names = [column.name for column in (cursor.description or [])]
    return lambda values: Record(zip(names, values))


class PostgresConnection:
    """Small adapter for Store's parameterized SQL; never accepts user SQL."""
    def __init__(self, connection):
        self.raw = connection

    def execute(self, query, params=None):
        if query == 'BEGIN IMMEDIATE':
            # Serialize optimistic network bootstrap imports across processes.
            return self.raw.execute('SELECT pg_advisory_xact_lock(830017)')
        query = query.replace('?', '%s')
        if query.startswith('INSERT OR IGNORE INTO '):
            query = query.replace('INSERT OR IGNORE INTO ', 'INSERT INTO ', 1) + ' ON CONFLICT DO NOTHING'
        return self.raw.execute(query, params)

    def rollback(self):
        self.raw.rollback()

class MySQLConnection:
    def __init__(self, url):
        import pymysql
        from urllib.parse import urlsplit, unquote
        p=urlsplit(url); self.raw=pymysql.connect(host=p.hostname, port=p.port or 3306, user=unquote(p.username or ''), password=unquote(p.password or ''), database=(p.path or '/')[1:], autocommit=False, cursorclass=pymysql.cursors.DictCursor)
    def execute(self, query, params=None):
        query=query.replace('BEGIN IMMEDIATE','START TRANSACTION').replace('INSERT OR IGNORE INTO','INSERT IGNORE INTO').replace('?', '%s')
        if ' ON CONFLICT' in query: query=query.split(' ON CONFLICT',1)[0]
        cur=self.raw.cursor(); cur.execute(query, params or ()); return cur
    def rollback(self): self.raw.rollback()
