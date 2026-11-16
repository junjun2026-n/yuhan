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
    if engine == 'postgresql':
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
