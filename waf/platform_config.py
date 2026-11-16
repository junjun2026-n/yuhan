"""Appliance identity and live SQLite tuning (independent of NIC configuration)."""
import socket
import time
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator


class PlatformConfig(BaseModel):
    model_config = ConfigDict(extra='forbid')
    platform_name: str = Field(default='WAF', min_length=1, max_length=60)
    hostname: str = Field(default='waf', pattern=r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
    database_timeout: int = Field(default=10, ge=1, le=120)
    wal_autocheckpoint: int = Field(default=1000, ge=100, le=100000)

    @field_validator('platform_name')
    @classmethod
    def clean_name(cls, value):
        value = value.strip()
        if not value or any(ord(c) < 32 for c in value):
            raise ValueError('平台名称不能为空或包含控制字符')
        return value


def status(store):
    config = store.platform_config()
    if store.engine == 'postgresql':
        from psycopg.conninfo import conninfo_to_dict
        info = conninfo_to_dict(store.path)
        with store.connect() as db:
            size = db.execute('SELECT pg_database_size(current_database())').fetchone()[0]
        database = {'engine': 'PostgreSQL', 'path': f"{info.get('host')}:{info.get('port', '5432')}/{info.get('dbname')}",
                    'size_bytes': size, 'external_supported': True}
    else:
        database = {'engine': 'SQLite', 'path': str(Path(store.path).resolve()),
                    'size_bytes': Path(store.path).stat().st_size, 'external_supported': True}
    return {'config': config.model_dump(), 'active_hostname': socket.gethostname(),
            'hostname_pending': config.hostname != socket.gethostname(),
            'database': database}


def test_database(store):
    start = time.perf_counter()
    with store.connect() as db:
        if store.engine == 'postgresql':
            try:
                db.execute('CREATE TEMP TABLE waf_connection_probe (id INTEGER) ON COMMIT DROP')
                db.execute('INSERT INTO waf_connection_probe VALUES (1)')
                assert db.execute('SELECT id FROM waf_connection_probe').fetchone()[0] == 1
                timeout = db.execute('SHOW statement_timeout').fetchone()[0]
            finally:
                db.rollback()
            return {'ok': True, 'detail': 'PostgreSQL 数据库读写测试通过，测试数据已回滚',
                    'engine': 'PostgreSQL', 'statement_timeout': timeout,
                    'elapsed_ms': round((time.perf_counter()-start)*1000, 2)}
        # Exercise writes in a rollback-only transaction without changing application data.
        db.execute('BEGIN IMMEDIATE')
        try:
            db.execute('CREATE TABLE IF NOT EXISTS connection_probe (id INTEGER)')
            db.execute('INSERT INTO connection_probe VALUES (1)')
            assert db.execute('SELECT id FROM connection_probe LIMIT 1').fetchone()[0] == 1
            journal = db.execute('PRAGMA journal_mode').fetchone()[0]
            timeout = db.execute('PRAGMA busy_timeout').fetchone()[0]
            checkpoint = db.execute('PRAGMA wal_autocheckpoint').fetchone()[0]
        finally:
            db.rollback()
    return {'ok': True, 'detail': '数据库读写测试通过，测试数据已回滚', 'journal_mode': journal,
            'busy_timeout_ms': timeout, 'wal_autocheckpoint': checkpoint,
            'elapsed_ms': round((time.perf_counter()-start)*1000, 2)}
