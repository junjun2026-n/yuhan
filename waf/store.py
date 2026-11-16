import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

DEFAULTS = {'upstream': '', 'domain_upstreams': {}, 'origin_rules': [], 'mode': 'block', 'enabled': True, 'rate_limit': 120,
            'max_body_bytes': 1048576, 'disabled_rules': [], 'protected_domains': [],
            'tls_enabled': False, 'tls_port': 8443, 'tls_certificate': '', 'domain_certificates': {}, 'custom_rules': []}


class Store:
    def __init__(self, path=None):
        if path is None:
            from .database import database_target
            path = database_target()
        self.path = str(path)
        self.engine = 'postgresql' if self.path.startswith(('postgresql://', 'postgres://')) or ('dbname=' in self.path and 'host=' in self.path) else 'sqlite'
        self.initialized = False
        if self.engine == 'sqlite': Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            if self.engine == 'sqlite': db.execute('PRAGMA journal_mode=WAL')
            else: db.execute('SELECT pg_advisory_xact_lock(830016)')
            schema = '''
                CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS system_settings (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS agent_state (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS bootstrap_state (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS platform_settings (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS log_forwarding (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL, state TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS accounts (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS web_sessions (token TEXT PRIMARY KEY, username TEXT NOT NULL, password_stamp TEXT NOT NULL, expires INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS traffic_protection (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, request_id TEXT NOT NULL,
                    ip TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL,
                    action TEXT NOT NULL, rule_id TEXT NOT NULL, status INTEGER NOT NULL);
                CREATE INDEX IF NOT EXISTS ix_events_created ON events(created_at);
            '''
            if self.engine == 'postgresql':
                schema = schema.replace('id INTEGER PRIMARY KEY, created_at', 'id BIGSERIAL PRIMARY KEY, created_at')
                for statement in schema.split(';'):
                    if statement.strip(): db.execute(statement)
            else: db.executescript(schema)
            if self.engine=='sqlite':db.execute('BEGIN IMMEDIATE')
            columns={row[1] for row in db.execute('PRAGMA table_info(events)')} if self.engine=='sqlite' else {row[0] for row in db.execute("SELECT column_name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='events'")}
            for name in ('domain','country','source_scope','threat_type','connection_detail'):
                if name not in columns:db.execute(f"ALTER TABLE events ADD COLUMN {name} TEXT NOT NULL DEFAULT ''")
            for name in ('action','domain','ip','country','threat_type','source_scope'):
                db.execute(f'CREATE INDEX IF NOT EXISTS ix_events_{name}_time ON events({name},created_at)')
            from .geoip import source
            legacy=db.execute("SELECT DISTINCT ip FROM events WHERE source_scope='' AND action!='admin'").fetchall()
            for row in legacy:
                info=source(row[0])
                db.execute("UPDATE events SET country=?,source_scope=? WHERE ip=? AND source_scope='' AND action!='admin'",(info['country'],info['scope'],row[0]))
            db.execute('INSERT OR IGNORE INTO settings VALUES (1,?)', (json.dumps(DEFAULTS),))
            # Classify old hits once. New hits retain their event-time classification
            # even when the matching custom rule is later edited or removed.
            from .threats import classify
            custom=json.loads(db.execute('SELECT value FROM settings WHERE id=1').fetchone()[0]).get('custom_rules',[])
            legacy=db.execute("SELECT DISTINCT rule_id,action FROM events WHERE threat_type='' AND action IN ('blocked','detected')").fetchall()
            for row in legacy:
                rule_id,action=row[0],row[1]
                db.execute("UPDATE events SET threat_type=? WHERE rule_id=? AND action=? AND threat_type=''",(classify(rule_id,action,custom),rule_id,action))
        self.initialized = True

    @contextmanager
    def connect(self):
        if self.engine == 'postgresql':
            import psycopg
            from .database import PostgresConnection, record_factory
            with psycopg.connect(self.path, row_factory=record_factory) as connection:
                db = PostgresConnection(connection)
                if self.initialized:
                    row = db.execute('SELECT value FROM platform_settings WHERE id=1').fetchone()
                    if row:
                        timeout = json.loads(row[0]).get('database_timeout', 10)
                        db.execute("SELECT set_config('statement_timeout', ?, true)", (str(int(timeout)*1000),))
                yield db
            return
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            try:
                row = db.execute('SELECT value FROM platform_settings WHERE id=1').fetchone()
            except sqlite3.OperationalError as exc:
                if 'no such table' not in str(exc): raise
                row = None
            if row:
                from .platform_config import PlatformConfig
                config = PlatformConfig.model_validate_json(row[0])
                db.execute(f'PRAGMA busy_timeout={config.database_timeout * 1000}')
                db.execute(f'PRAGMA wal_autocheckpoint={config.wal_autocheckpoint}')
            with db:
                yield db
        finally:
            db.close()

    def platform_config(self):
        from .platform_config import PlatformConfig
        with self.connect() as db:
            row = db.execute('SELECT value FROM platform_settings WHERE id=1').fetchone()
        return PlatformConfig.model_validate_json(row[0]) if row else PlatformConfig()

    def save_platform_config(self, value):
        with self.connect() as db:
            db.execute('INSERT INTO platform_settings VALUES(1,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value',
                       (value.model_dump_json(),))

    def settings(self):
        with self.connect() as db:
            return {**DEFAULTS, **json.loads(db.execute('SELECT value FROM settings WHERE id=1').fetchone()[0])}

    def network(self):
        from .network import NetworkConfig
        with self.connect() as db:
            row = db.execute('SELECT value FROM system_settings WHERE id=1').fetchone()
        return NetworkConfig.model_validate_json(row[0]) if row else NetworkConfig()

    def save_network(self, value):
        with self.connect() as db:
            db.execute('INSERT INTO system_settings VALUES(1,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value',
                       (value.model_dump_json(),))

    def bootstrap_state(self):
        with self.connect() as db:
            row = db.execute('SELECT value FROM bootstrap_state WHERE id=1').fetchone()
        return json.loads(row[0]) if row else {}

    def save_bootstrap_state(self, value):
        with self.connect() as db:
            db.execute('INSERT INTO bootstrap_state VALUES(1,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value',
                       (json.dumps(value),))

    def import_bootstrap_network(self, value, expected, state):
        from .network import NetworkConfig
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT value FROM system_settings WHERE id=1').fetchone()
            current = NetworkConfig.model_validate_json(row[0]) if row else NetworkConfig()
            if current != expected: raise ValueError('系统网卡配置已被其他操作修改，取消初始化导入')
            db.execute('INSERT INTO system_settings VALUES(1,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value',
                       (value.model_dump_json(),))
            db.execute('INSERT INTO bootstrap_state VALUES(1,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value',
                       (json.dumps(state),))

    def agent_state(self, value=None):
        with self.connect() as db:
            if value is not None:
                db.execute('INSERT INTO agent_state VALUES(1,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value', (json.dumps(value),))
            row = db.execute('SELECT value FROM agent_state WHERE id=1').fetchone()
        return json.loads(row[0]) if row else {}

    def save(self, value, preserve_custom=False, allowed_keys=None):
        with self.connect() as db:
            if self.engine=='sqlite': db.execute('BEGIN IMMEDIATE')
            else: db.execute('SELECT pg_advisory_xact_lock(830019)')
            if preserve_custom or allowed_keys is not None:
                current=json.loads(db.execute('SELECT value FROM settings WHERE id=1').fetchone()[0])
                if allowed_keys is not None: value={**current,**{key:item for key,item in value.items() if key in allowed_keys}}
            if preserve_custom:
                value={**value,'custom_rules':current.get('custom_rules',[])}
            db.execute('UPDATE settings SET value=? WHERE id=1', (json.dumps(value),))

    def change_custom_rule(self, identifier, value=None, delete=False, create=False):
        with self.connect() as db:
            if self.engine=='sqlite': db.execute('BEGIN IMMEDIATE')
            else: db.execute('SELECT pg_advisory_xact_lock(830019)')
            settings=json.loads(db.execute('SELECT value FROM settings WHERE id=1').fetchone()[0])
            rules=settings.get('custom_rules',[])
            existing=next((index for index,rule in enumerate(rules) if rule['id']==identifier),None)
            if create:
                if len(rules)>=200: raise ValueError('自定义规则最多 200 条')
                if existing is not None: raise ValueError('规则编号重复')
                rules.append({**value,'id':identifier})
            elif existing is None: raise KeyError(identifier)
            elif delete: rules.pop(existing)
            else: rules[existing]={**value,'id':identifier}
            settings['custom_rules']=rules
            db.execute('UPDATE settings SET value=? WHERE id=1',(json.dumps(settings),))
        return rules

    def event(self, request_id, ip, method, path, action, rule_id, status, domain='', connection=None):
        if action=='admin' and ip=='admin':
            from .accounts import actor
            ip=actor.get() or ip
        # Never persist bodies, query strings, cookies, Authorization, or matched payloads.
        from .geoip import source
        from .tls import normalize_domain
        try:domain=normalize_domain(domain,wildcard=False) if domain else ''
        except ValueError:domain=''
        info=source(ip) if action!='admin' else {'country':'','scope':''}
        with self.connect() as db:
            from .threats import classify
            custom=[]
            if rule_id.startswith('CUSTOM-') and action in ('blocked','detected'):
                custom=json.loads(db.execute('SELECT value FROM settings WHERE id=1').fetchone()[0]).get('custom_rules',[])
            threat_type=classify(rule_id,action,custom)
            db.execute('INSERT INTO events (created_at,request_id,ip,method,path,action,rule_id,status,domain,country,source_scope,threat_type,connection_detail) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                       (datetime.now(timezone.utc).isoformat(), request_id, ip, method, path[:512], action, rule_id, status,domain,info['country'],info['scope'],threat_type,json.dumps(connection or {})))

    def events(self, action='', page=1):
        with self.connect() as db:
            return [dict(row) for row in db.execute(
                'SELECT * FROM events WHERE (? = \'\' OR action=?) ORDER BY id DESC LIMIT 100 OFFSET ?',
                (action, action, (page-1)*100))]

    def events_page(self, action='', page=1, page_size=100, **filters):
        from .reporting import event_where
        where,params=event_where(action,**filters)
        with self.connect() as db:
            total = db.execute('SELECT count(*) FROM events WHERE '+where,params).fetchone()[0]
            pages = (total + page_size - 1) // page_size
            page = min(max(1, page), max(1, pages))
            items = [dict(row) for row in db.execute(
                'SELECT * FROM events WHERE '+where+' ORDER BY id DESC LIMIT ? OFFSET ?',
                (*params,page_size,(page-1)*page_size))]
            return {'items': items, 'total': total, 'page': page, 'page_size': page_size, 'pages': pages}

    def stats(self):
        with self.connect() as db:
            counts = {row[0]: row[1] for row in db.execute('SELECT action,count(*) FROM events GROUP BY action')}
        return {'total': sum(v for k, v in counts.items() if k != 'admin'), 'blocked': counts.get('blocked', 0),
                'detected': counts.get('detected', 0), 'allowed': counts.get('allowed', 0),
                'observed': counts.get('observed', 0),
                'errors': counts.get('error', 0)}
