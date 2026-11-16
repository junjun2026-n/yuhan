"""Run with all WAF application processes stopped: migrate and activate staged storage."""
import json
from datetime import datetime, timezone
import os
import socket

from .database import database_target, config_path
from .database_config import pending_path, read_config, resolved, values_for, probe
from .migrate import migrate
from .store import Store


def main():
    # The launcher always binds this local port. Refuse an online migration.
    port = 8401 if os.getenv('WAF_DEV_MODE') == '1' else 8301
    try:
        with socket.create_connection(('127.0.0.1',port),timeout=1):
            raise RuntimeError('请先停止 WAF 服务后再迁移数据库')
    except ConnectionRefusedError: pass
    pending = pending_path()
    if not pending.exists(): raise RuntimeError('没有待生效的数据库配置')
    value = resolved(read_config(pending))
    probe(value)
    source, target = Store(), Store(database_target(values_for(value)))
    same = source.path == target.path
    if source.engine == target.engine == 'postgresql':
        from psycopg.conninfo import conninfo_to_dict
        old,new = conninfo_to_dict(source.path),conninfo_to_dict(target.path)
        same = all(old.get(key, '5432' if key=='port' else '') == new.get(key, '5432' if key=='port' else '') for key in ('host','port','dbname'))
    if same:
        print('Database connection unchanged; configuration verified.')
    else:
        print(json.dumps(migrate(source,target),indent=2))
    active = config_path()
    if active.exists():
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        backup = active.with_name('database.'+stamp+'.backup.env')
        backup.write_bytes(active.read_bytes())
        if os.name != 'nt': backup.chmod(0o600)
    pending.replace(active)
    print('Database migration verified and configuration activated. Start WAF service.')


if __name__ == '__main__': main()
