# ============================================================
# 文件名称：migrate.py
# 生成日期：2026-10-27
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：执行 migrate 对应的启动、构建或运维任务。
#           文件用途：供WAF的 yuhan/waf/migrate.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Offline, transactional migration of all WAF tables between supported stores."""
import argparse
import hashlib
import json

from .store import Store

TABLES = ('settings', 'system_settings', 'platform_settings', 'bootstrap_state', 'agent_state', 'log_forwarding', 'accounts', 'traffic_protection', 'events')


def digest(rows):
    return hashlib.sha256(json.dumps([dict(row) for row in rows], sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def migrate(source, target):
    if source.path == target.path: raise ValueError('Source and target must differ')
    report = {}
    with source.connect() as origin, target.connect() as destination:
        origin.rollback()
        if source.engine == 'sqlite': origin.execute('BEGIN')
        else: origin.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
        if target.engine == 'postgresql': destination.execute('SELECT pg_advisory_xact_lock(830018)')
        # Never overwrite an existing installation. The default singleton is harmless.
        for table in TABLES:
            count = destination.execute(f'SELECT count(*) FROM {table}').fetchone()[0]
            if count and table != 'settings': raise ValueError(f'Target table {table} is not empty')
        if target.settings() != __import__('waf.store', fromlist=['DEFAULTS']).DEFAULTS:
            raise ValueError('Target already contains customized settings')
        for table in TABLES:
            rows = origin.execute(f'SELECT * FROM {table} ORDER BY id').fetchall()
            destination.execute(f'DELETE FROM {table}')
            for row in rows:
                record = dict(row)
                columns = ','.join(record)
                placeholders = ','.join('?' for _ in record)
                destination.execute(f'INSERT INTO {table} ({columns}) VALUES ({placeholders})', tuple(record.values()))
            copied = destination.execute(f'SELECT * FROM {table} ORDER BY id').fetchall()
            if digest(rows) != digest(copied): raise ValueError(f'Verification failed: {table}')
            report[table] = {'rows': len(rows), 'sha256': digest(rows)}
        if target.engine == 'postgresql':
            destination.execute("SELECT setval(pg_get_serial_sequence('events','id'), COALESCE(MAX(id),1), MAX(id) IS NOT NULL) FROM events")
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--sqlite-source', required=True)
    args = parser.parse_args()
    print(json.dumps(migrate(Store(args.sqlite_source), Store()), indent=2))
