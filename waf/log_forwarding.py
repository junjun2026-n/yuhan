# ============================================================
# 文件名称：log_forwarding.py
# 生成日期：2026-10-28
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：组织并转发平台日志。
#           文件用途：供WAF的 yuhan/waf/log_forwarding.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Persistent audit event forwarding; only the admin process runs the sender."""
import asyncio
import ipaddress
import json
import socket
import ssl
import string
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

FIELDS = {'id', 'created_at', 'request_id', 'ip', 'method', 'path', 'action', 'rule_id', 'status', 'hostname', 'platform_name'}


class LogConfig(BaseModel):
    model_config = ConfigDict(extra='forbid')
    enabled: bool = False
    host: str = ''
    port: int = Field(default=514, ge=1, le=65535)
    protocol: Literal['udp', 'tcp', 'tls'] = 'udp'
    format: Literal['json', 'syslog', 'custom'] = 'json'
    template: str = Field(default='{created_at} {ip} {method} {path} {action} {rule_id} {status}', max_length=8192)
    facility: int = Field(default=16, ge=0, le=23)

    @model_validator(mode='after')
    def validate_config(self):
        if self.host:
            try: ipaddress.ip_address(self.host)
            except ValueError: raise ValueError('接收服务器必须是有效 IPv4 或 IPv6 地址')
        if self.enabled and not self.host: raise ValueError('启用转发时必须填写接收服务器 IP')
        if any(ord(c) < 32 for c in self.template): raise ValueError('模板必须为单行文本')
        try:
            for _, name, spec, conversion in string.Formatter().parse(self.template):
                if name is not None and (name not in FIELDS or spec or conversion):
                    raise ValueError('模板仅支持列出的字段，不支持属性、格式化或转换表达式')
        except ValueError as exc: raise ValueError('自定义模板无效：' + str(exc))
        if self.format == 'custom' and not self.template.strip(): raise ValueError('自定义模板不能为空')
        return self


def configuration(store):
    with store.connect() as db:
        row = db.execute('SELECT value,state FROM log_forwarding WHERE id=1').fetchone()
    return (LogConfig.model_validate_json(row[0]), json.loads(row[1])) if row else (LogConfig(), {'cursor': 0})


def save_config(store, config):
    with store.connect() as db:
        db.execute('INSERT INTO log_forwarding VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value',
                   (config.model_dump_json(), json.dumps({'cursor': 0})))


def public_status(store):
    config, state = configuration(store)
    with store.connect() as db:
        pending = db.execute('SELECT count(*) FROM events WHERE id>?', (state.get('cursor', 0),)).fetchone()[0]
    return {'config': config.model_dump(), 'state': state, 'pending': pending}


def render(config, event, platform):
    record = {**event, 'hostname': platform.hostname, 'platform_name': platform.platform_name}
    record['source_system']='waf'
    try:
        connection=json.loads(event.get('connection_detail') or '{}')
        for key in ('src_ip','src_port','dst_ip','dst_port','protocol'):
            if key in connection:record[key]=connection[key]
    except (ValueError,TypeError):pass
    try:
        with socket.socket(socket.AF_INET6 if ':' in config.host else socket.AF_INET,socket.SOCK_DGRAM) as route:
            route.connect((config.host,config.port));record['sender_ip']=route.getsockname()[0]
    except OSError:record['sender_ip']=''
    payload = json.dumps(record, ensure_ascii=False, separators=(',', ':'))
    if config.format == 'syslog':
        # RFC 5424 header, local facility, informational severity; JSON MSG.
        payload = f'<{config.facility * 8 + 6}>1 {record["created_at"]} {platform.hostname} WAF - {record["action"]} - {payload}'
    elif config.format == 'custom':
        safe = {key: json.dumps(value, ensure_ascii=False)[1:-1] if isinstance(value, str) else str(value) for key, value in record.items()}
        payload = config.template.format_map(safe)
    result = payload.encode('utf-8')
    if len(result) > 60000: raise ValueError('日志消息超过 60000 字节')
    return result


def send(config, payload):
    family = socket.AF_INET6 if ipaddress.ip_address(config.host).version == 6 else socket.AF_INET
    if config.protocol == 'udp':
        with socket.socket(family, socket.SOCK_DGRAM) as connection:
            connection.settimeout(3)
            connection.sendto(payload, (config.host, config.port))
    else:
        with socket.create_connection((config.host, config.port), timeout=3) as connection:
            if config.protocol == 'tls':
                with ssl.create_default_context().wrap_socket(connection, server_hostname=config.host) as secure:
                    secure.sendall(payload + b'\n')
            else: connection.sendall(payload + b'\n')


def forward_batch(store, stop=None):
    config, state = configuration(store)
    if not config.enabled: return False
    try:
        with store.connect() as db:
            rows = db.execute('SELECT * FROM events WHERE id>? ORDER BY id LIMIT 100', (state.get('cursor', 0),)).fetchall()
        platform = store.platform_config()
        for row in rows:
            if stop is not None and stop.is_set(): break
            send(config, render(config, dict(row), platform))
            state.update(cursor=row['id'], last_sent_at=datetime.now(timezone.utc).isoformat(), last_error='')
            with store.connect() as db:
                db.execute('UPDATE log_forwarding SET state=? WHERE id=1', (json.dumps(state),))
        return bool(rows)
    except (OSError, ValueError):
        state['last_error'] = '转发失败，请检查服务器、端口、协议及 TLS 证书；将自动重试'
        with store.connect() as db:
            db.execute('UPDATE log_forwarding SET state=? WHERE id=1', (json.dumps(state),))
        return False


async def worker(store, stop):
    while not stop.is_set():
        try: busy = await asyncio.to_thread(forward_batch, store, stop)
        except Exception:
            # Database outages must not terminate forwarding or the admin service.
            busy = False
        try: await asyncio.wait_for(stop.wait(), timeout=0.05 if busy else 5)
        except asyncio.TimeoutError: pass
