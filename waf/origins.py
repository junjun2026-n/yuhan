"""Configured domain routing and per-worker origin rotation."""
from urllib.parse import urlsplit

from .tls import domain_matches


def normalize_origin(value):
    value = value.strip()
    if not value:
        return ''
    if any(char.isspace() or ord(char) < 32 for char in value) or any(char in value for char in '\\?#'):
        raise ValueError('源站地址包含非法字符')
    parsed = urlsplit(value)
    if (parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment or parsed.path not in ('', '/')):
        raise ValueError('源站须为 HTTP/HTTPS 地址，不包含用户名、密码、路径或查询参数')
    port = parsed.port if parsed.port is not None else (443 if parsed.scheme == 'https' else 80)
    if not 1 <= port <= 65535 or port in (8300, 8301, 8443):
        raise ValueError('源站端口无效或指向 WAF 监听端口')
    return value.rstrip('/')


class OriginRouter:
    def __init__(self):
        self.counters = {}

    def select(self, settings, host, port=None, path='/'):
        rules = settings.get('origin_rules', [])
        candidates = []
        for number, rule in enumerate(rules):
            if not domain_matches(host, rule['domain']) or (rule.get('port') and rule['port'] != port):
                continue
            prefix = rule.get('path_prefix', '/')
            if not path.startswith(prefix):
                continue
            candidates.append((int(rule.get('priority', 100)), len(prefix), rule['domain'].startswith('*.'), number, rule['origins']))
        if candidates:
            _, _, _, number, selected = sorted(candidates, key=lambda item: (-item[0], item[2], -item[1], item[3]))[0]
            domain = f'rule:{number}'
            origins = tuple(selected)
        else:
            bindings = settings.get('domain_upstreams', {})
            domain = host if host in bindings else next((key for key in sorted(bindings) if domain_matches(host, key)), '')
            origins = tuple(bindings[domain]) if domain else ((settings['upstream'],) if settings['upstream'] else ())
        valid_keys = set(settings.get('domain_upstreams', {})) | {''} | {f'rule:{number}' for number in range(len(rules))}
        self.counters = {key: value for key, value in self.counters.items() if key in valid_keys}
        if not origins:
            return ()
        previous, index = self.counters.get(domain, ((), 0))
        if previous != origins:
            index = 0
        self.counters[domain] = (origins, (index + 1) % len(origins))
        return origins[index:] + origins[:index]
