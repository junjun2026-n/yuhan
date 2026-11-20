# ============================================================
# 文件名称：rules.py
# 生成日期：2026-10-27
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：定义和执行防护规则。
#           文件用途：供WAF的 yuhan/waf/rules.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
import re
import time
from collections import OrderedDict
from html import unescape
from urllib.parse import unquote

RULES = [
    {'id': 'SQLI-001', 'name': 'SQL 注入', 'category': 'SQLi',
     'pattern': r"\bunion\s+(?:all\s+)?select\b|\b(?:or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|\b(?:sleep|benchmark)\s*\("},
    {'id': 'XSS-001', 'name': '跨站脚本', 'category': 'XSS',
     'pattern': r'<\s*script\b|\bon(?:error|load|click|mouseover)\s*=|javascript\s*:'},
    {'id': 'PATH-001', 'name': '目录穿越', 'category': 'Traversal',
     'pattern': r'(?:\.\.[/\\])|(?:/etc/(?:passwd|shadow))|(?:windows[/\\]win\.ini)'},
    {'id': 'CMD-001', 'name': '命令注入', 'category': 'Command',
     'pattern': r'(?:;|\|\||&&|\$\(|`)\s*(?:cat|curl|wget|bash|sh|powershell|cmd|whoami|id)\b'},
    {'id': 'SCAN-001', 'name': '敏感路径扫描', 'category': 'Scanner',
     'pattern': r'(?:^|/)(?:\.git(?:/|$)|\.env(?:$|[/?])|wp-config\.php|phpmyadmin(?:/|$))'},
]
COMPILED = [(rule, re.compile(rule['pattern'], re.I)) for rule in RULES]


def inspect(parts, disabled=()):
    for value in parts:
        value = str(value)
        for _ in range(2):
            value = unescape(unquote(value.replace('+', ' ')))
        for rule, pattern in COMPILED:
            if rule['id'] not in disabled and pattern.search(value):
                return rule['id']
    return ''


class RateLimiter:
    def __init__(self):
        self.clients = OrderedDict()

    def allow(self, ip, limit):
        now = time.monotonic()
        while self.clients and next(iter(self.clients.values()))[0] + 60 <= now:
            self.clients.popitem(last=False)
        start, count = self.clients.get(ip, (now, 0))
        # Refuse new addresses at capacity instead of allowing unbounded memory growth.
        if ip not in self.clients and len(self.clients) >= 20000:
            return False
        count += 1
        self.clients[ip] = (start, count)
        return count <= limit
