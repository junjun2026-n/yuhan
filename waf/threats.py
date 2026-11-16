"""Stable event-time classification for overview rankings."""
from .rules import RULES

LABELS = {'SQLi':'SQL 注入','XSS':'跨站脚本','Traversal':'目录穿越','Command':'命令注入',
          'Scanner':'敏感路径扫描','CC':'CC / 请求频率超限','Port':'业务端口防护',
          'Custom':'自定义防护','Method':'请求方法限制','Domain':'域名访问限制',
          'Body':'请求体超限','Other':'其他防护命中','blacklist':'黑名单'}


def classify(rule_id, action, custom_rules=()):
    if action not in ('blocked','detected'):
        return ''
    if rule_id.startswith('PORT_DENY'):
        return 'blacklist'
    if rule_id.startswith('CUSTOM-'):
        rule=next((r for r in custom_rules if r['id']==rule_id),None)
        return 'blacklist' if rule and rule.get('action')=='block' and rule.get('source_ip') else 'Custom'
    known=next((r['category'] for r in RULES if r['id']==rule_id),None)
    if known:return known
    if rule_id=='RATE' or rule_id.startswith('CC_'):return 'CC'
    if rule_id.startswith('PORT_'):return 'Port'
    return {'METHOD':'Method','DOMAIN':'Domain','BODY':'Body'}.get(rule_id,'Other')
