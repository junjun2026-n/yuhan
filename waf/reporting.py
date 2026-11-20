# ============================================================
# 文件名称：reporting.py
# 生成日期：2026-11-05
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 reporting 模块相关功能。
#           文件用途：供WAF的 yuhan/waf/reporting.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Shared predicates keep overview counts and drill-down lists consistent."""
from datetime import datetime,timedelta,timezone
from .geoip import index

BUSINESS=('blocked','detected','allowed','observed','error')


def event_where(action='',since='',until='',domain='',ip='',country='',rule_id='',method='',path='',status=None,external=False,threat_type=''):
    clauses=[];params=[]
    if action=='business':clauses.append("action IN ('blocked','detected','allowed','observed','error')")
    elif action=='hits':clauses.append("action IN ('blocked','detected')")
    elif action=='blacklist':clauses.append("action IN ('blocked','detected') AND threat_type='blacklist'")
    elif action=='attacks':clauses.append("action IN ('blocked','detected') AND threat_type NOT IN ('','blacklist')")
    elif action:clauses.append('action=?');params.append(action)
    for name,value in (('domain',domain),('ip',ip),('country',country),('rule_id',rule_id),('method',method),('path',path),('threat_type',threat_type)):
        if value:clauses.append(name+'=?');params.append(value)
    if status is not None:clauses.append('status=?');params.append(status)
    if since:clauses.append('created_at>=?');params.append(since)
    if until:clauses.append('created_at<=?');params.append(until)
    if external:clauses.append("source_scope='external'")
    return ' AND '.join(clauses) or '1=1',tuple(params)


def time_range(period):
    now=datetime.now(timezone.utc);until=now.isoformat()
    since=(now-timedelta(days={'24h':1,'7d':7,'30d':30}[period])).isoformat() if period!='all' else ''
    return since,until


def overview(store,period='all'):
    since,until=time_range(period)
    where,params=event_where('business',since=since,until=until)
    with store.connect() as db:
        if store.engine=='sqlite':db.execute('BEGIN')
        else:
            db.rollback();db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
        counts={row[0]:row[1] for row in db.execute('SELECT action,count(*) FROM events WHERE '+where+' GROUP BY action',params)}
        rankings={}
        for key,column,extra in (
            ('domains','domain',"domain!=''"),('external_ips','ip',"source_scope='external'"),
            ('countries','country',"source_scope='external' AND country!=''"),
            ('rules','rule_id',"rule_id!='' AND action IN ('blocked','detected')"),
            ('blacklist_ips','ip',"threat_type='blacklist' AND action IN ('blocked','detected')"),
            ('attacks','threat_type',"threat_type NOT IN ('','blacklist') AND action IN ('blocked','detected')"),
            ('paths','path','1=1'),('methods','method','1=1'),('statuses','status','status>0')):
            rows=db.execute(f'SELECT {column},count(*) FROM events WHERE {where} AND {extra} GROUP BY {column} ORDER BY count(*) DESC,{column} ASC LIMIT 5',params)
            rankings[key]=[{'value':row[0],'count':row[1]} for row in rows]
        from .threats import LABELS
        for item in rankings['attacks']:item['label']=LABELS.get(item['value'],item['value'])
        missing=db.execute('SELECT count(*) FROM events WHERE '+where+" AND domain=''",params).fetchone()[0]
        external=db.execute('SELECT count(*) FROM events WHERE '+where+" AND source_scope='external'",params).fetchone()[0]
    return {'counts':{'total':sum(counts.values()),'blocked':counts.get('blocked',0),'detected':counts.get('detected',0),
        'allowed':counts.get('allowed',0),'observed':counts.get('observed',0),'errors':counts.get('error',0)},
        'rankings':rankings,'period':period,'since':since,'until':until,'external_requests':external,'missing_domains':missing,
        'geoip_available':bool(index()),'geoip_provider':'DB-IP Lite'}
