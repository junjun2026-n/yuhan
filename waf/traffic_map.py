"""Bounded public-source request graph, using bundled country coordinates."""
import json
from functools import lru_cache
from pathlib import Path

from .reporting import event_where, time_range


@lru_cache(maxsize=1)
def coordinates():
    return json.loads((Path(__file__).parent/'data/country-coordinates.json').read_text(encoding='utf-8'))


def traffic_map(store, period='24h', limit=150):
    since,until=time_range(period)
    where,params=event_where('business',since=since,until=until,external=True)
    with store.connect() as db:
        if store.engine=='sqlite':db.execute('BEGIN')
        else:
            db.rollback();db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
        totals=db.execute('SELECT count(*) requests,count(DISTINCT ip) sources FROM events WHERE '+where,params).fetchone()
        counts={r[0]:r[1] for r in db.execute('SELECT action,count(*) FROM events WHERE '+where+' GROUP BY action',params)}
        countries=[(r[0],r[1]) for r in db.execute('SELECT country,count(*) FROM events WHERE '+where+' GROUP BY country',params)]
        rows=db.execute("""SELECT ip,MAX(country) country,count(*) requests,
            SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) blocked,
            SUM(CASE WHEN action='detected' THEN 1 ELSE 0 END) detected,
            SUM(CASE WHEN action='allowed' THEN 1 ELSE 0 END) allowed,
            SUM(CASE WHEN action='observed' THEN 1 ELSE 0 END) observed,
            SUM(CASE WHEN action='error' THEN 1 ELSE 0 END) errors,
            MIN(created_at) first,MAX(created_at) last
            FROM events WHERE """+where+' GROUP BY ip ORDER BY count(*) DESC,ip ASC LIMIT ?',(*params,limit)).fetchall()
        domains=[{'domain':r[0],'requests':r[1]} for r in db.execute('SELECT domain,count(*) FROM events WHERE '+where+" AND domain!='' GROUP BY domain ORDER BY count(*) DESC,domain ASC LIMIT 5",params)]
    positions=coordinates();nodes=[]
    for row in rows:
        node=dict(row);point=positions.get(node['country'])
        node.update(longitude=point[0] if point else None,latitude=point[1] if point else None)
        nodes.append(node)
    return dict(period=period,since=since,until=until,nodes=nodes,domains=domains,limit=limit,
                totals=dict(requests=totals[0],sources=totals[1],countries=sum(1 for country,_ in countries if country in positions),
                            **counts,shown_sources=len(nodes),shown_requests=sum(n['requests'] for n in nodes),
                            mapped_sources=sum(n['latitude'] is not None for n in nodes),
                            unlocated_requests=sum(count for country,count in countries if country not in positions)),
                location_precision='country',metric='requests',destination_kind='logical_waf',
                geoip_provider='DB-IP Lite',map_provider='Natural Earth')
