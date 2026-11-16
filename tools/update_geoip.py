"""Build the bundled offline country index from DB-IP Lite CSVs (CC BY 4.0)."""
import base64
import csv
import hashlib
import ipaddress
import json
from pathlib import Path
import struct
import urllib.request

ROOT=Path(__file__).resolve().parents[1]/'waf/data'


def get(url):
    request=urllib.request.Request(url,headers={'User-Agent':'Qionghai-WAF'})
    with urllib.request.urlopen(request,timeout=120) as response:return json.load(response)


def main():
    ROOT.mkdir(exist_ok=True)
    entries=get('https://api.github.com/repos/sapics/ip-location-db/contents/dbip-country')
    sources=[];parts=[];counts=[]
    for version in (4,6):
        item=next(e for e in entries if e['name']==f'dbip-country-ipv{version}.csv')
        value=get(item['git_url'])
        data=base64.b64decode(value['content'])
        assert hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==item['sha']
        output=bytearray();count=0;previous=-1;width=4 if version==4 else 16
        for start,end,country in csv.reader(data.decode().splitlines()):
            first,last=ipaddress.ip_address(start),ipaddress.ip_address(end)
            assert first.version==last.version==version and previous<int(first)<=int(last)
            assert len(country)==2 and country.isascii() and country.isupper()
            output.extend(first.packed+last.packed+country.encode('ascii'));count+=1;previous=int(last)
        parts.append(output);counts.append(count)
        sources.append({'url':item['html_url'],'git_sha':item['sha'],'sha256':hashlib.sha256(data).hexdigest(),'ranges':count})
    packed=b'WAFGEO01'+struct.pack('>II',*counts)+b''.join(parts)
    (ROOT/'country.bin').write_bytes(packed)
    (ROOT/'country-sources.json').write_text(json.dumps({'provider':'DB-IP Lite via sapics/ip-location-db','license':'CC BY 4.0','attribution':'IP Geolocation by DB-IP https://db-ip.com','sources':sources,'sha256':hashlib.sha256(packed).hexdigest()},indent=2)+'\n')
    license_item=next(e for e in entries if e['name']=='DBIP-LICENSE')
    (ROOT/'DBIP-LICENSE').write_bytes(base64.b64decode(get(license_item['git_url'])['content']))
    print('Built offline country index:',len(packed),'bytes',counts)


if __name__=='__main__':main()
