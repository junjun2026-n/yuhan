"""Local country lookup: no visitor address is sent to an external API."""
from functools import lru_cache
import ipaddress
import mmap
from pathlib import Path
import struct

DATA=Path(__file__).resolve().parent/'data/country.bin'


@lru_cache(maxsize=1)
def index():
    try:
        with DATA.open('rb') as stream: result=mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ)
        if result[:8]!=b'WAFGEO01':result.close();return None
        v4,v6=struct.unpack('>II',result[8:16])
        if len(result)!=16+v4*10+v6*34:result.close();return None
        return result,v4,v6
    except (OSError,ValueError):return None


@lru_cache(maxsize=65536)
def source(address):
    try:
        ip=ipaddress.ip_address(address)
        if isinstance(ip,ipaddress.IPv6Address) and ip.ipv4_mapped:ip=ip.ipv4_mapped
    except ValueError:return {'external':False,'country':'','scope':'invalid'}
    if not ip.is_global or ip.is_multicast:return {'external':False,'country':'','scope':'internal'}
    data=index();country='ZZ'
    if data:
        mapped,v4,v6=data;width=4 if ip.version==4 else 16;size=width*2+2
        base=16 if width==4 else 16+v4*10
        low,high=0,(v4 if width==4 else v6)-1;packed=ip.packed
        while low<=high:
            middle=(low+high)//2;offset=base+middle*size
            if packed<mapped[offset:offset+width]:high=middle-1
            elif packed>mapped[offset+width:offset+width*2]:low=middle+1
            else:country=mapped[offset+width*2:offset+size].decode('ascii');break
    return {'external':True,'country':country,'scope':'external'}
