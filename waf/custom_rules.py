"""Validated emergency policies, evaluated before built-in attack signatures."""
import ipaddress
import json
from datetime import datetime,timezone
from functools import lru_cache
from typing import Literal
from urllib.parse import unquote

from pydantic import BaseModel,ConfigDict,Field,field_validator,model_validator
from .tls import normalize_domain,domain_matches


class CustomRule(BaseModel):
    model_config=ConfigDict(extra='forbid')
    name: str=Field(min_length=1,max_length=80)
    enabled: bool=True
    action: Literal['block','allow','monitor']='block'
    priority: int=Field(default=100,ge=1,le=10000)
    source_ip: str=Field(default='',max_length=64)
    domain: str=Field(default='',max_length=253)
    methods: list[str]=Field(default_factory=list,max_length=9)
    path: str=Field(default='',max_length=512)
    path_match: Literal['prefix','exact','contains']='prefix'
    keyword: str=Field(default='',max_length=256)
    case_sensitive: bool=False
    expires_at: datetime | None=None
    match_all: bool=False

    @field_validator('name','source_ip','domain','path','keyword')
    @classmethod
    def clean(cls,value):
        value=value.strip()
        if any(ord(c)<32 for c in value): raise ValueError('规则文本不能包含控制字符')
        return value

    @field_validator('source_ip')
    @classmethod
    def valid_ip(cls,value):
        if not value: return ''
        return str(ipaddress.ip_network(value,strict=False))

    @field_validator('domain')
    @classmethod
    def valid_domain(cls,value): return normalize_domain(value) if value else ''

    @field_validator('methods')
    @classmethod
    def valid_methods(cls,value):
        methods=sorted(set(method.upper().strip() for method in value))
        if set(methods)-{'GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS','TRACE','CONNECT'}: raise ValueError('请求方法无效')
        return methods

    @field_validator('expires_at')
    @classmethod
    def valid_expiry(cls,value):
        if value is not None and value.utcoffset() is None: raise ValueError('到期时间必须包含时区')
        return value.astimezone(timezone.utc) if value else None

    @model_validator(mode='after')
    def valid_conditions(self):
        if not self.name: raise ValueError('规则名称不能为空')
        if not any((self.source_ip,self.domain,self.methods,self.path,self.keyword,self.match_all)):
            raise ValueError('至少配置一个匹配条件，或明确选择“匹配全部请求”')
        if self.path and self.path_match!='contains' and not self.path.startswith('/'):
            raise ValueError('精确或前缀路径须以 / 开头')
        return self


@lru_cache(maxsize=8)
def compiled(serialized):
    result=[]
    for value in json.loads(serialized):
        rule=CustomRule.model_validate({key:value for key,value in value.items() if key!='id'})
        result.append((value['id'],rule,ipaddress.ip_network(rule.source_ip) if rule.source_ip else None))
    return sorted(result,key=lambda item:(item[1].priority,item[0]))


def evaluate(rules,ip,host,method,path,query=''):
    if not rules: return None
    now=datetime.now(timezone.utc)
    try: address=ipaddress.ip_address(ip)
    except ValueError: address=None
    decoded_path,decoded_url=path,path+('?' + query if query else '')
    for _ in range(2):
        decoded_path=unquote(decoded_path)
        decoded_url=unquote(decoded_url.replace('+',' '))
    for identifier,rule,network in compiled(json.dumps(rules,sort_keys=True)):
        if not rule.enabled or (rule.expires_at and rule.expires_at<=now): continue
        if network and (address is None or address not in network): continue
        if rule.domain and not domain_matches(host,rule.domain): continue
        if rule.methods and method.upper() not in rule.methods: continue
        actual,wanted,url,keyword=decoded_path,rule.path,decoded_url,rule.keyword
        if not rule.case_sensitive: actual,wanted,url,keyword=actual.casefold(),wanted.casefold(),url.casefold(),keyword.casefold()
        if wanted:
            matched=actual==wanted if rule.path_match=='exact' else actual.startswith(wanted) if rule.path_match=='prefix' else wanted in actual
            if not matched: continue
        if keyword and keyword not in url: continue
        return {'id':identifier,'action':rule.action,'name':rule.name}
    return None
