# ============================================================
# 文件名称：network.py
# 生成日期：2026-10-27
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 network 模块相关功能。
#           文件用途：供WAF的 yuhan/waf/network.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Persistent logical NICs; OS names are resolved only at the host boundary."""
import ctypes
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import subprocess
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class LogicalNIC(BaseModel):
    model_config = ConfigDict(extra='forbid')
    alias: str = Field(pattern=r'^[a-z][a-z0-9_-]{0,23}$')
    role: Literal['management', 'business'] = 'business'
    physical_id: str = Field(default='', max_length=160)


class NetworkConfig(BaseModel):
    model_config = ConfigDict(extra='forbid')
    deployment_mode: Literal['proxy', 'bypass', 'inline'] = 'proxy'
    nic_count: int = Field(default=3, ge=1, le=32)
    management_cidr: str = '192.168.1.1/24'
    interfaces: list[LogicalNIC] = Field(default_factory=lambda: [
        LogicalNIC(alias='mgmt0', role='management'), LogicalNIC(alias='port1'), LogicalNIC(alias='port2')])
    mirror_alias: str = 'port1'
    ingress_alias: str = 'port1'
    egress_alias: str = 'port2'

    @field_validator('management_cidr')
    @classmethod
    def valid_address(cls, value):
        address = ipaddress.IPv4Interface(value)
        if address.ip.is_loopback or address.ip.is_multicast or address.ip.is_unspecified or address.ip.is_link_local:
            raise ValueError('管理地址须为有效的单播 IPv4 地址')
        if address.network.prefixlen < 31 and address.ip in (address.network.network_address, address.network.broadcast_address):
            raise ValueError('管理地址不能为网络地址或广播地址')
        return str(address)

    @model_validator(mode='after')
    def validate_interfaces(self):
        if self.nic_count != len(self.interfaces): raise ValueError('网卡数量与逻辑网卡行数不一致')
        aliases = [nic.alias for nic in self.interfaces]
        if len(set(aliases)) != len(aliases): raise ValueError('网卡别名不能重复')
        if sum(nic.role == 'management' for nic in self.interfaces) != 1:
            raise ValueError('必须且只能配置一个管理网卡')
        bound = [nic.physical_id for nic in self.interfaces if nic.physical_id]
        if len(set(bound)) != len(bound): raise ValueError('同一物理网卡不能重复绑定')
        business = {nic.alias for nic in self.interfaces if nic.role == 'business'}
        if self.deployment_mode == 'bypass' and self.mirror_alias not in business:
            raise ValueError('旁挂镜像口须选择业务网卡别名')
        if self.deployment_mode == 'inline' and (self.ingress_alias not in business or
                self.egress_alias not in business or self.ingress_alias == self.egress_alias):
            raise ValueError('串联入口与出口须为两个不同的业务网卡')
        return self


def privileged():
    return bool(ctypes.windll.shell32.IsUserAnAdmin()) if os.name == 'nt' else os.geteuid() == 0


def powershell(script, payload=None):
    # The script is constant; browser-provided data is JSON on stdin, never shell code.
    prelude = "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); $ErrorActionPreference='Stop'; "
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', prelude + script],
                            input=json.dumps(payload) if payload is not None else '',
                            capture_output=True, text=True, encoding='utf-8', timeout=30,
                            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if result.returncode: raise RuntimeError('操作系统网卡操作失败：' + result.stderr.strip()[:600])
    return json.loads(result.stdout.strip() or 'null')


def adapters():
    if os.name == 'nt':
        result = powershell(r'''
        $rows = @(Get-NetAdapter | ForEach-Object {
          $nic = $_
          $ips = @(Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" })
          [PSCustomObject]@{id="windows:$($nic.InterfaceGuid.ToString().Trim('{}').ToLower())"; name=$nic.Name;
            description=$nic.InterfaceDescription; mac=$nic.MacAddress; status=$nic.Status.ToString();
            ipv4=$ips; index=$nic.ifIndex}
        })
        ConvertTo-Json -InputObject $rows -Depth 5 -Compress
        ''')
        return result or []
    if platform.system() != 'Linux': raise RuntimeError('当前系统不支持网卡枚举')
    try:
        result = subprocess.run(['ip', '-j', '-d', 'address', 'show'], check=True, capture_output=True, text=True, timeout=10)
    except (subprocess.SubprocessError, OSError) as exc:
        raise RuntimeError('无法读取 Linux 网卡，请检查 iproute2 是否安装') from exc
    rows = []
    for nic in json.loads(result.stdout):
        if nic['ifname'] == 'lo' or nic.get('link_type') != 'ether' or nic.get('linkinfo',{}).get('info_kind')=='bridge': continue
        name = nic['ifname']
        # Permanent MAC remains stable across OS interface renaming; virtual NICs are also supported.
        mac = nic.get('permaddr') or nic.get('address', '')
        rows.append({'id':'linux:' + mac.lower(), 'name':name, 'mac':mac, 'description':name,
                     'status':nic.get('operstate', 'UNKNOWN'), 'index':nic['ifindex'],
                     'ipv4':[f"{v['local']}/{v['prefixlen']}" for v in nic.get('addr_info',[]) if v['family']=='inet'],
                     'ipv6_global':[v['local'] for v in nic.get('addr_info',[]) if v['family']=='inet6' and v.get('scope')=='global']})
    return rows


def resolve(config, inventory):
    by_id = {nic['id']:nic for nic in inventory}
    for key in list(by_id):
        if sum(nic['id']==key for nic in inventory)>1: del by_id[key]
    return {nic.alias:by_id.get(nic.physical_id) for nic in config.interfaces}


def validate_bindings(config, inventory, previous=None):
    present = {nic['id'] for nic in inventory}
    retained = {(nic.alias,nic.physical_id) for nic in previous.interfaces} if previous else set()
    for nic in config.interfaces:
        if nic.physical_id and sum(item['id']==nic.physical_id for item in inventory)>1:
            raise ValueError(f'{nic.alias} 的物理标识不唯一，请修复重复 MAC 地址')
        if nic.physical_id and nic.physical_id not in present and (nic.alias,nic.physical_id) not in retained:
            raise ValueError(f'{nic.alias} 绑定的物理网卡不存在，请刷新网卡列表')


def apply_management(config, inventory):
    if not privileged(): raise PermissionError('应用 IP 需要以管理员权限运行 WAF 服务')
    bound = resolve(config, inventory)
    logical = next(nic for nic in config.interfaces if nic.role == 'management')
    nic = bound[logical.alias]
    if not nic: raise ValueError('管理网卡未绑定或绑定的物理网卡已丢失')
    address = ipaddress.IPv4Interface(config.management_cidr)
    # Reject collisions on this host. Do not move or remove any address.
    for other in inventory:
        for existing in other['ipv4']:
            if ipaddress.ip_interface(existing).ip == address.ip:
                if other['id'] != nic['id'] or existing != str(address):
                    raise ValueError('目标管理 IP 已存在于其他网卡或使用了不同前缀')
                ensure_management_link_up(nic)
                return {'changed':False, 'alias':logical.alias, 'cidr':str(address)}
    if os.name == 'nt':
        powershell(r'''
        $data = [Console]::In.ReadToEnd() | ConvertFrom-Json
        $nic = @(Get-NetAdapter | Where-Object { "windows:$($_.InterfaceGuid.ToString().Trim('{}').ToLower())" -eq $data.id })
        if ($nic.Count -ne 1) { throw 'Adapter binding lost' }
        $dhcp = (Get-NetIPInterface -InterfaceIndex $nic[0].ifIndex -AddressFamily IPv4).Dhcp.ToString()
        if ($dhcp -eq 'Enabled') { throw 'DHCP is enabled; use a dedicated static management NIC to avoid disabling DHCP' }
        New-NetIPAddress -InterfaceIndex $nic[0].ifIndex -IPAddress $data.ip -PrefixLength $data.prefix -SkipAsSource $true | Out-Null
        '{"ok":true}'
        ''', {'id':nic['id'], 'ip':str(address.ip), 'prefix':address.network.prefixlen})
    elif platform.system() == 'Linux':
        try:
            subprocess.run(['ip','address','add',str(address),'dev',nic['name']],check=True,capture_output=True,timeout=10)
        except subprocess.SubprocessError as exc: raise RuntimeError('添加管理 IP 失败，请检查网卡和系统网络服务') from exc
        ensure_management_link_up(nic)
    else: raise RuntimeError('当前操作系统不支持应用管理 IP')
    return {'changed':True, 'alias':logical.alias, 'cidr':str(address)}


def ensure_management_link_up(nic):
    if os.name != 'nt' and platform.system() == 'Linux':
        try:
            subprocess.run(['ip','link','set','dev',nic['name'],'up'],check=True,capture_output=True,timeout=10)
        except subprocess.SubprocessError as exc: raise RuntimeError('管理网卡启用失败，请检查专用管理口状态') from exc


def ensure_business_link_up(nic):
    if not privileged(): raise PermissionError('启用业务网卡需要 root / 管理员权限')
    if os.name != 'nt' and platform.system() == 'Linux':
        try:
            subprocess.run(['ip','link','set','dev',nic['name'],'up'],check=True,capture_output=True,timeout=10)
        except subprocess.SubprocessError as exc: raise RuntimeError('业务网卡启用失败，请检查宿主机网卡状态') from exc
    else: raise RuntimeError('业务网卡加载运行环境须为 Ubuntu / Linux；配置测试可使用 bring_up=false')


def network_status(config, inventory):
    bound = resolve(config, inventory)
    rows = []
    for nic in config.interfaces:
        physical = bound[nic.alias]
        rows.append({**nic.model_dump(), 'binding_status': 'bound' if physical else ('missing' if nic.physical_id else 'unbound'),
                     'physical':physical})
    management = next(row for row in rows if row['role']=='management')
    applied = bool(management['physical'] and config.management_cidr in management['physical']['ipv4'])
    return {'platform':platform.system(), 'privileged':privileged(), 'interfaces':rows,
            'management_ip_applied':applied, 'management_url':f'http://{ipaddress.IPv4Interface(config.management_cidr).ip}:8301',
            'data_plane_available':platform.system()=='Linux',
            'note':'镜像旁挂和透明串联需在 Linux 上启动数据平面；Windows 仅支持配置与反向代理。'}
