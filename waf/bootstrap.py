# ============================================================
# 文件名称：bootstrap.py
# 生成日期：2026-10-27
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 bootstrap 模块相关功能。
#           文件用途：供WAF的 yuhan/waf/bootstrap.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Management provisioning and explicit business NIC bindings from mgrnic.ini."""
import configparser
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import re
import subprocess

from .network import NetworkConfig, LogicalNIC, adapters, apply_management, network_status, ensure_management_link_up, ensure_business_link_up, resolve


def read_document(path):
    parser = configparser.ConfigParser(interpolation=None)
    with Path(path).open(encoding='utf-8-sig') as stream:
        parser.read_file(stream)
    if not parser.has_section('management') or parser.defaults():
        raise ValueError('mgrnic.ini 必须包含 [management]，不允许 DEFAULT 配置')
    for name in parser.sections():
        if name == 'management': allowed = {'alias','interface','physical_id','mac','ip','nic_count','apply_ip'}
        elif re.fullmatch(r'business:[a-z][a-z0-9_-]{0,23}', name):
            allowed = {'interface','physical_id','mac','bring_up'}
        else: raise ValueError('未知配置节：' + name + '；业务口格式为 [business:port1]')
        unknown = set(parser[name]) - allowed
        if unknown: raise ValueError(name + ' 存在未知配置项：' + ', '.join(sorted(unknown)))
        read_selector(parser[name])
    return parser


def read_selector(section):
    selected = [(key,section.get(key,'').strip()) for key in ('interface','physical_id','mac') if section.get(key,'').strip()]
    if len(selected)>1: raise ValueError('interface、physical_id、mac 只能填写一项')
    if selected and selected[0][0]=='mac': normalize_mac(selected[0][1])
    return selected[0] if selected else None


def business_specs(parser):
    return [{'alias':name.split(':',1)[1], 'selector':read_selector(parser[name]),
             'bring_up':parser[name].getboolean('bring_up',fallback=True)}
            for name in parser.sections() if name.startswith('business:')]


def read_config(path):
    parser = read_document(path)
    section = parser['management']
    selected = read_selector(section)
    alias = section.get('alias','mgmt0').strip()
    count = section.getint('nic_count',fallback=3)
    if not 1 <= count <= 32: raise ValueError('nic_count 必须为 1～32')
    interfaces = [LogicalNIC(alias=alias,role='management')]
    specs = business_specs(parser)
    if len(specs)>count-1: raise ValueError('业务口数量超过 nic_count，请增加网卡总数量')
    interfaces.extend(LogicalNIC(alias=spec['alias']) for spec in specs)
    port = 1
    while len(interfaces)<count:
        name = f'port{port}'; port += 1
        if name not in {nic.alias for nic in interfaces}: interfaces.append(LogicalNIC(alias=name))
    business = [nic.alias for nic in interfaces if nic.role=='business']
    config = NetworkConfig(nic_count=count,management_cidr=section.get('ip','192.168.1.1/24').strip(),
        interfaces=interfaces,mirror_alias=business[0] if business else '',
        ingress_alias=business[0] if business else '',egress_alias=business[1] if len(business)>1 else '')
    return config, selected, section.getboolean('apply_ip',fallback=True)


def normalize_mac(value):
    normalized = re.sub('[:-]','',value).lower()
    if not re.fullmatch(r'[0-9a-f]{12}',normalized): raise ValueError('MAC 地址格式无效')
    return normalized


def select_adapter(selector, inventory):
    kind, value = selector
    if kind=='mac':
        wanted = normalize_mac(value)
        found = [nic for nic in inventory if re.sub('[:-]','',nic.get('mac','')).lower()==wanted]
    else:
        field = 'name' if kind=='interface' else 'id'
        found = [nic for nic in inventory if nic[field]==value]
    if len(found)!=1: raise ValueError('网卡选择须唯一匹配一个实际网卡，当前匹配数量：' + str(len(found)))
    if sum(nic['id']==found[0]['id'] for nic in inventory)!=1:
        raise ValueError('管理网卡物理标识重复，请修复重复 MAC')
    return found[0]


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def initialize_management(store, path):
    """Retry failed initialization, but never overwrite completed / manually changed config.

    Subsequent boots restore the saved address if initial provisioning opted into IP application.
    The INI is no longer read once provisioning is complete.
    """
    state = store.bootstrap_state()
    current = store.network()
    if state.get('state') in ('skipped_existing','skipped_changed'):
        return state
    if state.get('state')=='completed':
        if not state.get('apply_ip'): return state
        try:
            inventory = adapters()
            if not network_status(current,inventory)['management_ip_applied']:
                apply_management(current,inventory)
            else:
                alias = next(nic.alias for nic in current.interfaces if nic.role=='management')
                ensure_management_link_up(resolve(current,inventory)[alias])
            state.update(last_error='',last_checked=timestamp())
        except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as exc:
            state.update(last_error=str(exc),last_checked=timestamp())
        store.save_bootstrap_state(state)
        return state
    if state.get('imported_config'):
        if current.model_dump()!=state['imported_config']:
            result={**state,'state':'skipped_changed','detail':'系统配置已在页面修改，停止 INI 初始化，保留现有配置。'}
            store.save_bootstrap_state(result)
            return result
    elif current != NetworkConfig():
        result={'state':'skipped_existing','detail':'已有自定义系统配置，保留现有配置，不导入 mgrnic.ini。'}
        store.save_bootstrap_state(result)
        return result
    result = {**state,'updated_at':timestamp(),'source':'mgrnic.ini'}
    try:
        config, selector, apply_ip = read_config(path)
        if selector is None:
            result.update(state='waiting_selection',detail='请在 mgrnic.ini 中填写管理网卡 interface、physical_id 或 mac。',last_error='')
        else:
            inventory = adapters()
            physical = select_adapter(selector,inventory)
            config.interfaces[0].physical_id=physical['id']
            result.update(state='pending_ip' if apply_ip else 'completed',apply_ip=apply_ip,
                imported_config=config.model_dump(),last_error='',detail='管理网卡配置已导入。')
            # Persist config and its ownership marker in one transaction; protect concurrent UI edits.
            store.import_bootstrap_network(config,current,result)
            if apply_ip:
                if not network_status(config,inventory)['management_ip_applied']:
                    apply_management(config,inventory)
                else:
                    ensure_management_link_up(physical)
                result.update(state='completed',detail='管理网卡及 IP 初始化完成。')
            result['completed_at']=timestamp()
            store.event('bootstrap', 'local', 'INIT', '/system/management', 'admin', 'MGRNIC_INIT', 200)
    except (ValueError, RuntimeError, OSError, configparser.Error, subprocess.SubprocessError) as exc:
        result.update(state='pending_ip' if result.get('imported_config') else 'error',last_error=str(exc),
                      detail='管理网卡初始化未完成；修正配置或权限后再次启动会重试，本机管理入口保留。')
    store.save_bootstrap_state(result)
    return result


def initialize_network(store, path):
    state = initialize_management(store, path)
    if state.get('state') not in ('completed','skipped_existing','skipped_changed'): return state
    # Existing installations keep their management address and deployment mode.
    # Only explicitly selected business aliases are imported independently.
    try:
        if not Path(path).exists(): return state
        specs = [spec for spec in business_specs(read_document(path)) if spec['selector']]
        if not specs: return state
        desired = hashlib.sha256(json.dumps(specs,sort_keys=True).encode()).hexdigest()
        previous = state.get('business', {})
        current = store.network()
        current_bindings = {nic.alias:nic.physical_id for nic in current.interfaces if nic.role=='business'}
        if previous.get('source_hash') == desired and any(current_bindings.get(alias)!=binding for alias,binding in previous.get('bindings',{}).items()):
            state['business'] = {**previous,'state':'skipped_changed','detail':'业务口已在页面修改，保留页面配置；修改 INI 选择项后才重新导入。','last_checked':timestamp()}
            store.save_bootstrap_state(state)
            return state
        inventory = adapters()
        updated = current.model_copy(deep=True)
        by_alias = {nic.alias:nic for nic in updated.interfaces if nic.role=='business'}
        selected = {}
        for spec in specs:
            alias = spec['alias']
            if alias not in by_alias: raise ValueError(f'业务别名 {alias} 不存在，请先在页面配置相应业务网卡')
            if previous.get('source_hash') == desired:
                physical = resolve(current,inventory).get(alias)
                if not physical: raise ValueError(f'业务网卡 {alias} 已丢失，请检查宿主机网卡')
            else: physical = select_adapter(spec['selector'],inventory)
            if physical.get('ipv4') or physical.get('ipv6_global'):
                raise ValueError(f'业务网卡 {alias} 已配置 IP，请使用独立的无 IP 业务网卡')
            selected[alias] = physical
            by_alias[alias].physical_id = physical['id']
        # Revalidate uniqueness including the saved management NIC. Never share it.
        updated = NetworkConfig.model_validate(updated.model_dump())
        state['business'] = {'source_hash':desired,'bindings':{alias:nic['id'] for alias,nic in selected.items()},
                             'state':'pending_link','last_error':'','last_checked':timestamp()}
        if state.get('imported_config'): state['imported_config'] = updated.model_dump()
        store.import_bootstrap_network(updated,current,state)
        for spec in specs:
            if spec['bring_up']: ensure_business_link_up(selected[spec['alias']])
        changed = previous.get('source_hash') != desired
        state['business'].update(state='completed',detail='业务口绑定已加载，Docker host 网络可直接调用宿主机业务网卡。')
        store.save_bootstrap_state(state)
        if changed: store.event('bootstrap','local','INIT','/system/business','admin','BUSINESS_NIC_INIT',200)
    except (ValueError, RuntimeError, OSError, configparser.Error, subprocess.SubprocessError) as exc:
        state['business'] = {**state.get('business',{}),'state':'error','last_error':str(exc),'last_checked':timestamp(),
                             'detail':'业务网卡初始化未完成；修正后重启重试，管理口和其他配置保留。'}
        store.save_bootstrap_state(state)
    return state
