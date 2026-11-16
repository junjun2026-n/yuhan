from pathlib import Path

import pytest

from waf import bootstrap
from waf.network import NetworkConfig
from waf.store import Store


@pytest.fixture
def setup(tmp_path,monkeypatch):
    store=Store(tmp_path/'test.db')
    path=tmp_path/'mgrnic.ini'
    inventory=[{'id':'physical-1','name':'管理网卡','mac':'AA-BB-CC-DD-EE-FF','ipv4':[],'status':'Up'}]
    monkeypatch.setattr(bootstrap,'adapters',lambda:inventory)
    monkeypatch.setattr(bootstrap,'ensure_management_link_up',lambda *_:None)
    return store,path,inventory


def write(path, text):
    path.write_text('[management]\n'+text,encoding='utf-8-sig')


def test_template_defaults_no_hardware_operations(setup,monkeypatch):
    store,path,_=setup
    path.write_text((Path(__file__).parents[1]/'mgrnic.ini').read_text(encoding='utf-8'),encoding='utf-8')
    monkeypatch.setattr(bootstrap,'adapters',lambda:pytest.fail('Blank selector must not inspect or change hardware'))
    result=bootstrap.initialize_network(store,path)
    assert result['state']=='waiting_selection'
    assert store.network()==NetworkConfig()


@pytest.mark.parametrize('selector',['interface = 管理网卡','physical_id = physical-1','mac = aa:bb:cc:dd:ee:ff'])
def test_selectors_and_config_only(setup,monkeypatch,selector):
    store,path,_=setup
    write(path,selector+'\nalias = admin0\nip = 192.168.1.1/24\nnic_count = 4\napply_ip = false\n')
    monkeypatch.setattr(bootstrap,'apply_management',lambda *_:pytest.fail('config-only must not touch OS'))
    result=bootstrap.initialize_network(store,path)
    assert result['state']=='completed'
    assert store.network().interfaces[0].alias=='admin0'
    assert store.network().interfaces[0].physical_id=='physical-1'
    assert store.network().nic_count==4
    assert store.events()[0]['rule_id']=='MGRNIC_INIT'


def test_ip_apply_and_one_time_import(setup,monkeypatch):
    store,path,inventory=setup
    write(path,'interface = 管理网卡\n')
    calls=[]
    def apply(config,nics):
        calls.append(config.management_cidr)
        inventory[0]['ipv4']=[config.management_cidr]
    monkeypatch.setattr(bootstrap,'apply_management',apply)
    assert bootstrap.initialize_network(store,path)['state']=='completed'
    path.write_text('broken content',encoding='utf-8')
    assert bootstrap.initialize_network(store,path)['state']=='completed'
    assert calls==['192.168.1.1/24']
    # A subsequent boot restores the saved IP even though the INI is no longer valid.
    inventory[0]['ipv4']=[]
    assert bootstrap.initialize_network(store,path)['state']=='completed'
    assert calls==['192.168.1.1/24']*2


def test_permission_failure_retried(setup,monkeypatch):
    store,path,_=setup
    write(path,'interface = 管理网卡\n')
    monkeypatch.setattr(bootstrap,'apply_management',lambda *_:(_ for _ in ()).throw(PermissionError('need admin')))
    result=bootstrap.initialize_network(store,path)
    assert result['state']=='pending_ip'
    assert result['last_error']=='need admin'
    assert store.network().interfaces[0].physical_id=='physical-1'
    monkeypatch.setattr(bootstrap,'apply_management',lambda *_:None)
    assert bootstrap.initialize_network(store,path)['state']=='completed'


def test_pending_ini_can_be_corrected(setup,monkeypatch):
    store,path,_=setup
    write(path,'interface = 管理网卡\n')
    monkeypatch.setattr(bootstrap,'apply_management',lambda *_:(_ for _ in ()).throw(PermissionError('need admin')))
    bootstrap.initialize_network(store,path)
    write(path,'interface = 管理网卡\nip = 192.168.2.1/24\napply_ip = false\n')
    assert bootstrap.initialize_network(store,path)['state']=='completed'
    assert store.network().management_cidr=='192.168.2.1/24'


def test_existing_and_manual_changes_preserved(setup,monkeypatch):
    store,path,_=setup
    write(path,'interface = 管理网卡\n')
    network=store.network();network.management_cidr='192.168.5.1/24';store.save_network(network)
    monkeypatch.setattr(bootstrap,'adapters',lambda:pytest.fail('Existing configuration must be preserved'))
    assert bootstrap.initialize_network(store,path)['state']=='skipped_existing'
    assert store.network()==network


def test_gui_changes_after_failed_init_preserved(setup,monkeypatch):
    store,path,_=setup
    write(path,'interface = 管理网卡\n')
    monkeypatch.setattr(bootstrap,'apply_management',lambda *_:(_ for _ in ()).throw(PermissionError('need admin')))
    bootstrap.initialize_network(store,path)
    config=store.network();config.management_cidr='192.168.6.1/24';store.save_network(config)
    assert bootstrap.initialize_network(store,path)['state']=='skipped_changed'
    assert store.network()==config


@pytest.mark.parametrize('text',[
    'interface = missing',
    'interface = 管理网卡\nphysical_id = physical-1',
    'mac = INVALID',
    'ip = 127.0.0.1/8',
    'ip = 192.168.1.0/24',
    'nic_count = 33',
    'nic_count = 0',
    'apply_ip = maybe',
    'alias = INVALID ALIAS',
    'interfaec = 管理网卡',
    'interface = 管理网卡\ninterface = 管理网卡',
])
def test_invalid_config_leaves_network_unchanged(setup,monkeypatch,text):
    store,path,_=setup
    write(path,text)
    monkeypatch.setattr(bootstrap,'apply_management',lambda *_:pytest.fail('Invalid config must not be applied'))
    assert bootstrap.initialize_network(store,path)['state']=='error'
    assert store.network()==NetworkConfig()


def test_ambiguous_hardware_rejected(setup):
    store,path,inventory=setup
    write(path,'mac = AA:BB:CC:DD:EE:FF')
    inventory.append({**inventory[0],'id':'physical-2'})
    assert bootstrap.initialize_network(store,path)['state']=='error'


def test_missing_file_can_be_fixed(setup):
    store,path,_=setup
    assert bootstrap.initialize_network(store,path)['state']=='error'
    write(path,'interface = 管理网卡\napply_ip = false')
    assert bootstrap.initialize_network(store,path)['state']=='completed'


def test_transaction_refuses_concurrent_changes(setup):
    store,_,_=setup
    expected=store.network()
    config=store.network();config.management_cidr='192.168.8.1/24';store.save_network(config)
    with pytest.raises(ValueError):store.import_bootstrap_network(expected,expected,{'state':'completed'})
    assert store.network()==config
    assert not store.bootstrap_state()


def test_cli_init_reads_ini_when_credentials_already_exist(tmp_path,monkeypatch):
    from waf import cli
    env=tmp_path/'.env'
    env.write_text('WAF_ADMIN_USER=existing-admin\nWAF_ADMIN_PASSWORD=retain-me\n',encoding='utf-8')
    path=tmp_path/'mgrnic.ini'
    write(path,'interface = mgmt-device\napply_ip = false\n')
    monkeypatch.setattr(cli,'ROOT',tmp_path)
    monkeypatch.setattr(cli,'protect',lambda *_:None)
    database=tmp_path/'runtime/test.db'
    monkeypatch.setenv('WAF_DATABASE',str(database))
    monkeypatch.setattr(bootstrap,'adapters',lambda:[{'id':'device-1','name':'mgmt-device','ipv4':[]}])
    assert cli.initialize()['state']=='completed'
    assert 'retain-me' in env.read_text(encoding='utf-8')
    assert Store(database).network().interfaces[0].physical_id=='device-1'
