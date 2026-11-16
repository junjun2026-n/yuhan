import pytest

from waf import bootstrap
from waf.network import NetworkConfig
from waf.store import Store


@pytest.fixture
def environment(tmp_path,monkeypatch):
    store=Store(tmp_path/'network.db')
    path=tmp_path/'mgrnic.ini'
    inventory=[dict(id='mgmt-id',name='ens33',mac='00:11:22:33:44:01',ipv4=[],status='UP'),
               dict(id='business-1',name='ens34',mac='00:11:22:33:44:02',ipv4=[],status='DOWN'),
               dict(id='business-2',name='ens35',mac='00:11:22:33:44:03',ipv4=[],status='DOWN')]
    calls=[]
    monkeypatch.setattr(bootstrap,'adapters',lambda:inventory)
    monkeypatch.setattr(bootstrap,'ensure_business_link_up',lambda nic:calls.append(nic['name']))
    monkeypatch.setattr(bootstrap,'apply_management',lambda *_:pytest.fail('Management IP must not change'))
    return store,path,inventory,calls


def write(path,business,management='interface=ens33\napply_ip=false\nnic_count=3'):
    path.write_text('[management]\n'+management+'\n'+business,encoding='utf-8')


def test_business_interface_and_mac_loaded_and_restored(environment):
    store,path,inventory,calls=environment
    write(path,'[business:port1]\ninterface=ens34\n[ business:port2 ]\nmac=00-11-22-33-44-03'.replace('[ business:port2 ]','[business:port2]'))
    state=bootstrap.initialize_network(store,path)
    assert state['state']=='completed' and state['business']['state']=='completed'
    assert [nic.physical_id for nic in store.network().interfaces]==['mgmt-id','business-1','business-2']
    assert calls==['ens34','ens35']
    assert store.network().deployment_mode=='proxy'
    inventory[1]['name']='renamed-business'
    state=bootstrap.initialize_network(store,path)
    assert state['business']['state']=='completed'
    assert calls[-2:]==['renamed-business','ens35']
    assert len([event for event in store.events() if event['rule_id']=='BUSINESS_NIC_INIT'])==1


def test_existing_management_and_deployment_mode_preserved(environment):
    store,path,_,calls=environment
    write(path,'')
    bootstrap.initialize_network(store,path)
    current=store.network();current.management_cidr='192.168.17.126/24';current.deployment_mode='bypass'
    store.save_network(current)
    write(path,'[business:port1]\nphysical_id=business-1\nbring_up=false',management='interface=missing-management\nip=192.168.99.1/24')
    result=bootstrap.initialize_network(store,path)
    assert result['business']['state']=='completed'
    assert store.network().management_cidr=='192.168.17.126/24'
    assert store.network().deployment_mode=='bypass'
    assert store.network().interfaces[0].physical_id=='mgmt-id'
    assert store.network().interfaces[1].physical_id=='business-1'
    assert not calls


@pytest.mark.parametrize('business',[
    '[business:port1]\ninterface=ens33',
    '[business:port1]\ninterface=ens34\n[ business:port2 ]\ninterface=ens34',
    '[business:port1]\ninterface=ens34\n[ business:port2 ]\ninterface=missing',
])
def test_atomic_business_bindings_reject_missing_and_shared_nics(environment,business):
    store,path,_,calls=environment
    write(path,'');bootstrap.initialize_network(store,path)
    previous=store.network()
    write(path,business.replace('[ business:port2 ]','[business:port2]'))
    result=bootstrap.initialize_network(store,path)
    assert result['business']['state']=='error'
    assert store.network()==previous and not calls


def test_addressed_business_nic_is_rejected(environment):
    store,path,inventory,calls=environment
    write(path,'');bootstrap.initialize_network(store,path)
    previous=store.network()
    inventory[1]['ipv4']=['10.10.0.1/24']
    write(path,'[business:port1]\ninterface=ens34')
    assert bootstrap.initialize_network(store,path)['business']['state']=='error'
    assert store.network()==previous and not calls


def test_manual_binding_change_preserved_until_ini_changes(environment):
    store,path,_,calls=environment
    write(path,'[business:port1]\ninterface=ens34')
    bootstrap.initialize_network(store,path)
    current=store.network();current.interfaces[1].physical_id='business-2';store.save_network(current)
    calls.clear()
    assert bootstrap.initialize_network(store,path)['business']['state']=='skipped_changed'
    assert store.network()==current and not calls
    write(path,'[business:port1]\nphysical_id=business-1')
    assert bootstrap.initialize_network(store,path)['business']['state']=='completed'
    assert store.network().interfaces[1].physical_id=='business-1'


def test_link_failure_can_retry_without_losing_management(environment,monkeypatch):
    store,path,_,_=environment
    write(path,'[business:port1]\ninterface=ens34')
    def fail(_): raise PermissionError('need root')
    monkeypatch.setattr(bootstrap,'ensure_business_link_up',fail)
    result=bootstrap.initialize_network(store,path)
    assert result['state']=='completed' and result['business']['state']=='error'
    assert store.network().interfaces[0].physical_id=='mgmt-id'
    monkeypatch.setattr(bootstrap,'ensure_business_link_up',lambda *_:None)
    assert bootstrap.initialize_network(store,path)['business']['state']=='completed'


@pytest.mark.parametrize('business',[
    '[business:port1]\ninterface=ens34\nmac=00:11:22:33:44:02',
    '[business:port1]\nbring_up=maybe',
    '[business:INVALID]\ninterface=ens34',
    '[business:port1]\ninterfaec=ens34',
])
def test_invalid_business_ini_does_not_import_any_network(environment,business):
    store,path,_,calls=environment
    write(path,business)
    assert bootstrap.initialize_network(store,path)['state']=='error'
    assert store.network()==NetworkConfig() and not calls
