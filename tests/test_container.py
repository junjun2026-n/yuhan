from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest
import yaml

from waf import cli, healthcheck, bootstrap
from waf.network import NetworkConfig

ROOT=Path(__file__).resolve().parents[1]


class Worker:
    def __init__(self):
        self.code=None; self.terminated=False; self.killed=False
    def poll(self): return self.code
    def terminate(self): self.terminated=True
    def kill(self): self.killed=True; self.code=-9
    def wait(self,timeout): self.code=0


def test_supervisor_config_switch_and_no_failure_loop(monkeypatch,tmp_path):
    children=[]
    def spawn(args,cwd):
        assert args[-2:]==['-m','waf.dataplane']
        worker=Worker();children.append(worker);return worker
    monkeypatch.setattr(cli.subprocess,'Popen',spawn)
    supervisor=cli.DataPlaneSupervisor(tmp_path)
    config=NetworkConfig()
    supervisor.tick(config)
    assert not children
    config.deployment_mode='inline'
    supervisor.tick(config)
    assert len(children)==1
    supervisor.tick(config)
    assert len(children)==1
    children[-1].code=1
    supervisor.tick(config)
    assert len(children)==1 # Do not repeatedly create / destroy a bridge on a failed configuration.
    config.management_cidr='192.168.2.1/24'
    supervisor.tick(config)
    assert len(children)==2
    config.deployment_mode='proxy'
    supervisor.tick(config)
    assert children[-1].terminated
    assert supervisor.worker is None


def test_supervisor_cleanup_timeout(monkeypatch,tmp_path):
    supervisor=cli.DataPlaneSupervisor(tmp_path)
    worker=Worker()
    def wait(timeout):
        if not worker.killed: raise subprocess.TimeoutExpired('worker',timeout)
        worker.code=-9
    worker.wait=wait
    supervisor.worker=worker
    supervisor.stop()
    assert worker.terminated and worker.killed


def test_credentials_persist_in_writable_runtime(monkeypatch,tmp_path):
    monkeypatch.setattr(cli,'ROOT',tmp_path)
    monkeypatch.setattr(cli,'protect',lambda *_:None)
    monkeypatch.setattr(cli,'initialize_management',lambda:{'state':'waiting_selection'})
    path=tmp_path/'runtime/admin.env'
    monkeypatch.setenv('WAF_ENV_FILE',str(path))
    assert cli.initialize()['state']=='waiting_selection'
    first=path.read_text(encoding='utf-8')
    assert 'WAF_ADMIN_PASSWORD=' in first
    assert not (tmp_path/'.env').exists()
    cli.initialize()
    assert path.read_text(encoding='utf-8')==first
    assert (tmp_path/'runtime/initial-admin.txt').exists()


def test_compose_deployment_contract():
    service=yaml.safe_load((ROOT/'compose.yaml').read_text(encoding='utf-8'))['services']['waf']
    assert service['network_mode']=='host'
    assert 'ports' not in service
    assert not service.get('privileged',False)
    assert {'NET_ADMIN','NET_RAW'} <= set(service['cap_add'])
    assert service['read_only'] is True
    assert service['init'] is True
    mounts={v['target']:v for v in service['volumes']}
    assert mounts['/app/mgrnic.ini']['read_only'] is True
    assert '/app/runtime' in mounts
    assert service['environment']['WAF_ENV_FILE']=='/app/runtime/admin.env'
    assert service['healthcheck']['test'][-1]=='waf.healthcheck'


@pytest.mark.parametrize('running,expected',[(True,True),(False,False)])
def test_health_requires_expected_data_plane(monkeypatch,running,expected):
    monkeypatch.setenv('WAF_ADMIN_PASSWORD','test-password')
    monkeypatch.setenv('WAF_DATAPLANE_AUTOSTART','1')
    monkeypatch.setattr(healthcheck,'load_dotenv',lambda *_:None)
    class Client:
        def __init__(self,**kwargs):pass
        def __enter__(self):return self
        def __exit__(self,*_):pass
        def get(self,url):return SimpleNamespace(status_code=200,json=lambda:{'agent_expected':True,'data_plane_running':running})
    class Socket:
        def __enter__(self):return self
        def __exit__(self,*_):pass
    monkeypatch.setattr(healthcheck.httpx,'Client',Client)
    monkeypatch.setattr(healthcheck.socket,'create_connection',lambda *_args,**_kwargs:Socket())
    assert healthcheck.check() is expected
