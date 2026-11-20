# ============================================================
# 文件名称：test_development.py
# 生成日期：2026-10-27
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：验证 development 相关功能。
#           文件用途：用于开发验证及功能回归。
#           注意事项：使用隔离测试环境，避免操作正式业务数据。
# ============================================================
import tarfile

from tools import deploy, dev
from waf import cli


def test_release_excludes_private_runtime_and_network_profile(tmp_path):
    archive = tmp_path/'source.tar.gz'
    digest = deploy.package(archive)
    assert len(digest) == 64
    with tarfile.open(archive) as package:
        names = package.getnames()
        assert 'waf/main.py' in names and 'tools/update-server.sh' in names
        assert not any(name.startswith(('runtime/','.venv/','packages/')) for name in names)
        assert 'mgrnic.ini' not in names and '.env' not in names
        assert not any(name.endswith(('.key','.sqlite3','.env')) for name in names)


def test_development_ignores_production_connection_and_auth(monkeypatch,tmp_path):
    monkeypatch.setattr(dev,'ROOT',tmp_path)
    monkeypatch.setenv('WAF_ADMIN_PASSWORD','production-secret')
    monkeypatch.setenv('WAF_DATABASE_CONFIG','production-config.env')
    monkeypatch.setenv('WAF_DB_ENGINE','postgresql')
    profile=tmp_path/'runtime/dev/database.postgresql.env'
    profile.parent.mkdir(parents=True)
    profile.write_text('WAF_DB_ENGINE=postgresql\nWAF_DB_HOST=dev-db\nWAF_DB_NAME=waf_dev\n',encoding='utf-8')
    def run(command,cwd,env):
        assert cwd == tmp_path
        assert 'WAF_ADMIN_PASSWORD' not in env
        assert env['WAF_DB_ENGINE'] == 'postgresql'
        assert (tmp_path/'runtime/dev/database.env').read_text(encoding='utf-8') == profile.read_text(encoding='utf-8')
        assert env['WAF_DATABASE_CONFIG'] == str(tmp_path/'runtime/dev/database.env')
        assert env['WAF_DATAPLANE_AUTOSTART'] == '0'
        assert env['WAF_TLS_RUNTIME'] == str(tmp_path/'runtime/dev/tls')
        return 0
    monkeypatch.setattr(dev.subprocess,'call',run)
    assert dev.main() == 0


def test_development_skips_host_network_initialization(monkeypatch):
    monkeypatch.setenv('WAF_DEV_MODE','1')
    assert cli.initialize_management() == {'state':'development'}
