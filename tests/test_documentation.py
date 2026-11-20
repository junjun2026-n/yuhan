# ============================================================
# 文件名称：test_documentation.py
# 生成日期：2026-10-28
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：验证 documentation 相关功能。
#           文件用途：用于开发验证及功能回归。
#           注意事项：使用隔离测试环境，避免操作正式业务数据。
# ============================================================
import re
from pathlib import Path

from fastapi.testclient import TestClient
from waf.main import create_app


def test_authenticated_manual_download(tmp_path, monkeypatch):
    monkeypatch.setenv('WAF_ADMIN_PASSWORD', 'test-password')
    with TestClient(create_app('admin', database=tmp_path/'waf.sqlite3')) as client:
        assert client.get('/api/documentation/user-guide').status_code == 401
        response = client.get('/api/documentation/user-guide', auth=('admin','test-password'))
        assert response.status_code == 200
        assert 'attachment' in response.headers['content-disposition']
        assert 'WAF-USER-GUIDE.md' in response.headers['content-disposition']
        manual = Path(__file__).resolve().parents[1]/'docs/USER_GUIDE.md'
        assert response.content == manual.read_bytes()
        for target in re.findall(r'\]\(([^)]+\.md)\)', manual.read_text(encoding='utf-8')):
            assert (manual.parent/target).is_file(), target
