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
