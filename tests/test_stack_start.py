from pathlib import Path
import pytest
from waf import stack_start


def test_database_password_is_read_from_secret(monkeypatch):
    monkeypatch.setattr(Path, 'read_text', lambda *args, **kwargs: 'private-test-value\n')
    calls=[]
    monkeypatch.setattr(stack_start.os, 'execvp', lambda *args: calls.append(args))
    monkeypatch.setenv('WAF_DB_PASSWORD', 'previous')
    stack_start.main()
    assert stack_start.os.environ['WAF_DB_PASSWORD']=='private-test-value'
    assert calls==[('python', ['python','-m','waf.cli','serve'])]


def test_empty_secret_stops_startup(monkeypatch):
    monkeypatch.setattr(Path, 'read_text', lambda *args, **kwargs: '\n')
    with pytest.raises(SystemExit, match='empty'):
        stack_start.main()
