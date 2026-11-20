# ============================================================
# 文件名称：test_stack_start.py
# 生成日期：2026-10-28
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：验证 stack_start 相关功能。
#           文件用途：用于开发验证及功能回归。
#           注意事项：使用隔离测试环境，避免操作正式业务数据。
# ============================================================
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
