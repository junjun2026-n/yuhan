# ============================================================
# 文件名称：stack_start.py
# 生成日期：2026-10-28
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 stack_start 模块相关功能。
#           文件用途：供WAF的 yuhan/waf/stack_start.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Read the Compose database secret without embedding it in container metadata."""
import os
from pathlib import Path


def main():
    secret = Path('/run/secrets/postgres_password').read_text(encoding='utf-8').strip()
    if not secret:
        raise SystemExit('PostgreSQL password secret is empty')
    os.environ['WAF_DB_PASSWORD'] = secret
    os.execvp('python', ['python', '-m', 'waf.cli', 'serve'])


if __name__ == '__main__':
    main()
