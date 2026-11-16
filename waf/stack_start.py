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
