"""Exercise site routing configuration in an isolated browser/database."""
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

import httpx
from playwright.sync_api import sync_playwright, expect


def main():
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix='waf-origins-') as folder:
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        env = dict(os.environ, WAF_ENV_FILE=str(Path(folder)/'missing.env'),
            WAF_DATABASE_CONFIG=str(Path(folder)/'missing-db.env'), WAF_DB_ENGINE='sqlite',
            WAF_DATABASE=str(Path(folder)/'test.db'), WAF_ADMIN_USER='admin',
            WAF_ADMIN_PASSWORD='isolated-test-password', WAF_LOG_SENDER='0',
            WAF_TLS_RUNTIME=str(Path(folder)/'tls'))
        interpreter = root/'.venv'/('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
        server = subprocess.Popen([str(interpreter), '-m', 'uvicorn', 'waf.main:create_admin',
            '--factory', '--host', '127.0.0.1', '--port', str(port)], cwd=root,
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            url = f'http://127.0.0.1:{port}'
            with httpx.Client(trust_env=False) as client:
                for _ in range(100):
                    try:
                        if client.get(url+'/').status_code == 401:
                            break
                    except httpx.HTTPError:
                        pass
                    time.sleep(.1)
                else:
                    raise RuntimeError('Test server did not start')
            with sync_playwright() as p:
                browser = p.chromium.launch(channel='msedge', headless=True)
                page = browser.new_page()
                page.set_default_timeout(30000)
                errors = []
                page.on('pageerror', lambda error: errors.append(str(error)))
                page.goto(url)
                page.locator('#username').fill('admin')
                page.locator('#password').fill('isolated-test-password')
                page.locator('#login-submit').click()
                page.locator('[data-tab=settings]').click()
                expect(page.locator('#rate_limit')).to_have_value('120', timeout=30000)
                page.locator('#protected_domains').fill('one.example.com\ntwo.example.com')
                first = page.locator('#domain-upstream-list textarea[data-domain="one.example.com"]')
                first.fill('http://10.0.0.11:8080\nhttp://10.0.0.12:8080')
                page.locator('#domain-upstream-list textarea[data-domain="two.example.com"]').fill('https://other.example.com')
                page.locator('#add-origin-rule').click()
                rule = page.locator('#origin-rule-list fieldset').first
                rule.locator('[data-field=domain]').fill('one.example.com')
                rule.locator('[data-field=port]').fill('443')
                rule.locator('[data-field=path_prefix]').fill('/api')
                rule.locator('[data-field=origins]').fill('http://10.0.1.1:8080\nhttp://10.0.1.2:8080')
                page.locator('#settings-form button[type=submit]').click()
                expect(page.locator('#message')).to_contain_text('配置已保存', timeout=30000)
                page.reload()
                page.locator('[data-tab=settings]').click()
                expect(page.locator('#rate_limit')).to_have_value('120', timeout=30000)
                expect(first).to_have_value('http://10.0.0.11:8080\nhttp://10.0.0.12:8080')
                expect(page.locator('#origin-rule-list [data-field=path_prefix]')).to_have_value('/api')
                page.locator('#origin-rule-list button').click()
                page.locator('#protected_domains').fill('one.example.com\ntwo.example.com\n*.example.org')
                expect(page.locator('#domain-upstream-list textarea')).to_have_count(3)
                expect(first).to_have_value('http://10.0.0.11:8080\nhttp://10.0.0.12:8080')
                page.locator('#protected_domains').fill('one.example.com')
                expect(page.locator('#domain-upstream-list textarea')).to_have_count(1)
                first.fill('http://10.0.0.13:8080')
                page.locator('#settings-form button[type=submit]').click()
                expect(page.locator('#message')).to_contain_text('配置已保存', timeout=30000)
                value = page.request.get(url+'/api/settings').json()
                assert value['domain_upstreams'] == {'one.example.com':['http://10.0.0.13:8080']}
                for width in (1280, 480):
                    page.set_viewport_size({'width':width,'height':900})
                    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                assert not errors, errors
                page.locator('#logout').click()
                page.wait_for_url('**/login?reason=logout')
                page.reload()
                expect(page.locator('#login-form')).to_be_visible()
                assert page.request.get(url+'/api/me').status == 401
                page.goto(url)
                expect(page.locator('#login-form')).to_be_visible()
                page.locator('#username').fill('admin')
                page.locator('#password').fill('isolated-test-password')
                page.locator('#login-submit').click()
                expect(page.locator('#logout')).to_be_visible()
                assert page.request.get(url+'/api/me').status == 200
                browser.close()
                print('Browser passed: domain configuration, login, logout, reload after logout and re-login; no JS errors.')
        finally:
            server.terminate()
            server.wait(timeout=15)


if __name__ == '__main__':
    main()
