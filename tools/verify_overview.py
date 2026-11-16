"""Exercise overview rankings, drill-down, pagination and permissions in an isolated DB."""
import os
import base64
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.request

from playwright.sync_api import sync_playwright,expect

ROOT=Path(__file__).resolve().parents[1]


def main():
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    base=f'http://127.0.0.1:{port}'
    code="""
import os,sys
from pathlib import Path
sys.path.insert(0,str(Path.cwd()/'tests'))
from waf.main import create_app
from waf import accounts
from test_reporting import seed
import uvicorn
app=create_app('admin',database=sys.argv[1]);seed(app.state.store)
with app.state.store.connect() as db:
    db.execute("UPDATE events SET rule_id='CUSTOM-ui-black',threat_type='blacklist' WHERE request_id IN ('0','1')")
accounts.change(app.state.store,'summary',accounts.UserInput(username='summary',password='summary-password',role='custom',permissions=['overview']),create=True)
uvicorn.run(app,host='127.0.0.1',port=int(sys.argv[2]),log_level='error')
"""
    with tempfile.TemporaryDirectory(prefix='waf-overview-') as folder:
        env={**os.environ,'WAF_ADMIN_USER':'admin','WAF_ADMIN_PASSWORD':'test-password','WAF_LOG_SENDER':'0'}
        log=Path(folder)/'server.log'
        with log.open('w') as output:
            process=subprocess.Popen([str(ROOT/'.venv/Scripts/python.exe'),'-c',code,str(Path(folder)/'test.db'),str(port)],cwd=ROOT,env=env,stdout=output,stderr=subprocess.STDOUT)
            try:
                for _ in range(100):
                    try:
                        request=urllib.request.Request(base+'/api/stats/overview',headers={'Authorization':'Basic '+base64.b64encode(b'admin:test-password').decode()})
                        urllib.request.urlopen(request,timeout=1);break
                    except OSError:time.sleep(.2)
                else:raise AssertionError(log.read_text())
                with sync_playwright() as p:
                    browser=p.chromium.launch(channel='msedge',headless=True)
                    context=browser.new_context(http_credentials={'username':'admin','password':'test-password'},viewport={'width':1440,'height':1100})
                    page=context.new_page();errors=[];page.on('pageerror',lambda error:errors.append(str(error)))
                    page.goto(base);page.wait_for_load_state('networkidle')
                    expect(page.locator('.rank-panel')).to_have_count(9)
                    expect(page.locator('.metric[data-action=business] strong')).to_have_text('12')
                    for action,count in [('blocked','7'),('detected','1'),('allowed','3'),('error','1')]:
                        page.locator('[data-tab=overview]').click()
                        page.locator(f'.metric[data-action={action}]').click()
                        expect(page.locator('#events')).to_be_visible()
                        expect(page.locator('#page-label')).to_contain_text('共 '+count+' 条')
                        assert page.locator('#action').input_value()==action
                    for key,count in [('domains','8'),('external_ips','7'),('countries','7'),('blacklist_ips','2'),('attacks','5'),('rules','5'),('paths','7'),('methods','9'),('statuses','7')]:
                        page.locator('[data-tab=overview]').click()
                        page.locator(f'[data-ranking={key}] button').first.click()
                        expect(page.locator('#page-label')).to_contain_text('共 '+count+' 条')
                    page.locator('#event-page-size').select_option('20')
                    page.locator('#event-filter-clear').click()
                    expect(page.locator('#page-label')).to_contain_text('共 13 条')
                    expect(page.locator('#event-filter-bar')).to_be_hidden()
                    page.locator('[data-tab=overview]').click()
                    page.locator('#overview-period').select_option('24h')
                    expect(page.locator('.metric[data-action=business] strong')).to_have_text('11')
                    expect(page.locator('.metric[data-action=error] strong')).to_have_text('0')
                    page.screenshot(path=str(ROOT/'runtime/overview-top5.png'),full_page=True)
                    for width in (1440,480):
                        page.set_viewport_size({'width':width,'height':1000})
                        assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth'),width
                    summary=browser.new_context(http_credentials={'username':'summary','password':'summary-password'})
                    restricted=summary.new_page();restricted.goto(base);restricted.wait_for_load_state('networkidle')
                    expect(restricted.locator('.metric')).to_have_count(6)
                    assert restricted.locator('.metric:enabled').count()==0
                    expect(restricted.locator('[data-tab=events]')).to_be_hidden()
                    assert not errors,errors
                    print('PASS nine TOP5 rankings, metric/ranking drill-down, scope, permissions, responsive layout, no JS errors')
                    browser.close()
            finally:
                if process.poll() is None:
                    subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                process.wait(15)


if __name__=='__main__':main()
