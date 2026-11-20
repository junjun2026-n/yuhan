# ============================================================
# 文件名称：verify_traffic_map.py
# 生成日期：2026-11-05
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 verify_traffic_map 模块相关功能。
#           文件用途：供WAF的 yuhan/tools/verify_traffic_map.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Verify the map against isolated traffic; never writes to deployed databases."""
import base64
import os
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
import sys
from pathlib import Path
sys.path.insert(0,str(Path.cwd()/'tests'))
from waf.main import create_app
from waf import accounts
from test_traffic_map import assert_map
import uvicorn
app=create_app('admin',database=sys.argv[1]);assert_map(app.state.store)
for i in range(180):
    app.state.store.event('map-'+str(i),'8.8.4.'+str(i+1),'GET','/','allowed','',200,'app.example.com')
accounts.change(app.state.store,'summary',accounts.UserInput(username='summary',password='summary-password',role='custom',permissions=['overview']),create=True)
uvicorn.run(app,host='127.0.0.1',port=int(sys.argv[2]),log_level='error')
"""
    with tempfile.TemporaryDirectory(prefix='waf-traffic-map-') as folder:
        env={**os.environ,'WAF_ADMIN_USER':'admin','WAF_ADMIN_PASSWORD':'map-test-password','WAF_LOG_SENDER':'0'}
        log=Path(folder)/'server.log'
        with log.open('w') as output:
            process=subprocess.Popen([str(ROOT/'.venv/Scripts/python.exe'),'-c',code,str(Path(folder)/'test.db'),str(port)],cwd=ROOT,env=env,stdout=output,stderr=subprocess.STDOUT)
            try:
                for _ in range(100):
                    try:
                        request=urllib.request.Request(base+'/api/stats/traffic-map',headers={'Authorization':'Basic '+base64.b64encode(b'admin:map-test-password').decode()})
                        urllib.request.urlopen(request,timeout=1);break
                    except OSError:time.sleep(.2)
                else:raise AssertionError(log.read_text())
                with sync_playwright() as p:
                    browser=p.chromium.launch(channel='msedge',headless=True)
                    context=browser.new_context(http_credentials={'username':'admin','password':'map-test-password'},viewport={'width':1440,'height':1000})
                    page=context.new_page();errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
                    page.goto(base);page.wait_for_load_state('networkidle')
                    expect(page.locator('#open-traffic-map')).to_be_visible()
                    page.locator('#open-traffic-map').click();expect(page.locator('#traffic-map-dialog')).to_be_visible()
                    page.wait_for_function('document.fullscreenElement === document.documentElement')
                    expect(page.locator('#map-fullscreen-hint')).to_be_hidden()
                    expect(page.locator('#map-source-list button')).to_have_count(150)
                    expect(page.locator('#map-updated')).to_contain_text('更新于')
                    page.wait_for_timeout(400)
                    assert page.locator('#traffic-map-dialog').evaluate('(el)=>el.clientWidth>=window.innerWidth-2')
                    # A real basemap and connection drawing must reach the canvas.
                    assert page.locator('#traffic-map-canvas').evaluate('(el)=>{const c=el.getContext("2d"),d=c.getImageData(0,0,el.width,el.height).data;let n=0;for(let i=3;i<d.length;i+=4)if(d[i])n++;return n>10000;}')
                    page.locator('#map-source-list button').first.click();expect(page.locator('#map-detail')).to_contain_text('8.8.8.8')
                    page.locator('#map-zoom-in').click();page.locator('#map-zoom-out').click();page.locator('#map-reset').click()
                    page.screenshot(path=str(ROOT/'runtime/traffic-map-desktop.png'))
                    page.locator('#map-detail button').click();expect(page.locator('#traffic-map-dialog')).not_to_be_visible()
                    page.wait_for_function('!document.fullscreenElement')
                    expect(page.locator('#page-label')).to_contain_text('共 5 条')
                    page.locator('[data-tab=overview]').click();page.locator('#open-traffic-map').click()
                    page.locator('#map-limit').select_option('50');expect(page.locator('#map-source-list button')).to_have_count(50)
                    page.locator('#map-period').select_option('24h');expect(page.locator('#map-updated')).to_contain_text('更新于')
                    page.route('**/api/stats/traffic-map?*',lambda route:route.fulfill(status=503,content_type='application/json',body='{"detail":"test map failure"}'))
                    page.locator('#map-refresh').click();expect(page.locator('#map-status')).to_contain_text('更新失败')
                    expect(page.locator('#map-source-list button')).to_have_count(50)
                    page.unroute('**/api/stats/traffic-map?*');page.locator('#map-refresh').click();expect(page.locator('#map-updated')).to_contain_text('更新于')
                    page.locator('#map-close').click();expect(page.locator('#traffic-map-dialog')).not_to_be_visible()
                    page.wait_for_function('!document.fullscreenElement')
                    # If fullscreen is denied, explain the visible browser chrome and
                    # let a fresh user gesture retry; never silently claim fullscreen.
                    page.evaluate('''() => {window.originalMapFullscreen=document.documentElement.requestFullscreen;
                        document.documentElement.requestFullscreen=()=>Promise.reject(new Error('test fullscreen denial'));}''')
                    page.locator('#open-traffic-map').click()
                    expect(page.locator('#map-fullscreen-hint')).to_be_visible()
                    assert not page.evaluate('Boolean(document.fullscreenElement)')
                    page.evaluate('() => {document.documentElement.requestFullscreen=window.originalMapFullscreen;}')
                    page.locator('#map-fullscreen').click()
                    page.wait_for_function('document.fullscreenElement === document.documentElement')
                    expect(page.locator('#map-fullscreen-hint')).to_be_hidden()
                    page.evaluate('document.exitFullscreen()')
                    expect(page.locator('#traffic-map-dialog')).not_to_be_visible()
                    page.set_viewport_size({'width':480,'height':900});page.locator('#open-traffic-map').click()
                    expect(page.locator('#map-source-list button')).to_have_count(50)
                    assert page.locator('#traffic-map-dialog').evaluate('(el)=>el.scrollWidth<=el.clientWidth+1')
                    page.screenshot(path=str(ROOT/'runtime/traffic-map-mobile.png'))
                    page.locator('#map-close').click();page.locator('[data-tab=settings]').click();expect(page.locator('#open-traffic-map')).to_be_hidden()
                    summary=browser.new_context(http_credentials={'username':'summary','password':'summary-password'})
                    restricted=summary.new_page();restricted.goto(base);restricted.wait_for_load_state('networkidle');restricted.locator('#open-traffic-map').click()
                    expect(restricted.locator('#map-source-list button')).to_have_count(150)
                    restricted.locator('#map-source-list button').first.click();expect(restricted.locator('#map-detail button')).to_have_count(0)
                    assert not errors,errors
                    print('PASS document fullscreen, hidden browser navigation request, fullscreen denial/retry/exit, basemap, 150 sources, zoom, drill-down, filters, failure recovery, mobile and permissions')
                    browser.close()
            finally:
                if process.poll() is None:subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                process.wait(15)


if __name__=='__main__':main()
