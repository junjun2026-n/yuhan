# ============================================================
# 文件名称：verify_deployed_overview.py
# 生成日期：2026-11-05
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 verify_deployed_overview 模块相关功能。
#           文件用途：供WAF的 yuhan/tools/verify_deployed_overview.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Read-only overview and list verification for an existing deployment."""
import argparse
from pathlib import Path
from playwright.sync_api import sync_playwright,expect

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base',default='http://192.168.17.126:8301')
    parser.add_argument('--credentials',type=Path,default=ROOT/'runtime/192.168.17.126-initial-admin.txt')
    args=parser.parse_args()
    credentials=dict(line.split(': ',1) for line in args.credentials.read_text(encoding='utf-8').splitlines() if ': ' in line)
    with sync_playwright() as p:
        browser=p.chromium.launch(channel='msedge',headless=True)
        context=browser.new_context(http_credentials={'username':credentials['Username'],'password':credentials['Password']})
        page=context.new_page();errors=[];page.on('pageerror',lambda error:errors.append(str(error)))
        page.goto(args.base);page.wait_for_load_state('networkidle')
        expect(page.locator('.rank-panel')).to_have_count(9)
        result=context.request.get(args.base+'/api/stats/overview').json()
        assert result['geoip_available']
        for action in ('business','blocked','detected','allowed','observed','error'):
            page.locator('[data-tab=overview]').click()
            metric=page.locator(f'.metric[data-action={action}]')
            count=metric.locator('strong').inner_text()
            metric.click()
            expect(page.locator('#events')).to_be_visible()
            expect(page.locator('#page-label')).to_contain_text('共 '+count.replace(',','')+' 条')
            assert page.locator('#action').input_value()==action
        page.locator('[data-tab=overview]').click()
        buttons=page.locator('.rank-panel button')
        if buttons.count():
            count=buttons.first.locator('strong').inner_text().replace(' 次','').replace(',','')
            buttons.first.click();expect(page.locator('#page-label')).to_contain_text('共 '+count+' 条')
        page.locator('[data-tab=overview]').click()
        for width in (1440,480):
            page.set_viewport_size({'width':width,'height':1000})
            assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth'),width
        assert not errors,errors
        print('PASS deployed overview, six metric links, ranking link, country index and responsive layout:',args.base)
        browser.close()


if __name__=='__main__':main()
