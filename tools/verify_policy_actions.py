# ============================================================
# 文件名称：verify_policy_actions.py
# 生成日期：2026-11-05
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 verify_policy_actions 模块相关功能。
#           文件用途：供WAF的 yuhan/tools/verify_policy_actions.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Browser regression for policy action states against the isolated dev service."""
import json
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

ROOT=Path(__file__).resolve().parents[1]
BASE='http://127.0.0.1:8401'


def main():
    credentials=dict(line.split(': ',1) for line in (ROOT/'runtime/dev/initial-admin.txt').read_text(encoding='utf-8').splitlines() if ': ' in line)
    with sync_playwright() as p:
        browser=p.chromium.launch(channel='msedge',headless=True)
        context=browser.new_context(http_credentials={'username':credentials['Username'],'password':credentials['Password']})
        original=context.request.get(BASE+'/api/traffic-protection').json()
        page=context.new_page();errors=[];page.on('pageerror',lambda error:errors.append(str(error)))
        headers={'Origin':BASE,'Content-Type':'application/json'}
        try:
            page.goto(BASE);page.wait_for_load_state('networkidle')
            page.locator('[data-tab=rules]').click();page.locator('#tab-rules-custom').click()
            for section in ('cc','ports'):
                initial=page.locator(f'#{section}-list tr[data-rule-id]').count()
                page.locator(f'#{section}-new').click()
                page.locator(f'#{section}-name').fill('action-state-'+section)
                page.locator(f'#{section}-enabled').check()
                page.locator(f'#{section}-target_type').select_option('domain')
                page.locator(f'#{section}-target').fill('action-test.invalid')
                page.locator(f'#{section}-form button[type=submit]').click()
                rows=page.locator(f'#{section}-list tr[data-rule-id]')
                expect(rows).to_have_count(initial+1)
                row=rows.filter(has_text='action-state-'+section)
                expect(row.locator('[data-policy-action=delete]')).to_be_disabled()
                expect(row.locator('[data-policy-action=edit]')).to_be_enabled()
                row.locator('[data-policy-action=edit]').click()
                for action in ('edit','delete','toggle'):
                    expect(row.locator(f'[data-policy-action={action}]')).to_be_disabled()
                page.locator(f'#{section}-reset').click()
                expect(row.locator('[data-policy-action=edit]')).to_be_enabled()
                expect(row.locator('[data-policy-action=delete]')).to_be_disabled()
                row.locator('[data-policy-action=toggle]').click()
                expect(row.get_by_role('button',name='启用',exact=True)).to_be_enabled()
                expect(row.locator('[data-policy-action=delete]')).to_be_enabled()
                row.locator('[data-policy-action=edit]').click()
                expect(row.locator('[data-policy-action=delete]')).to_be_disabled()
                page.locator(f'#{section}-name').fill('saved-state-'+section)
                page.locator(f'#{section}-form button[type=submit]').click()
                row=rows.filter(has_text='saved-state-'+section)
                expect(row.locator('[data-policy-action=edit]')).to_be_enabled()
                expect(row.locator('[data-policy-action=delete]')).to_be_enabled()
                page.once('dialog',lambda dialog:dialog.accept())
                row.locator('[data-policy-action=delete]').click()
                expect(rows).to_have_count(initial)
            assert not errors,errors
            print(json.dumps({'cc_and_ports_action_states':True,'javascript_errors':errors}))
        finally:
            response=context.request.put(BASE+'/api/traffic-protection',headers=headers,data=json.dumps(original))
            assert response.status==200,response.text()
            browser.close()


if __name__=='__main__':main()
