"""Read-only checks for the offline public request map on an existing service."""
import argparse
from pathlib import Path

from playwright.sync_api import sync_playwright,expect

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base',default='http://192.168.17.126:8301')
    parser.add_argument('--credentials',type=Path,default=ROOT/'runtime/192.168.17.126-initial-admin.txt')
    args=parser.parse_args()
    values=dict(line.split(': ',1) for line in args.credentials.read_text(encoding='utf-8').splitlines() if ': ' in line)
    with sync_playwright() as p:
        browser=p.chromium.launch(channel='msedge',headless=True)
        context=browser.new_context(http_credentials={'username':values['Username'],'password':values['Password']},viewport={'width':1440,'height':1000})
        page=context.new_page();errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
        page.goto(args.base);page.wait_for_load_state('networkidle')
        expect(page.locator('#open-traffic-map')).to_be_visible()
        page.locator('#open-traffic-map').click();expect(page.locator('#traffic-map-dialog')).to_be_visible()
        page.wait_for_function('document.fullscreenElement === document.documentElement')
        expect(page.locator('#map-fullscreen-hint')).to_be_hidden()
        expect(page.locator('#map-updated')).to_contain_text('更新于',timeout=20000)
        result=context.request.get(args.base+'/api/stats/traffic-map?period=all').json()
        assert result['location_precision']=='country' and result['metric']=='requests'
        assert len(context.request.get(args.base+'/world-map.json').json()['features'])==177
        expect(page.locator('#map-metrics>div')).to_have_count(5)
        if page.locator('#map-source-list button').count():
            page.locator('#map-source-list button').first.click();expect(page.locator('#map-detail strong')).to_be_visible()
        page.locator('#map-zoom-in').click();page.locator('#map-reset').click();page.locator('#map-refresh').click()
        expect(page.locator('#map-updated')).to_contain_text('更新于')
        page.locator('#map-close').click();expect(page.locator('#traffic-map-dialog')).not_to_be_visible()
        page.wait_for_function('!document.fullscreenElement')
        assert not errors,errors
        print('PASS deployed offline world map, public-source aggregation, fullscreen, details, zoom, refresh and close:',args.base)
        browser.close()


if __name__=='__main__':main()
