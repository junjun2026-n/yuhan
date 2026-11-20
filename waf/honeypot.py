# ============================================================
# 文件名称：honeypot.py
# 生成日期：2026-11-18
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 honeypot 模块相关功能。
#           文件用途：供WAF的 yuhan/waf/honeypot.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Bounded forwarding of rejected attack requests to an isolated decoy."""
import anyio
import httpx
from starlette.responses import Response


async def forward(client, request, body, address, ip, request_id, rule):
    from .main import HOP
    tokens = set(request.headers.get('connection', '').lower().replace(' ', '').split(','))
    excluded = HOP | tokens | {'host', 'authorization', 'cookie', 'forwarded'}
    headers = [(k, v) for k, v in request.headers.items()
               if k.lower() not in excluded and not k.lower().startswith(('x-forwarded-', 'x-waf-'))]
    headers.extend([('X-Forwarded-For', ip), ('X-WAF-Request-ID', request_id), ('X-WAF-Rule', rule)])
    path = request.scope.get('raw_path', b'/').decode('ascii')
    suffix = path + ('?' + request.url.query if request.url.query else '')
    try:
        with anyio.fail_after(5):
            async with client.stream(request.method, address + suffix, headers=headers, content=body) as upstream:
                payload = bytearray()
                async for chunk in upstream.aiter_raw():
                    payload.extend(chunk)
                    if len(payload) > 2 * 1024 * 1024:
                        return None
                # Never expose a decoy redirect or create a browser session on behalf of the real site.
                if 300 <= upstream.status_code < 400 or upstream.status_code >= 500:
                    return None
                response = Response(bytes(payload), status_code=upstream.status_code)
                response_tokens = set(upstream.headers.get('connection', '').lower().replace(' ', '').split(','))
                response.raw_headers = [(k, v) for k, v in upstream.headers.raw
                                        if k.decode().lower() not in HOP | response_tokens | {'set-cookie', 'location'}]
                response.headers['X-WAF-Request-ID'] = request_id
                response.headers['Cache-Control'] = 'no-store'
                return response
    except (httpx.HTTPError, TimeoutError, ValueError):
        return None
