# ============================================================
# 文件名称：sessions.py
# 生成日期：2026-11-15
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：管理连接或用户会话数据。
#           文件用途：供WAF的 yuhan/waf/sessions.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
import hashlib
import secrets
import time

COOKIE = 'waf_session'
BLOCK = 'waf_logged_out'
TTL = 8 * 60 * 60


def business_cookie(value):
    return '; '.join(part.strip() for part in value.split(';') if part.strip().split('=',1)[0] not in (COOKIE, BLOCK))


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def issue(store, user):
    token = secrets.token_urlsafe(32)
    with store.connect() as db:
        db.execute('DELETE FROM web_sessions WHERE expires <= ?', (int(time.time()),))
        db.execute('INSERT INTO web_sessions(token,username,password_stamp,expires) VALUES(?,?,?,?)',
                   (digest(token), user['username'], digest(user['password_hash']), int(time.time()) + TTL))
    return token


def resolve(store, token, users):
    with store.connect() as db:
        row = db.execute('SELECT username,password_stamp,expires FROM web_sessions WHERE token=?', (digest(token),)).fetchone()
    if not row or row['expires'] <= time.time():
        return None
    return next((user for user in users if user['username'] == row['username'] and user['enabled']
                 and secrets.compare_digest(digest(user['password_hash']), row['password_stamp'])), None)


def revoke(store, token):
    with store.connect() as db:
        db.execute('DELETE FROM web_sessions WHERE token=?', (digest(token),))
