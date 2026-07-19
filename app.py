"""
用户管理系统 - 安全加固版本

防护措施：
  1. Debug 模式关闭
  2. Secret Key 随机生成
  3. 密码 scrypt 加盐哈希存储
  4. SVG 数学验证码（纯 Python 生成）
  5. IP 速率限制 30 次/分钟（登录接口 10 次/分钟）
  6. 账户连续 5 次失败锁定 5 分钟
  7. 渐进式延迟（每次失败 +0.5s，上限 3s）
  8. CSRF Token 一次性使用
  9. 参数污染防护
  10. Content-Type 校验
  11. Session 安全：登录刷新 ID + 30 分钟过期
  12. 统一错误提示
  13. /admin 角色校验
"""

import os
import random
import time
import secrets
from datetime import timedelta

from flask import (
    Flask, render_template, request, redirect, session, abort
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

# ─── 应用初始化 ────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

# ─── 速率限制 ──────────────────────────────────────────────────────────

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["30 per minute"],
    storage_uri="memory://",
)

# ─── 用户数据库（密码使用 scrypt 加盐哈希存储） ────────────────────────

USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}

# ─── 账户锁定记录 ──────────────────────────────────────────────────────
# login_attempts[username] = {"fail_count": int, "lock_time": float|None}

login_attempts = {}
MAX_FAILS = 5
LOCK_MINUTES = 5


# ─── SVG 数学验证码 ────────────────────────────────────────────────────

def generate_captcha():
    """生成 1-10 以内的加减法，返回 (算式字符串, 正确答案, SVG_HTML)"""
    a = random.randint(1, 10)
    b = random.randint(1, 10)
    op = random.choice(["+", "-"])

    if op == "+":
        answer = a + b
    else:
        if a < b:
            a, b = b, a
        answer = a - b

    expression = f"{a} {op} {b}"

    # SVG 验证码图片
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="140" height="44" viewBox="0 0 140 44">
  <rect width="140" height="44" fill="#f0f4ff" rx="8" ry="8"/>
  <text x="70" y="30" text-anchor="middle" font-size="22"
        font-family="monospace" font-weight="bold"
        fill="#667eea" letter-spacing="3">{expression}</text>
</svg>'''

    return expression, answer, svg


# ─── 账户锁定 ──────────────────────────────────────────────────────────

def is_account_locked(username):
    """检查账户是否被锁定"""
    record = login_attempts.get(username)
    if not record:
        return False
    lock_time = record.get("lock_time")
    if lock_time is None:
        return False
    if time.time() - lock_time > LOCK_MINUTES * 60:
        del login_attempts[username]
        return False
    return True


def record_fail(username):
    """记录登录失败"""
    now = time.time()
    if username not in login_attempts:
        login_attempts[username] = {"fail_count": 0, "lock_time": None}
    login_attempts[username]["fail_count"] += 1
    if login_attempts[username]["fail_count"] >= MAX_FAILS:
        login_attempts[username]["lock_time"] = now


def clear_attempts(username):
    """登录成功清除失败记录"""
    login_attempts.pop(username, None)


# ─── Content-Type 校验 ─────────────────────────────────────────────────

@app.before_request
def check_content_type():
    """拦截非表单 POST 请求"""
    if request.method == "POST":
        ct = (request.content_type or "").lower()
        allowed = ["application/x-www-form-urlencoded", "multipart/form-data"]
        if ct and not any(ct.startswith(a) for a in allowed):
            return {"error": "不支持的 Content-Type"}, 400


# ─── 首页 ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    username = session.get("user")
    user_info = None
    if username and username in USERS:
        user_info = dict(USERS[username])
        del user_info["password"]  # 不传递密码字段
    return render_template("index.html", user=user_info)


# ─── 登录 ──────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        return handle_login_post()
    return handle_login_get()


def handle_login_get():
    """GET 登录页：生成验证码和 CSRF Token"""
    expr, answer, svg = generate_captcha()
    session["captcha_answer"] = answer
    session["csrf_token"] = secrets.token_hex(16)
    return render_template(
        "login.html",
        captcha_svg=svg,
        csrf_token=session["csrf_token"],
    )


# 登录 POST 单独加速率限制（10 次/分钟）
@limiter.limit("10 per minute")
def handle_login_post():
    """登录 POST：安全检查链条"""

    # 1. 参数污染防护
    username = request.form.get("username")
    password = request.form.get("password")

    if username is None or password is None:
        return render_template("login.html", captcha_svg="", csrf_token="", error="非法请求参数"), 400
    if not isinstance(username, str) or not isinstance(password, str):
        return render_template("login.html", captcha_svg="", csrf_token="", error="非法请求参数"), 400

    username = username.strip()

    # 2. CSRF 校验
    csrf_token = request.form.get("csrf_token", "")
    stored_token = session.pop("csrf_token", None)
    if not stored_token or csrf_token != stored_token:
        return render_template("login.html", captcha_svg="", csrf_token="", error="非法请求参数"), 400

    # 3. 验证码校验
    user_answer = request.form.get("captcha", "")
    correct_answer = session.pop("captcha_answer", None)
    if correct_answer is None:
        return redirect("/login")
    try:
        if int(user_answer) != correct_answer:
            # 验证码错误时重新生成新验证码
            expr, ans2, svg2 = generate_captcha()
            session["captcha_answer"] = ans2
            session["csrf_token"] = secrets.token_hex(16)
            return render_template("login.html", captcha_svg=svg2, csrf_token=session["csrf_token"], error="验证码错误"), 401
    except (ValueError, TypeError):
        expr, ans2, svg2 = generate_captcha()
        session["captcha_answer"] = ans2
        session["csrf_token"] = secrets.token_hex(16)
        return render_template("login.html", captcha_svg=svg2, csrf_token=session["csrf_token"], error="验证码错误"), 401

    # 4. 账户锁定检查
    if is_account_locked(username):
        remaining = LOCK_MINUTES
        lock_record = login_attempts.get(username, {})
        lock_time = lock_record.get("lock_time")
        if lock_time:
            remaining = int(LOCK_MINUTES - (time.time() - lock_time) / 60)
            if remaining < 0:
                remaining = 0
        expr, ans2, svg2 = generate_captcha()
        session["captcha_answer"] = ans2
        session["csrf_token"] = secrets.token_hex(16)
        return render_template(
            "login.html", captcha_svg=svg2, csrf_token=session["csrf_token"],
            error=f"账户已锁定，请 {remaining} 分钟后再试"
        ), 401

    # 5. 渐进式延迟
    fail_count = login_attempts.get(username, {}).get("fail_count", 0)
    delay = min(fail_count * 0.5, 3.0)
    if delay > 0:
        time.sleep(delay)

    # 6. 密码验证
    user = USERS.get(username)
    is_valid = user is not None and check_password_hash(user["password"], password)

    if is_valid:
        # 验证通过：刷新 Session
        session.clear()
        session["user"] = username
        session["role"] = user["role"]
        session.permanent = True
        clear_attempts(username)
        return redirect("/")

    # 验证失败
    record_fail(username)
    expr, ans2, svg2 = generate_captcha()
    session["captcha_answer"] = ans2
    session["csrf_token"] = secrets.token_hex(16)
    return render_template(
        "login.html", captcha_svg=svg2, csrf_token=session["csrf_token"],
        error="用户名或密码错误"
    ), 401


# ─── 登出 ──────────────────────────────────────────────────────────────

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ─── 管理员面板 ─────────────────────────────────────────────────────────

@app.route("/admin")
def admin_panel():
    if session.get("role") != "admin":
        abort(403)
    return render_template("admin.html", username=session.get("user", ""))


# ─── 启动 ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
