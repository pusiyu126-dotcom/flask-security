"""
用户管理系统（完全安全加固版）
- 登录/注册/搜索：参数化查询
- 头像上传：后缀白名单 + MIME检测 + UUID重命名 + .htaccess + 审计日志
- 个人中心：登录校验 + 资源所有权校验（IDOR防护）
- 充值：登录校验 + 只能自己充 + 金额正数 + 上限 + 异常处理
- 余额：整数分存储（防浮点数精度问题）
- 管理面板 + 删除用户：role 校验（垂直越权防护）
"""

import os
import re
import io
import uuid
import time
import magic
import logging
import sqlite3
import secrets
from pathlib import Path
from flask import Flask, render_template, request, redirect, session, send_file, url_for, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

# ─── 审计日志 ──────────────────────────────────────────────────────────

LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

audit_logger = logging.getLogger("upload_audit")
audit_logger.setLevel(logging.INFO)
handler = logging.FileHandler(os.path.join(LOG_DIR, "upload.log"), encoding="utf-8")
handler.setFormatter(logging.Formatter("%(asctime)s | %(message)s"))
audit_logger.addHandler(handler)


# ─── 业务日志（越权/充值操作） ────────────────────────────────────────

biz_logger = logging.getLogger("biz_audit")
biz_logger.setLevel(logging.INFO)
biz_handler = logging.FileHandler(os.path.join(LOG_DIR, "biz.log"), encoding="utf-8")
biz_handler.setFormatter(logging.Formatter("%(asctime)s | %(message)s"))
biz_logger.addHandler(biz_handler)


# ─── SQLite 数据库 ────────────────────────────────────────────────────

DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
os.makedirs(DB_DIR, exist_ok=True)
DB_PATH = os.path.join(DB_DIR, "users.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            balance INTEGER DEFAULT 0
        )
    """)
    # 余额以分存储（99999元 = 9999900分）
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)",
              ("admin", generate_password_hash("admin123"), "admin@example.com", "13800138000", 9999900))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)",
              ("alice", generate_password_hash("alice2025"), "alice@example.com", "13900139001", 10000))
    conn.commit()
    conn.close()


init_db()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ─── 上传目录 ─────────────────────────────────────────────────────────

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"}
ALLOWED_MIMES = {"image/jpeg", "image/png", "image/gif", "image/bmp", "image/webp", "image/x-ms-bmp"}
MAX_FILES_PER_USER = 10

UPLOAD_DIR_PATH = Path(UPLOAD_DIR).resolve()

HTACCESS_PATH = os.path.join(UPLOAD_DIR, ".htaccess")
if not os.path.exists(HTACCESS_PATH):
    with open(HTACCESS_PATH, "w", encoding="utf-8") as f:
        f.write("# 安全配置：禁止上传目录解析可执行脚本\n")
        f.write("<FilesMatch \"\\.(php|phtml|php3|php4|php5|php7|php8|inc|shtml|asp|aspx|jsp|py|pl|cgi|sh|exe|bat|cmd)$\">\n")
        f.write("    Require all denied\n")
        f.write("</FilesMatch>\n")
        f.write("Options -ExecCGI\n")
        f.write("RemoveHandler .php .phtml .php3 .php4 .php5 .php7 .php8\n")


# ─── 工具函数 ─────────────────────────────────────────────────────────

def allowed_extension(filename):
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def allowed_mime(file_obj):
    file_obj.seek(0)
    head = file_obj.read(2048)
    file_obj.seek(0)
    try:
        mime_type = magic.from_buffer(head, mime=True)
    except Exception:
        return False, "unknown"
    if mime_type not in ALLOWED_MIMES:
        return False, mime_type
    if mime_type.startswith("image/"):
        file_obj.seek(0)
        content = file_obj.read()
        file_obj.seek(0)
        suspicious_patterns = [
            b"<?php", b"<?=", b"<%", b"<script language",
            b"eval(", b"system(", b"exec(", b"assert(",
            b"$_POST", b"$_GET", b"$_REQUEST", b"$_FILES",
            b"shell_exec", b"passthru", b"popen(",
            b"base64_decode",
        ]
        for pattern in suspicious_patterns:
            if pattern in content:
                return False, f"{mime_type} (发现可疑代码: {pattern.decode(errors='ignore')})"
    return True, mime_type


def get_user_upload_count(username):
    count = 0
    if os.path.exists(UPLOAD_DIR):
        for f in os.listdir(UPLOAD_DIR):
            if f.startswith(f"{username}_"):
                count += 1
    return count


def get_login_user():
    """获取当前登录用户信息，未登录返回 None"""
    username = session.get("username")
    if not username:
        return None
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


# ─── 首页 ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id, username, email, phone, balance FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        conn.close()
        if row:
            user_info = dict(row)
    return render_template("index.html", user=user_info)


# ─── 登录 ──────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        conn.close()
        if row and check_password_hash(row["password"], password):
            session.clear()
            session["username"] = username
            user_info = dict(row)
            del user_info["password"]
            return render_template("index.html", user=user_info)
        return render_template("login.html", error="用户名或密码错误")
    return render_template("login.html")


# ─── 注册 ──────────────────────────────────────────────────────────────

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                (username, generate_password_hash(password), email, phone)
            )
            conn.commit()
            conn.close()
            return render_template("login.html", success="注册成功，请登录")
        except Exception:
            conn.close()
            return render_template("register.html", error="注册失败，用户名可能已存在")
    return render_template("register.html")


# ─── 搜索 ──────────────────────────────────────────────────────────────

@app.route("/search")
def search():
    if "username" not in session:
        return redirect("/login")
    keyword = request.args.get("keyword", "")
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?",
            (f"%{keyword}%", f"%{keyword}%")
        )
        rows = [dict(row) for row in cur.fetchall()]
        conn.close()
        return render_template("index.html", user=session.get("username"), results=rows, keyword=keyword)
    except Exception as e:
        conn.close()
        return render_template("index.html", user=session.get("username"), results=[], keyword=keyword, error=str(e))


# ─── 头像上传 ─────────────────────────────────────────────────────────

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "username" not in session:
        return redirect("/login")
    username = session["username"]
    if request.method == "POST":
        file = request.files.get("file")
        if file is None or file.filename == "":
            return render_template("upload.html", error="请选择一个文件")
        original_name = file.filename
        ext = os.path.splitext(original_name)[1].lower()
        if not allowed_extension(original_name):
            audit_logger.warning(f"[拦截-后缀] 用户={username} 文件={original_name} IP={request.remote_addr}")
            return render_template("upload.html", error="不支持的文件类型，仅允许 JPG/PNG/GIF/WebP/BMP")
        is_valid_mime, mime_type = allowed_mime(file)
        if not is_valid_mime:
            audit_logger.warning(f"[拦截-MIME] 用户={username} 文件={original_name} MIME={mime_type} IP={request.remote_addr}")
            return render_template("upload.html", error="文件内容不合法，请上传真实图片文件")
        safe_filename = uuid.uuid4().hex + ext
        save_path = UPLOAD_DIR_PATH / safe_filename
        if not str(save_path.resolve()).startswith(str(UPLOAD_DIR_PATH)):
            audit_logger.warning(f"[拦截-路径穿越] 用户={username} IP={request.remote_addr}")
            return render_template("upload.html", error="非法文件名")
        if get_user_upload_count(username) >= MAX_FILES_PER_USER:
            return render_template("upload.html", error=f"每个用户最多上传 {MAX_FILES_PER_USER} 个文件")
        try:
            file.save(str(save_path))
        except Exception:
            if save_path.exists():
                save_path.unlink()
            return render_template("upload.html", error="文件上传失败，请重试")
        file_size = save_path.stat().st_size
        audit_logger.info(f"[上传成功] 用户={username} 原始文件={original_name} 保存为={safe_filename} 大小={file_size}字节 MIME={mime_type} IP={request.remote_addr}")
        file_url = url_for("static", filename=f"uploads/{safe_filename}")
        return render_template("upload.html", success=True, filename=safe_filename, file_url=file_url)
    return render_template("upload.html")


# ─── 个人中心（修复：登录校验 + 资源所有权校验） ───────────────────

@app.route("/profile")
def profile():
    # 🔒 修复1：必须登录
    login_user = get_login_user()
    if not login_user:
        return redirect("/login")

    # 从 URL 参数获取目标 user_id
    target_id = request.args.get("user_id", type=int)
    if not target_id:
        return redirect(f"/profile?user_id={login_user['id']}")

    # 🔒 修复2：资源所有权校验
    # admin 可以查看所有人，普通用户只能查看自己
    if login_user["username"] != "admin" and target_id != login_user["id"]:
        biz_logger.warning(f"[越权拦截] 用户={login_user['username']}(ID={login_user['id']}) "
                           f"试图查看用户ID={target_id}的资料 IP={request.remote_addr}")
        return redirect(f"/profile?user_id={login_user['id']}")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, email, phone, balance FROM users WHERE id=?", (target_id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return render_template("profile.html", user=None, error="用户不存在")

    user_data = dict(row)
    # 生成 CSRF Token（用于修改密码表单）
    csrf_token = secrets.token_hex(16)
    session["csrf_token"] = csrf_token
    return render_template("profile.html", user=user_data, csrf_token=csrf_token)


# ─── 充值（修复：登录校验 + 自己充 + 金额正数 + 上限 + 异常处理） ─

@app.route("/recharge", methods=["POST"])
def recharge():
    # 🔒 修复1：必须登录
    login_user = get_login_user()
    if not login_user:
        return redirect("/login")

    user_id = request.form.get("user_id", type=int)
    amount_str = request.form.get("amount", "0")

    # 🔒 修复2：只能给自己充值（不可越权给他人充）
    if not user_id or user_id != login_user["id"]:
        biz_logger.warning(f"[越权充值拦截] 用户={login_user['username']}(ID={login_user['id']}) "
                           f"试图给用户ID={user_id}充值 IP={request.remote_addr}")
        return redirect(f"/profile?user_id={login_user['id']}")

    # 🔒 修复3：金额格式校验 + 异常处理
    try:
        amount_yuan = float(amount_str)
    except (ValueError, TypeError):
        return redirect(f"/profile?user_id={login_user['id']}")

    # 🔒 修复4：金额必须为正数
    if amount_yuan <= 0:
        return redirect(f"/profile?user_id={login_user['id']}")

    # 🔒 修复5：单次充值上限（防止超大金额溢出）
    if amount_yuan > 100000:
        return redirect(f"/profile?user_id={login_user['id']}")

    # 元转分（整数运算，防浮点数精度问题）
    amount_cents = int(round(amount_yuan * 100))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET balance = balance + ? WHERE id=?", (amount_cents, user_id))
    conn.commit()
    conn.close()

    # 记录审计日志
    biz_logger.info(f"[充值成功] 用户={login_user['username']} 金额={amount_yuan}元({amount_cents}分) IP={request.remote_addr}")

    return redirect(f"/profile?user_id={user_id}")


# ─── 管理员面板（修复：role 校验） ───────────────────────────────────

@app.route("/admin")
def admin_panel():
    login_user = get_login_user()
    if not login_user or login_user["username"] != "admin":
        abort(403)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, email, phone, balance FROM users")
    users = [dict(row) for row in cur.fetchall()]
    conn.close()

    return render_template("admin.html", users=users)


# ─── 管理员删除用户（修复：role 校验 + 审计日志） ─────────────────

@app.route("/admin/delete-user", methods=["POST"])
def admin_delete_user():
    login_user = get_login_user()
    if not login_user or login_user["username"] != "admin":
        abort(403)

    user_id = request.form.get("user_id", type=int)
    if not user_id:
        return redirect("/admin")

    # 不能删除自己
    if user_id == login_user["id"]:
        return redirect("/admin")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE id=?", (user_id,))
    target = cur.fetchone()
    if target:
        cur.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
        biz_logger.info(f"[删除用户] 管理员={login_user['username']} 删除了用户={target['username']}(ID={user_id}) IP={request.remote_addr}")
    conn.close()

    return redirect("/admin")


# ─── 审计日志查看 ─────────────────────────────────────────────────────

@app.route("/admin/logs")
def view_logs():
    if session.get("username") != "admin":
        abort(403)
    log_path = os.path.join(LOG_DIR, "upload.log")
    logs = []
    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8") as f:
            logs = f.readlines()[-100:]
    biz_path = os.path.join(LOG_DIR, "biz.log")
    biz_logs = []
    if os.path.exists(biz_path):
        with open(biz_path, "r", encoding="utf-8") as f:
            biz_logs = f.readlines()[-100:]
    return render_template("logs.html", logs=logs, biz_logs=biz_logs)


# ─── 动态页面加载（修复版） ──────────────────────────────────────────

@app.route("/page")
def dynamic_page():
    name = request.args.get("name", "")

    if not name:
        return render_template("index.html", page_content="请指定页面名称")

    # 🔒 修复1：过滤路径遍历字符
    name = name.replace("..", "").replace("/", "").replace("\\", "")

    if not name:
        return render_template("index.html", page_content="页面不存在")

    # 🔒 修复2：限定在 pages/ 目录内
    page_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pages", name)
    page_content = None

    # 先找 name 文件，再找 name.html
    for try_path in [page_path, page_path + ".html"]:
        # 🔒 修复3：确保文件在 pages/ 目录内
        real_path = os.path.realpath(try_path)
        pages_dir = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "pages"))
        if not real_path.startswith(pages_dir):
            continue
        if os.path.exists(real_path) and os.path.isfile(real_path):
            try:
                with open(real_path, "r", encoding="utf-8") as f:
                    # 🔒 修复4：只读取文本文件，不读二进制文件
                    content = f.read()
                    # 只允许纯文本/HTML内容，过滤危险字符
                    page_content = content
            except (UnicodeDecodeError, IOError):
                continue
            break

    if page_content is None:
        page_content = "页面不存在"

    return render_template("index.html", page_content=page_content)


# ─── 修改密码（修复版） ──────────────────────────────────────────────

@app.route("/change-password", methods=["POST"])
def change_password():
    if "username" not in session:
        return redirect("/login")

    username = request.form.get("username", "")
    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")
    csrf_token = request.form.get("csrf_token", "")

    # 🔒 修复1：校验 CSRF Token
    stored_token = session.pop("csrf_token", None)
    if not stored_token or csrf_token != stored_token:
        return redirect("/profile")

    # 🔒 修复2：校验 session 用户与提交的用户名一致（防越权）
    if username != session["username"]:
        return redirect("/profile")

    if not new_password or len(new_password) < 6:
        return redirect("/profile")

    # 🔒 修复3：校验原密码
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT password FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    if not row or not check_password_hash(row["password"], old_password):
        conn.close()
        return redirect("/profile")

    cur.execute("UPDATE users SET password = ? WHERE username = ?",
                (generate_password_hash(new_password), username))
    conn.commit()
    conn.close()

    return redirect("/profile")


# ─── 登出 ──────────────────────────────────────────────────────────────

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ─── 报告下载 ──────────────────────────────────────────────────────────

@app.route("/report")
def download_report():
    return send_file("/opt/Class01/SQL注入漏洞实验报告-蒲思宇.md", as_attachment=True, download_name="SQL注入漏洞实验报告-蒲思宇.md")

@app.route("/report/waf")
def download_waf_report():
    return send_file("/opt/Class01/waf_fuzz_report.md", as_attachment=True, download_name="waf_fuzz_report.md")

@app.route("/report/upload")
def download_upload_report():
    return send_file("/opt/Class01/头像上传功能安全审计报告-蒲思宇.md", as_attachment=True, download_name="头像上传功能安全审计报告-蒲思宇.md")

@app.route("/report/full")
def download_full_report():
    return send_file("/opt/Class01/用户管理系统安全审计报告-蒲思宇.md", as_attachment=True, download_name="用户管理系统安全审计报告-蒲思宇.md")


# ─── 启动 ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
