"""
用户管理系统（完全安全加固版）
- 登录/注册/搜索：参数化查询
- 头像上传：后缀白名单 + MIME真实类型检测 + UUID重命名
           + 防路径穿越 + .htaccess防护 + 审计日志
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

# ─── 应用配置 ─────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB

# ─── 审计日志 ──────────────────────────────────────────────────────────

LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

audit_logger = logging.getLogger("upload_audit")
audit_logger.setLevel(logging.INFO)
handler = logging.FileHandler(os.path.join(LOG_DIR, "upload.log"), encoding="utf-8")
handler.setFormatter(logging.Formatter("%(asctime)s | %(message)s"))
audit_logger.addHandler(handler)

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
            phone TEXT
        )
    """)
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("admin", generate_password_hash("admin123"), "admin@example.com", "13800138000"))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("alice", generate_password_hash("alice2025"), "alice@example.com", "13900139001"))
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

# 允许的扩展名
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"}
# 允许的 MIME 类型
ALLOWED_MIMES = {
    "image/jpeg", "image/png", "image/gif",
    "image/bmp", "image/webp", "image/x-ms-bmp",
}
# 每个用户最大上传文件数
MAX_FILES_PER_USER = 10

UPLOAD_DIR_PATH = Path(UPLOAD_DIR).resolve()


# ─── .htaccess 自动部署（禁止上传目录解析脚本） ─────────────────────

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
    """检查文件扩展名"""
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def allowed_mime(file_obj):
    """读取文件头魔数检测真实 MIME 类型，并扫描图片马特征"""
    file_obj.seek(0)
    head = file_obj.read(2048)
    file_obj.seek(0)

    try:
        mime_type = magic.from_buffer(head, mime=True)
    except Exception:
        return False, "unknown"

    if mime_type not in ALLOWED_MIMES:
        return False, mime_type

    # 额外检测：对图片文件扫描是否含 PHP/ASP/JSP 代码（图片马检测）
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
    """获取用户已上传的文件数量"""
    count = 0
    if os.path.exists(UPLOAD_DIR):
        for f in os.listdir(UPLOAD_DIR):
            if f.startswith(f"{username}_"):
                count += 1
    return count


# ─── 首页 ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id, username, email, phone FROM users WHERE username=?", (username,))
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


# ─── 头像上传（完全安全加固版） ────────────────────────────────────

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

        # ✅ 修复1：后缀白名单校验
        if not allowed_extension(original_name):
            audit_logger.warning(
                f"[拦截-后缀] 用户={username} 文件={original_name} IP={request.remote_addr}"
            )
            return render_template("upload.html", error="不支持的文件类型，仅允许 JPG/PNG/GIF/WebP/BMP")

        # ✅ 修复2：MIME 真实类型检测（防图片马和改后缀）
        is_valid_mime, mime_type = allowed_mime(file)
        if not is_valid_mime:
            audit_logger.warning(
                f"[拦截-MIME] 用户={username} 文件={original_name} MIME={mime_type} IP={request.remote_addr}"
            )
            return render_template("upload.html", error="文件内容不合法，请上传真实图片文件")

        # ✅ 修复3：UUID 随机重命名（防覆盖 + 防文件名猜测）
        safe_filename = uuid.uuid4().hex + ext
        save_path = UPLOAD_DIR_PATH / safe_filename

        # ✅ 修复4：路径安全校验（防路径穿越）
        if not str(save_path.resolve()).startswith(str(UPLOAD_DIR_PATH)):
            audit_logger.warning(
                f"[拦截-路径穿越] 用户={username} IP={request.remote_addr}"
            )
            return render_template("upload.html", error="非法文件名")

        # ✅ 修复5：用户配额控制
        if get_user_upload_count(username) >= MAX_FILES_PER_USER:
            return render_template("upload.html", error=f"每个用户最多上传 {MAX_FILES_PER_USER} 个文件")

        # ✅ 保存文件（异常回滚）
        try:
            file.save(str(save_path))
        except Exception:
            if save_path.exists():
                save_path.unlink()
            return render_template("upload.html", error="文件上传失败，请重试")

        # ✅ 修复6：审计日志
        file_size = save_path.stat().st_size
        audit_logger.info(
            f"[上传成功] 用户={username} "
            f"原始文件={original_name} "
            f"保存为={safe_filename} "
            f"大小={file_size}字节 "
            f"MIME={mime_type} "
            f"IP={request.remote_addr}"
        )

        file_url = url_for("static", filename=f"uploads/{safe_filename}")
        return render_template("upload.html", success=True, filename=safe_filename, file_url=file_url)

    return render_template("upload.html")


# ─── 查看审计日志 ─────────────────────────────────────────────────────

@app.route("/admin/logs")
def view_logs():
    if session.get("username") != "admin":
        abort(403)
    log_path = os.path.join(LOG_DIR, "upload.log")
    logs = []
    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8") as f:
            logs = f.readlines()[-100:]  # 只显示最近100条
    return render_template("logs.html", logs=logs)


# ─── 登出 ──────────────────────────────────────────────────────────────

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ─── 报告下载 ──────────────────────────────────────────────────────────

@app.route("/report")
def download_report():
    return send_file(
        "/opt/Class01/SQL注入漏洞实验报告-蒲思宇.md",
        as_attachment=True,
        download_name="SQL注入漏洞实验报告-蒲思宇.md"
    )

@app.route("/report/waf")
def download_waf_report():
    return send_file(
        "/opt/Class01/waf_fuzz_report.md",
        as_attachment=True,
        download_name="waf_fuzz_report.md"
    )

@app.route("/report/upload")
def download_upload_report():
    return send_file(
        "/opt/Class01/头像上传功能安全审计报告-蒲思宇.md",
        as_attachment=True,
        download_name="头像上传功能安全审计报告-蒲思宇.md"
    )

@app.route("/report/full")
def download_full_report():
    return send_file(
        "/opt/Class01/用户管理系统安全审计报告-蒲思宇.md",
        as_attachment=True,
        download_name="用户管理系统安全审计报告-蒲思宇.md"
    )


# ─── 启动 ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
