"""
用户管理系统
- 登录功能：参数化查询（安全）
- 注册功能：参数化查询（安全）
- 搜索功能：参数化查询（安全）
"""

import os
import sqlite3
import secrets
from flask import Flask, render_template, request, redirect, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ─── SQLite 数据库初始化 ─────────────────────────────────────────────

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
    # 使用哈希密码插入默认用户
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
        # 先通过用户名查找用户
        cur.execute("SELECT * FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        conn.close()

        # 验证密码（使用哈希比对）
        if row and check_password_hash(row["password"], password):
            session["username"] = username
            user_info = dict(row)
            del user_info["password"]  # 不传递密码字段
            return render_template("index.html", user=user_info)

        return render_template("login.html", error="用户名或密码错误")

    return render_template("login.html")


# ─── 注册（修复：参数化查询 + 密码哈希） ──────────────────────────────

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")

        # ✅ 修复：使用参数化查询 + 密码哈希存储
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
            # 统一错误提示，防止用户枚举
            return render_template("register.html", error="注册失败，用户名可能已存在")

    return render_template("register.html")


# ─── 搜索（修复：参数化查询） ─────────────────────────────────────────

@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")

    # ✅ 修复：使用参数化查询（? 占位符），防止 SQL 注入
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


# ─── 启动 ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
