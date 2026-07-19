# Flask 用户管理系统 🔐

一个具备完善安全防护的 Flask 用户管理系统，适用于教学演示和安全加固实践。

## 项目结构

```
/opt/Class01/
├── app.py                    # 主应用文件
├── templates/
│   ├── base.html             # 基础模板
│   ├── login.html            # 登录页
│   ├── index.html            # 首页
│   └── admin.html            # 管理员面板
├── static/
│   └── css/
│       └── style.css         # 样式文件
└── hunter_search.py          # 鹰图资产搜索工具
```

## 预设用户

| 用户名 | 密码 | 角色 | 邮箱 | 手机 | 余额 |
|--------|------|------|------|------|------|
| admin | admin123 | admin | admin@example.com | 13800138000 | 99999 |
| alice | alice2025 | user | alice@example.com | 13900139001 | 100 |

## 安全防护（11 层）

1. ✅ Debug 模式关闭
2. ✅ Secret Key 随机生成
3. ✅ 密码 scrypt 加盐哈希存储
4. ✅ SVG 数学验证码（纯 Python 生成）
5. ✅ IP 速率限制（30 次/分钟，登录 10 次/分钟）
6. ✅ 账户连续 5 次失败锁定 5 分钟
7. ✅ 渐进式延迟（每次失败 +0.5s，上限 3s）
8. ✅ CSRF Token 一次性使用
9. ✅ 参数污染防护
10. ✅ Content-Type 校验
11. ✅ Session 安全（登录刷新 ID + 30 分钟过期）

## 快速启动

```bash
pip install flask flask-limiter
cd /opt/Class01
python3 app.py
```

访问 **http://localhost:5000**

## 技术栈

- **框架**: Python Flask
- **安全**: Werkzeug, Flask-Limiter
- **前端**: HTML5, CSS3 (Flexbox)
