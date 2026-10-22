const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// ===== 数据库初始化 =====
const db = new Database(path.join(__dirname, 'data.db'));
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    card_key TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS cards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    type TEXT NOT NULL,
    used INTEGER DEFAULT 0,
    used_by TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// ===== API 路由 =====

// 注册
app.post('/api/register', (req, res) => {
  const { account, password, cardKey } = req.body;
  if (!account || !password) {
    return res.json({ code: -1, msg: '账号和密码不能为空' });
  }
  if (password.length < 8) {
    return res.json({ code: -1, msg: '密码需要8位以上' });
  }

  // 验证卡密
  const card = db.prepare('SELECT * FROM cards WHERE code = ? AND used = 0').get(cardKey);
  if (!card) {
    return res.json({ code: -1, msg: '卡密无效或已被使用' });
  }

  try {
    const stmt = db.prepare('INSERT INTO users (account, password, card_key) VALUES (?, ?, ?)');
    stmt.run(account, password, cardKey);
    db.prepare('UPDATE cards SET used = 1, used_by = ? WHERE code = ?').run(account, cardKey);
    res.json({ code: 0, msg: '注册成功', data: { account } });
  } catch (e) {
    res.json({ code: -1, msg: '账号已存在' });
  }
});

// 登录
app.post('/api/login', (req, res) => {
  const { account, password } = req.body;
  if (!account || !password) {
    return res.json({ code: -1, msg: '账号和密码不能为空' });
  }
  const user = db.prepare('SELECT * FROM users WHERE account = ? AND password = ?').get(account, password);
  if (!user) {
    return res.json({ code: -1, msg: '账号或密码错误' });
  }
  res.json({ code: 0, msg: '登录成功', data: { account: user.account, cardKey: user.card_key } });
});

// 获取套餐
app.get('/api/plans', (req, res) => {
  res.json({
    code: 0,
    data: [
      { id: 'monthly', name: '月度授权', desc: '30天使用权限', price: 5 },
      { id: 'quarterly', name: '季度授权', desc: '90天使用权限', price: 10 },
      { id: 'permanent', name: '永久授权', desc: '终身使用权限', price: 15 },
    ],
  });
});

// ===== 启动 =====
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
