const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'cumt_messageboard_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 } // 24小时
}));

const pool = new Pool({
  user: 'postgres', host: 'localhost',
  database: 'messageboard2', password: 'YH1223725', port: 5433,
});

// 管理员账号（固定，不存数据库）
const ADMIN = { username: 'admin', password: 'admin123' };

async function initDB() {
  const adminPool = new Pool({
    user: 'postgres', host: 'localhost',
    database: 'postgres', password: 'YH1223725', port: 5433,
  });
  try {
    const res = await adminPool.query("SELECT 1 FROM pg_database WHERE datname = 'messageboard2'");
    if (!res.rows.length) {
      await adminPool.query('CREATE DATABASE messageboard2');
      console.log('数据库 messageboard2 创建成功');
    }
  } finally { await adminPool.end(); }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password VARCHAR(100) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      author VARCHAR(50) NOT NULL,
      content TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS replies (
      id SERIAL PRIMARY KEY,
      message_id INTEGER REFERENCES messages(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      author VARCHAR(50) NOT NULL,
      content TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
  console.log('数据表初始化完成');
}

// 中间件：检查登录
function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: '请先登录' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || !req.session.user.isAdmin)
    return res.status(403).json({ error: '无权限' });
  next();
}

// ===== 用户认证 =====
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: '用户名和密码不能为空' });
  if (username === ADMIN.username) return res.status(400).json({ error: '用户名已存在' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username',
      [username, hash]
    );
    req.session.user = { id: result.rows[0].id, username, isAdmin: false };
    res.json({ username });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: '用户名已存在' });
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  // 管理员登录
  if (username === ADMIN.username) {
    if (password !== ADMIN.password) return res.status(401).json({ error: '密码错误' });
    req.session.user = { id: 0, username: 'admin', isAdmin: true };
    return res.json({ username: 'admin', isAdmin: true });
  }
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (!result.rows.length) return res.status(401).json({ error: '用户名不存在' });
    const match = await bcrypt.compare(password, result.rows[0].password);
    if (!match) return res.status(401).json({ error: '密码错误' });
    req.session.user = { id: result.rows[0].id, username, isAdmin: false };
    res.json({ username, isAdmin: false });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/me', (req, res) => {
  if (!req.session.user) return res.json(null);
  res.json(req.session.user);
});

// ===== 留言 =====
app.get('/api/messages', async (req, res) => {
  try {
    const messages = await pool.query('SELECT * FROM messages ORDER BY created_at DESC');
    const replies = await pool.query('SELECT * FROM replies ORDER BY created_at ASC');
    res.json(messages.rows.map(msg => ({
      ...msg, replies: replies.rows.filter(r => r.message_id === msg.id)
    })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/messages', requireLogin, async (req, res) => {
  const { content } = req.body;
  const { id: user_id, username: author } = req.session.user;
  if (!content) return res.status(400).json({ error: '内容不能为空' });
  try {
    const result = await pool.query(
      'INSERT INTO messages (user_id, author, content) VALUES ($1, $2, $3) RETURNING *',
      [user_id || null, author, content]
    );
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/messages/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM messages WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== 回复 =====
app.post('/api/messages/:id/replies', requireLogin, async (req, res) => {
  const { content } = req.body;
  const { id: user_id, username: author } = req.session.user;
  const messageId = parseInt(req.params.id);
  if (!content) return res.status(400).json({ error: '内容不能为空' });
  try {
    const result = await pool.query(
      'INSERT INTO replies (message_id, user_id, author, content) VALUES ($1, $2, $3, $4) RETURNING *',
      [messageId, user_id || null, author, content]
    );
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/replies/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM replies WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

initDB().then(() => {
  app.listen(3001, () => console.log('服务器运行在 http://localhost:3001'));
});
