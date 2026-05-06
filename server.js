const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
// Serve static files from repo root (index.html). If you move index.html into /public later, adjust this.
app.use(express.static(__dirname));
app.use(session({
  secret: 'my_secret_123456',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 } // 24小时
}));

// ====== MySQL config (CHANGE THESE) ======
const MYSQL_CONFIG = {
  host: '127.0.0.1',
  port: 3306,
  user: 'root',
  password: 'abc123',
};

const DB_NAME = 'messageboard';

const pool = mysql.createPool({
  ...MYSQL_CONFIG,
  database: DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// 管理员账号（固定，不存数据库）
const ADMIN = { username: 'admin', password: 'admin123' };

async function initDB() {
  const connection = await mysql.createConnection(MYSQL_CONFIG);
  try {
    await connection.query(`CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
    await connection.query(`USE \`${DB_NAME}\``);

    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(100) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB;
    `);

    await connection.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NULL,
        author VARCHAR(50) NOT NULL,
        content LONGTEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_messages_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
      ) ENGINE=InnoDB;
    `);

    await connection.query(`
      CREATE TABLE IF NOT EXISTS replies (
        id INT AUTO_INCREMENT PRIMARY KEY,
        message_id INT NOT NULL,
        user_id INT NULL,
        author VARCHAR(50) NOT NULL,
        content LONGTEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_replies_message FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
        CONSTRAINT fk_replies_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
      ) ENGINE=InnoDB;
    `);

    // deletion operation logs (for "已删除" stats)
    await connection.query(`
      CREATE TABLE IF NOT EXISTS delete_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        operator_username VARCHAR(50) NOT NULL,
        target_type ENUM('message','reply') NOT NULL,
        target_id INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_operator_username (operator_username),
        INDEX idx_target_type (target_type),
        INDEX idx_created_at (created_at)
      ) ENGINE=InnoDB;
    `);

    console.log('数据库与数据表初始化完成');
  } finally {
    await connection.end();
  }
}

// ===== Utilities =====
function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: '请先登录' });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || !req.session.user.isAdmin)
    return res.status(403).json({ error: '无权限' });
  next();
}

async function logDelete(operatorUsername, targetType, targetId) {
  await pool.query(
    'INSERT INTO delete_logs (operator_username, target_type, target_id) VALUES (?, ?, ?)',
    [operatorUsername, targetType, targetId]
  );
}

// ===== 用户认证 =====
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: '用户名和密码不能为空' });
  if (username === ADMIN.username) return res.status(400).json({ error: '用户名已存在' });

  try {
    const hash = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      'INSERT INTO users (username, password) VALUES (?, ?)',
      [username, hash]
    );
    req.session.user = { id: result.insertId, username, isAdmin: false };
    res.json({ username, isAdmin: false });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: '用户名已存在' });
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  // 管理员登录
  if (username === ADMIN.username) {
    if (password !== ADMIN.password) return res.status(401).json({ error: '密码错误' });
    req.session.user = { id: 0, username: ADMIN.username, isAdmin: true };
    return res.json({ username: ADMIN.username, isAdmin: true });
  }

  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (!rows.length) return res.status(401).json({ error: '用户名不存在' });
    const match = await bcrypt.compare(password, rows[0].password);
    if (!match) return res.status(401).json({ error: '密码错误' });

    req.session.user = { id: rows[0].id, username, isAdmin: false };
    res.json({ username, isAdmin: false });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

app.get('/api/me', (req, res) => {
  if (!req.session.user) return res.json(null);
  res.json(req.session.user);
});

// ===== 统计（左侧栏） =====
app.get('/api/stats', async (req, res) => {
  try {
    // site totals (current existing)
    const [[siteMsg]] = await pool.query('SELECT COUNT(*) AS c FROM messages');
    const [[siteRep]] = await pool.query('SELECT COUNT(*) AS c FROM replies');

    let me = null;
    if (req.session.user) {
      const username = req.session.user.username;
      const [[myMsg]] = await pool.query('SELECT COUNT(*) AS c FROM messages WHERE author = ?', [username]);
      const [[myRep]] = await pool.query('SELECT COUNT(*) AS c FROM replies WHERE author = ?', [username]);

      // deletes: only for admin; non-admin return null
      let myDel = null;
      if (req.session.user.isAdmin) {
        const [[del]] = await pool.query('SELECT COUNT(*) AS c FROM delete_logs WHERE operator_username = ?', [username]);
        myDel = del.c;
      }

      me = {
        messages: myMsg.c,
        replies: myRep.c,
        deletes: myDel,
      };
    }

    res.json({
      me,
      site: {
        messages: siteMsg.c,
        replies: siteRep.c,
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== 留言 =====
app.get('/api/messages', async (req, res) => {
  try {
    const [messages] = await pool.query('SELECT * FROM messages ORDER BY created_at DESC');
    const [replies] = await pool.query('SELECT * FROM replies ORDER BY created_at ASC');
    res.json(messages.map(msg => ({
      ...msg,
      replies: replies.filter(r => r.message_id === msg.id)
    })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/messages', requireLogin, async (req, res) => {
  const { content } = req.body;
  const { id: user_id, username: author } = req.session.user;
  if (!content) return res.status(400).json({ error: '内容不能为空' });

  try {
    const [result] = await pool.query(
      'INSERT INTO messages (user_id, author, content) VALUES (?, ?, ?)',
      [user_id || null, author, content]
    );
    const [[row]] = await pool.query('SELECT * FROM messages WHERE id = ?', [result.insertId]);
    res.json(row);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/messages/:id', requireAdmin, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    await pool.query('DELETE FROM messages WHERE id = ?', [id]);
    await logDelete(req.session.user.username, 'message', id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== 回复 =====
app.post('/api/messages/:id/replies', requireLogin, async (req, res) => {
  const { content } = req.body;
  const { id: user_id, username: author } = req.session.user;
  const messageId = parseInt(req.params.id);
  if (!content) return res.status(400).json({ error: '内容不能为空' });

  try {
    const [result] = await pool.query(
      'INSERT INTO replies (message_id, user_id, author, content) VALUES (?, ?, ?, ?)',
      [messageId, user_id || null, author, content]
    );
    const [[row]] = await pool.query('SELECT * FROM replies WHERE id = ?', [result.insertId]);
    res.json(row);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/replies/:id', requireAdmin, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    await pool.query('DELETE FROM replies WHERE id = ?', [id]);
    await logDelete(req.session.user.username, 'reply', id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

initDB().then(() => {
  app.listen(3001, () => console.log('服务器运行在 http://localhost:3001'));
});
