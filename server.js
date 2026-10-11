const express = require('express');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ===== Подключение к PostgreSQL (ONREZA) =====
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ===== Создание таблиц =====
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      balance INTEGER DEFAULT 500,
      inventory TEXT DEFAULT '[]',
      is_owner INTEGER DEFAULT 0,
      is_admin INTEGER DEFAULT 0,
      xp INTEGER DEFAULT 0,
      total_upgrades INTEGER DEFAULT 0,
      total_wins INTEGER DEFAULT 0,
      total_loses INTEGER DEFAULT 0,
      current_win_streak INTEGER DEFAULT 0,
      best_win_streak INTEGER DEFAULT 0,
      stars_spins INTEGER DEFAULT 0,
      max_bet INTEGER DEFAULT 0,
      achievements TEXT DEFAULT '[]',
      ever_owned TEXT DEFAULT '[]',
      created_at BIGINT
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      created_at BIGINT
    );

    CREATE TABLE IF NOT EXISTS deposits (
      id SERIAL PRIMARY KEY,
      user_id INTEGER,
      username TEXT,
      amount INTEGER,
      bonus TEXT,
      by_owner INTEGER,
      ts BIGINT
    );

    CREATE TABLE IF NOT EXISTS games (
      id SERIAL PRIMARY KEY,
      user_id INTEGER,
      username TEXT,
      from_id TEXT,
      to_id TEXT,
      chance REAL,
      roll INTEGER,
      win INTEGER,
      bet INTEGER,
      mult REAL,
      mode TEXT,
      ts BIGINT
    );

    CREATE TABLE IF NOT EXISTS promos (
      code TEXT PRIMARY KEY,
      reward INTEGER,
      uses INTEGER,
      nft_id TEXT,
      created_by INTEGER,
      created_at BIGINT
    );

    CREATE TABLE IF NOT EXISTS promo_uses (
      code TEXT,
      user_id INTEGER,
      PRIMARY KEY (code, user_id)
    );
  `);
  console.log('✅ Таблицы готовы');
}

// ===== Middleware =====
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

async function auth(req, res, next) {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Не авторизован' });
    const sessionRes = await pool.query('SELECT * FROM sessions WHERE token = $1', [token]);
    const session = sessionRes.rows[0];
    if (!session) return res.status(401).json({ error: 'Сессия истекла' });
    const userRes = await pool.query('SELECT * FROM users WHERE id = $1', [session.user_id]);
    const user = userRes.rows[0];
    if (!user) return res.status(401).json({ error: 'Пользователь не найден' });
    req.user = user;
    next();
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}

function publicUser(u) {
  return {
    id: u.id,
    username: u.username,
    balance: u.balance,
    inventory: JSON.parse(u.inventory || '[]'),
    isOwner: !!u.is_owner,
    isAdmin: !!u.is_admin,
    xp: u.xp,
    totalUpgrades: u.total_upgrades,
    totalWins: u.total_wins,
    totalLoses: u.total_loses,
    currentWinStreak: u.current_win_streak,
    bestWinStreak: u.best_win_streak,
    starsSpins: u.stars_spins,
    maxBet: u.max_bet,
    achievements: JSON.parse(u.achievements || '[]'),
    everOwned: JSON.parse(u.ever_owned || '[]'),
    createdAt: Number(u.created_at),
  };
}

// ===== Роуты =====

app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || username.length < 3) return res.status(400).json({ error: 'Логин мин. 3' });
    if (!password || password.length < 5) return res.status(400).json({ error: 'Пароль мин. 5' });

    const exists = await pool.query('SELECT id FROM users WHERE LOWER(username) = LOWER($1)', [username]);
    if (exists.rows.length > 0) return res.status(400).json({ error: 'Логин занят' });

    const hash = bcrypt.hashSync(password, 10);
    const countRes = await pool.query('SELECT COUNT(*) as c FROM users');
    const isFirst = parseInt(countRes.rows[0].c, 10) === 0;

    const insertRes = await pool.query(
      `INSERT INTO users (username, password_hash, balance, inventory, is_owner, created_at)
       VALUES ($1, $2, 500, '[]', $3, $4) RETURNING *`,
      [username, hash, isFirst ? 1 : 0, Date.now()]
    );
    const user = insertRes.rows[0];

    const token = crypto.randomBytes(32).toString('hex');
    await pool.query('INSERT INTO sessions (token, user_id, created_at) VALUES ($1, $2, $3)', [token, user.id, Date.now()]);

    res.cookie('token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
    res.json({ user: publicUser(user) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const userRes = await pool.query('SELECT * FROM users WHERE LOWER(username) = LOWER($1)', [username]);
    const user = userRes.rows[0];
    if (!user) return res.status(400).json({ error: 'Неверный логин' });
    if (!bcrypt.compareSync(password, user.password_hash)) return res.status(400).json({ error: 'Неверный пароль' });

    const token = crypto.randomBytes(32).toString('hex');
    await pool.query('INSERT INTO sessions (token, user_id, created_at) VALUES ($1, $2, $3)', [token, user.id, Date.now()]);

    res.cookie('token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
    res.json({ user: publicUser(user) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/logout', async (req, res) => {
  try {
    const token = req.cookies.token;
    if (token) await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
    res.clearCookie('token');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/me', auth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

app.post('/api/save', auth, async (req, res) => {
  try {
    const u = req.user;
    const b = req.body;
    await pool.query(
      `UPDATE users SET
        balance = $1, inventory = $2, xp = $3, total_upgrades = $4,
        total_wins = $5, total_loses = $6, current_win_streak = $7,
        best_win_streak = $8, stars_spins = $9, max_bet = $10,
        achievements = $11, ever_owned = $12
       WHERE id = $13`,
      [
        b.balance ?? u.balance,
        JSON.stringify(b.inventory ?? JSON.parse(u.inventory)),
        b.xp ?? u.xp,
        b.totalUpgrades ?? u.total_upgrades,
        b.totalWins ?? u.total_wins,
        b.totalLoses ?? u.total_loses,
        b.currentWinStreak ?? u.current_win_streak,
        b.bestWinStreak ?? u.best_win_streak,
        b.starsSpins ?? u.stars_spins,
        b.maxBet ?? u.max_bet,
        JSON.stringify(b.achievements ?? JSON.parse(u.achievements)),
        JSON.stringify(b.everOwned ?? JSON.parse(u.ever_owned)),
        u.id
      ]
    );
    const updated = await pool.query('SELECT * FROM users WHERE id = $1', [u.id]);
    res.json({ user: publicUser(updated.rows[0]) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/game', auth, async (req, res) => {
  try {
    const { fromId, toId, chance, roll, win, bet, mult, mode } = req.body;
    await pool.query(
      `INSERT INTO games (user_id, username, from_id, to_id, chance, roll, win, bet, mult, mode, ts)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [req.user.id, req.user.username, fromId, toId, chance, roll, win ? 1 : 0, bet || 0, mult || 0, mode, Date.now()]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/users', auth, async (req, res) => {
  try {
    if (!req.user.is_owner && !req.user.is_admin) return res.status(403).json({ error: 'Нет доступа' });
    const users = await pool.query('SELECT * FROM users ORDER BY id ASC');
    res.json({ users: users.rows.map(publicUser) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/deposits', auth, async (req, res) => {
  try {
    if (!req.user.is_owner && !req.user.is_admin) return res.status(403).json({ error: 'Нет доступа' });
    const rows = await pool.query('SELECT * FROM deposits ORDER BY ts DESC LIMIT 300');
    res.json({ deposits: rows.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/games', auth, async (req, res) => {
  try {
    if (!req.user.is_owner && !req.user.is_admin) return res.status(403).json({ error: 'Нет доступа' });
    const rows = await pool.query('SELECT * FROM games ORDER BY ts DESC LIMIT 300');
    res.json({ games: rows.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/admin/give', auth, async (req, res) => {
  try {
    if (!req.user.is_owner && !req.user.is_admin) return res.status(403).json({ error: 'Нет доступа' });
    const { userId, amount } = req.body;
    if (!userId || !amount || amount <= 0) return res.status(400).json({ error: 'Неверные данные' });
    const targetRes = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    const target = targetRes.rows[0];
    if (!target) return res.status(404).json({ error: 'Юзер не найден' });
    await pool.query('UPDATE users SET balance = balance + $1 WHERE id = $2', [amount, userId]);
    await pool.query(
      'INSERT INTO deposits (user_id, username, amount, bonus, by_owner, ts) VALUES ($1, $2, $3, $4, $5, $6)',
      [userId, target.username, amount, '👑 выдача', req.user.id, Date.now()]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/admin/give-all', auth, async (req, res) => {
  try {
    if (!req.user.is_owner && !req.user.is_admin) return res.status(403).json({ error: 'Нет доступа' });
    const { amount } = req.body;
    if (!amount || amount <= 0) return res.status(400).json({ error: 'Неверные данные' });
    const users = await pool.query('SELECT * FROM users');
    for (const u of users.rows) {
      await pool.query('UPDATE users SET balance = balance + $1 WHERE id = $2', [amount, u.id]);
      await pool.query(
        'INSERT INTO deposits (user_id, username, amount, bonus, by_owner, ts) VALUES ($1, $2, $3, $4, $5, $6)',
        [u.id, u.username, amount, '👑 массовая', req.user.id, Date.now()]
      );
    }
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/admin/toggle-admin', auth, async (req, res) => {
  try {
    if (!req.user.is_owner) return res.status(403).json({ error: 'Только OWNER' });
    const { userId } = req.body;
    const targetRes = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    const target = targetRes.rows[0];
    if (!target) return res.status(404).json({ error: 'Юзер не найден' });
    if (target.is_owner) return res.status(400).json({ error: 'OWNER неприкосновенен' });
    await pool.query('UPDATE users SET is_admin = $1 WHERE id = $2', [target.is_admin ? 0 : 1, userId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/admin/delete', auth, async (req, res) => {
  try {
    if (!req.user.is_owner) return res.status(403).json({ error: 'Только OWNER' });
    const { userId } = req.body;
    if (userId === req.user.id) return res.status(400).json({ error: 'Себя нельзя' });
    await pool.query('DELETE FROM users WHERE id = $1', [userId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/promos', auth, async (req, res) => {
  try {
    if (!req.user.is_owner && !req.user.is_admin) return res.status(403).json({ error: 'Нет доступа' });
    const promos = await pool.query('SELECT * FROM promos');
    const uses = await pool.query('SELECT code, user_id FROM promo_uses');
    const grouped = {};
    for (const u of uses.rows) {
      if (!grouped[u.code]) grouped[u.code] = [];
      grouped[u.code].push(u.user_id);
    }
    res.json({ promos: promos.rows, uses: grouped });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/promos', auth, async (req, res) => {
  try {
    if (!req.user.is_owner && !req.user.is_admin) return res.status(403).json({ error: 'Нет доступа' });
    const { code, reward, uses, nftId } = req.body;
    if (!code || code.length < 3) return res.status(400).json({ error: 'Код мин. 3' });
    const exists = await pool.query('SELECT code FROM promos WHERE code = $1', [code]);
    if (exists.rows.length > 0) return res.status(400).json({ error: 'Уже есть' });
    await pool.query(
      'INSERT INTO promos (code, reward, uses, nft_id, created_by, created_at) VALUES ($1, $2, $3, $4, $5, $6)',
      [code, reward || 0, uses || 1, nftId || null, req.user.id, Date.now()]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/promos/delete', auth, async (req, res) => {
  try {
    if (!req.user.is_owner && !req.user.is_admin) return res.status(403).json({ error: 'Нет доступа' });
    const { code } = req.body;
    await pool.query('DELETE FROM promos WHERE code = $1', [code]);
    await pool.query('DELETE FROM promo_uses WHERE code = $1', [code]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/promos/activate', auth, async (req, res) => {
  try {
    const { code } = req.body;
    const promoRes = await pool.query('SELECT * FROM promos WHERE code = $1', [code]);
    const promo = promoRes.rows[0];
    if (!promo) return res.status(404).json({ error: 'Промокод не найден' });
    const already = await pool.query('SELECT 1 FROM promo_uses WHERE code = $1 AND user_id = $2', [code, req.user.id]);
    if (already.rows.length > 0) return res.status(400).json({ error: 'Уже активирован' });
    const usedRes = await pool.query('SELECT COUNT(*) as c FROM promo_uses WHERE code = $1', [code]);
    if (parseInt(usedRes.rows[0].c, 10) >= promo.uses) return res.status(400).json({ error: 'Промокод исчерпан' });

    await pool.query('INSERT INTO promo_uses (code, user_id) VALUES ($1, $2)', [code, req.user.id]);
    if (promo.reward > 0) {
      await pool.query('UPDATE users SET balance = balance + $1 WHERE id = $2', [promo.reward, req.user.id]);
    }
    if (promo.nft_id) {
      const inv = JSON.parse(req.user.inventory || '[]');
      inv.push(promo.nft_id);
      const ever = JSON.parse(req.user.ever_owned || '[]');
      if (!ever.includes(promo.nft_id)) ever.push(promo.nft_id);
      await pool.query('UPDATE users SET inventory = $1, ever_owned = $2 WHERE id = $3',
        [JSON.stringify(inv), JSON.stringify(ever), req.user.id]);
    }
    res.json({ ok: true, reward: promo.reward, nftId: promo.nft_id });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== Старт =====
initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`✅ BetterDrop запущен: http://localhost:${PORT}`);
  });
}).catch(err => {
  console.error('❌ Ошибка инициализации БД:', err.message);
  process.exit(1);
});
