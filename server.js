const express = require('express');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ===== База данных =====
const db = new Database('betterdrop.db');
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    created_at INTEGER
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at INTEGER
  );

  CREATE TABLE IF NOT EXISTS deposits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT,
    amount INTEGER,
    bonus TEXT,
    by_owner INTEGER,
    ts INTEGER
  );

  CREATE TABLE IF NOT EXISTS games (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    ts INTEGER
  );

  CREATE TABLE IF NOT EXISTS promos (
    code TEXT PRIMARY KEY,
    reward INTEGER,
    uses INTEGER,
    nft_id TEXT,
    created_by INTEGER,
    created_at INTEGER
  );

  CREATE TABLE IF NOT EXISTS promo_uses (
    code TEXT,
    user_id INTEGER,
    PRIMARY KEY (code, user_id)
  );
`);

// ===== Middleware =====
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

function auth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Не авторизован' });
  const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!session) return res.status(401).json({ error: 'Сессия истекла' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
  if (!user) return res.status(401).json({ error: 'Пользователь не найден' });
  req.user = user;
  next();
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
    createdAt: u.created_at,
  };
}

// ===== Роуты =====

// Регистрация
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || username.length < 3) return res.status(400).json({ error: 'Логин мин. 3' });
  if (!password || password.length < 5) return res.status(400).json({ error: 'Пароль мин. 5' });

  const exists = db.prepare('SELECT id FROM users WHERE LOWER(username) = LOWER(?)').get(username);
  if (exists) return res.status(400).json({ error: 'Логин занят' });

  const hash = bcrypt.hashSync(password, 10);
  const isFirst = db.prepare('SELECT COUNT(*) as c FROM users').get().c === 0;

  const result = db.prepare(`
    INSERT INTO users (username, password_hash, balance, inventory, is_owner, created_at)
    VALUES (?, ?, 500, '[]', ?, ?)
  `).run(username, hash, isFirst ? 1 : 0, Date.now());

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);

  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)')
    .run(token, user.id, Date.now());

  res.cookie('token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000 });
  res.json({ user: publicUser(user) });
});

// Вход
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)').get(username);
  if (!user) return res.status(400).json({ error: 'Неверный логин' });
  if (!bcrypt.compareSync(password, user.password_hash)) return res.status(400).json({ error: 'Неверный пароль' });

  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)')
    .run(token, user.id, Date.now());

  res.cookie('token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000 });
  res.json({ user: publicUser(user) });
});

// Выход
app.post('/api/logout', (req, res) => {
  const token = req.cookies.token;
  if (token) db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  res.clearCookie('token');
  res.json({ ok: true });
});

// Текущий юзер
app.get('/api/me', auth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

// Сохранить состояние
app.post('/api/save', auth, (req, res) => {
  const u = req.user;
  const body = req.body;

  db.prepare(`
    UPDATE users SET
      balance = ?, inventory = ?, xp = ?, total_upgrades = ?,
      total_wins = ?, total_loses = ?, current_win_streak = ?,
      best_win_streak = ?, stars_spins = ?, max_bet = ?,
      achievements = ?, ever_owned = ?
    WHERE id = ?
  `).run(
    body.balance ?? u.balance,
    JSON.stringify(body.inventory ?? JSON.parse(u.inventory)),
    body.xp ?? u.xp,
    body.totalUpgrades ?? u.total_upgrades,
    body.totalWins ?? u.total_wins,
    body.totalLoses ?? u.total_loses,
    body.currentWinStreak ?? u.current_win_streak,
    body.bestWinStreak ?? u.best_win_streak,
    body.starsSpins ?? u.stars_spins,
    body.maxBet ?? u.max_bet,
    JSON.stringify(body.achievements ?? JSON.parse(u.achievements)),
    JSON.stringify(body.everOwned ?? JSON.parse(u.ever_owned)),
    u.id
  );

  const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(u.id);
  res.json({ user: publicUser(updated) });
});

// Записать игру
app.post('/api/game', auth, (req, res) => {
  const { fromId, toId, chance, roll, win, bet, mult, mode } = req.body;
  db.prepare(`
    INSERT INTO games (user_id, username, from_id, to_id, chance, roll, win, bet, mult, mode, ts)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(req.user.id, req.user.username, fromId, toId, chance, roll, win ? 1 : 0, bet || 0, mult || 0, mode, Date.now());
  res.json({ ok: true });
});

// Список юзеров
app.get('/api/users', auth, (req, res) => {
  if (!req.user.is_owner && !req.user.is_admin) return res.status(403).json({ error: 'Нет доступа' });
  const users = db.prepare('SELECT * FROM users ORDER BY id ASC').all();
  res.json({ users: users.map(publicUser) });
});

// Пополнения
app.get('/api/deposits', auth, (req, res) => {
  if (!req.user.is_owner && !req.user.is_admin) return res.status(403).json({ error: 'Нет доступа' });
  const rows = db.prepare('SELECT * FROM deposits ORDER BY ts DESC LIMIT 300').all();
  res.json({ deposits: rows });
});

// Игры
app.get('/api/games', auth, (req, res) => {
  if (!req.user.is_owner && !req.user.is_admin) return res.status(403).json({ error: 'Нет доступа' });
  const rows = db.prepare('SELECT * FROM games ORDER BY ts DESC LIMIT 300').all();
  res.json({ games: rows });
});

// Выдать звёзды
app.post('/api/admin/give', auth, (req, res) => {
  if (!req.user.is_owner && !req.user.is_admin) return res.status(403).json({ error: 'Нет доступа' });
  const { userId, amount } = req.body;
  if (!userId || !amount || amount <= 0) return res.status(400).json({ error: 'Неверные данные' });
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!target) return res.status(404).json({ error: 'Юзер не найден' });
  db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(amount, userId);
  db.prepare('INSERT INTO deposits (user_id, username, amount, bonus, by_owner, ts) VALUES (?, ?, ?, ?, ?, ?)')
    .run(userId, target.username, amount, '👑 выдача', req.user.id, Date.now());
  res.json({ ok: true });
});

// Выдать всем
app.post('/api/admin/give-all', auth, (req, res) => {
  if (!req.user.is_owner && !req.user.is_admin) return res.status(403).json({ error: 'Нет доступа' });
  const { amount } = req.body;
  if (!amount || amount <= 0) return res.status(400).json({ error: 'Неверные данные' });
  const users = db.prepare('SELECT * FROM users').all();
  const stmt = db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?');
  const dep = db.prepare('INSERT INTO deposits (user_id, username, amount, bonus, by_owner, ts) VALUES (?, ?, ?, ?, ?, ?)');
  for (const u of users) {
    stmt.run(amount, u.id);
    dep.run(u.id, u.username, amount, '👑 массовая', req.user.id, Date.now());
  }
  res.json({ ok: true });
});

// Роль admin
app.post('/api/admin/toggle-admin', auth, (req, res) => {
  if (!req.user.is_owner) return res.status(403).json({ error: 'Только OWNER' });
  const { userId } = req.body;
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!target) return res.status(404).json({ error: 'Юзер не найден' });
  if (target.is_owner) return res.status(400).json({ error: 'OWNER неприкосновенен' });
  db.prepare('UPDATE users SET is_admin = ? WHERE id = ?').run(target.is_admin ? 0 : 1, userId);
  res.json({ ok: true });
});

// Удалить юзера
app.post('/api/admin/delete', auth, (req, res) => {
  if (!req.user.is_owner) return res.status(403).json({ error: 'Только OWNER' });
  const { userId } = req.body;
  if (userId === req.user.id) return res.status(400).json({ error: 'Себя нельзя' });
  db.prepare('DELETE FROM users WHERE id = ?').run(userId);
  res.json({ ok: true });
});

// Промокоды
app.get('/api/promos', auth, (req, res) => {
  if (!req.user.is_owner && !req.user.is_admin) return res.status(403).json({ error: 'Нет доступа' });
  const promos = db.prepare('SELECT * FROM promos').all();
  const uses = db.prepare('SELECT code, user_id FROM promo_uses').all();
  const grouped = {};
  for (const u of uses) {
    if (!grouped[u.code]) grouped[u.code] = [];
    grouped[u.code].push(u.user_id);
  }
  res.json({ promos, uses: grouped });
});

app.post('/api/promos', auth, (req, res) => {
  if (!req.user.is_owner && !req.user.is_admin) return res.status(403).json({ error: 'Нет доступа' });
  const { code, reward, uses, nftId } = req.body;
  if (!code || code.length < 3) return res.status(400).json({ error: 'Код мин. 3' });
  const exists = db.prepare('SELECT code FROM promos WHERE code = ?').get(code);
  if (exists) return res.status(400).json({ error: 'Уже есть' });
  db.prepare('INSERT INTO promos (code, reward, uses, nft_id, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(code, reward || 0, uses || 1, nftId || null, req.user.id, Date.now());
  res.json({ ok: true });
});

app.post('/api/promos/delete', auth, (req, res) => {
  if (!req.user.is_owner && !req.user.is_admin) return res.status(403).json({ error: 'Нет доступа' });
  const { code } = req.body;
  db.prepare('DELETE FROM promos WHERE code = ?').run(code);
  db.prepare('DELETE FROM promo_uses WHERE code = ?').run(code);
  res.json({ ok: true });
});

app.post('/api/promos/activate', auth, (req, res) => {
  const { code } = req.body;
  const promo = db.prepare('SELECT * FROM promos WHERE code = ?').get(code);
  if (!promo) return res.status(404).json({ error: 'Промокод не найден' });
  const already = db.prepare('SELECT 1 FROM promo_uses WHERE code = ? AND user_id = ?').get(code, req.user.id);
  if (already) return res.status(400).json({ error: 'Уже активирован' });
  const used = db.prepare('SELECT COUNT(*) as c FROM promo_uses WHERE code = ?').get(code).c;
  if (used >= promo.uses) return res.status(400).json({ error: 'Промокод исчерпан' });

  db.prepare('INSERT INTO promo_uses (code, user_id) VALUES (?, ?)').run(code, req.user.id);
  if (promo.reward > 0) {
    db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(promo.reward, req.user.id);
  }
  if (promo.nft_id) {
    const inv = JSON.parse(req.user.inventory || '[]');
    inv.push(promo.nft_id);
    const ever = JSON.parse(req.user.ever_owned || '[]');
    if (!ever.includes(promo.nft_id)) ever.push(promo.nft_id);
    db.prepare('UPDATE users SET inventory = ?, ever_owned = ? WHERE id = ?')
      .run(JSON.stringify(inv), JSON.stringify(ever), req.user.id);
  }
  res.json({ ok: true, reward: promo.reward, nftId: promo.nft_id });
});

// Старт
app.listen(PORT, () => {
  console.log(`✅ BetterDrop запущен: http://localhost:${PORT}`);
});
