import express from 'express';
import pg from 'pg';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
import cors from 'cors';
app.use(cors({
  origin: ['https://cspresources.com', 'https://www.cspresources.com'],
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../public')));

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret';

// ── Database Init ─────────────────────────────────────────────────────────────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS reports (
      id SERIAL PRIMARY KEY,
      client_name TEXT NOT NULL,
      data JSONB NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('admin', 'staff', 'client')),
      client_name TEXT,
      full_name TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      active BOOLEAN DEFAULT TRUE
    );

    CREATE INDEX IF NOT EXISTS idx_reports_client ON reports(client_name);
    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
  `);

  // Create default admin if none exists
  const existing = await pool.query("SELECT id FROM users WHERE role = 'admin' LIMIT 1");
  if (existing.rows.length === 0) {
    const hash = await bcrypt.hash('admin123', 12);
    await pool.query(
      "INSERT INTO users (username, password_hash, role, full_name) VALUES ($1, $2, 'admin', 'Administrator')",
      ['admin', hash]
    );
    console.log('Default admin created: username=admin password=admin123 (CHANGE THIS!)');
  }

  console.log('Database ready.');
}

// ── Auth Middleware ───────────────────────────────────────────────────────────
function requireAuth(roles = []) {
  return (req, res, next) => {
    const token = req.cookies?.token || req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Not authenticated' });
    try {
      const user = jwt.verify(token, JWT_SECRET);
      if (roles.length && !roles.includes(user.role)) {
        return res.status(403).json({ error: 'Access denied' });
      }
      req.user = user;
      next();
    } catch {
      res.status(401).json({ error: 'Invalid or expired session' });
    }
  };
}

// ── Auth Routes ───────────────────────────────────────────────────────────────

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });

  const result = await pool.query(
    'SELECT * FROM users WHERE username = $1 AND active = true', [username.toLowerCase()]
  );
  const user = result.rows[0];
  if (!user) return res.status(401).json({ error: 'Invalid username or password' });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid username or password' });

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role, clientName: user.client_name, fullName: user.full_name },
    JWT_SECRET,
    { expiresIn: '8h' }
  );

  res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 8 * 60 * 60 * 1000 });
  res.json({ role: user.role, username: user.username, fullName: user.full_name, clientName: user.client_name });
});

// POST /api/auth/logout
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

// GET /api/auth/me — check current session
app.get('/api/auth/me', requireAuth(), (req, res) => {
  res.json(req.user);
});

// ── User Management (Admin only) ──────────────────────────────────────────────

// GET /api/users
app.get('/api/users', requireAuth(['admin']), async (req, res) => {
  const result = await pool.query(
    'SELECT id, username, role, client_name, full_name, created_at, active FROM users ORDER BY role, username'
  );
  res.json(result.rows);
});

// POST /api/users — create new user
app.post('/api/users', requireAuth(['admin']), async (req, res) => {
  const { username, password, role, clientName, fullName } = req.body;
  if (!username || !password || !role) return res.status(400).json({ error: 'Missing required fields' });
  if (!['admin', 'staff', 'client'].includes(role)) return res.status(400).json({ error: 'Invalid role' });
  if (role === 'client' && !clientName) return res.status(400).json({ error: 'Client users require a client name' });

  const hash = await bcrypt.hash(password, 12);
  try {
    const result = await pool.query(
      'INSERT INTO users (username, password_hash, role, client_name, full_name) VALUES ($1, $2, $3, $4, $5) RETURNING id, username, role, client_name, full_name',
      [username.toLowerCase(), hash, role, clientName || null, fullName || null]
    );
    res.json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'Username already exists' });
    throw err;
  }
});

// PUT /api/users/:id — update user
app.put('/api/users/:id', requireAuth(['admin']), async (req, res) => {
  const { password, role, clientName, fullName, active } = req.body;
  const updates = [];
  const values = [];
  let idx = 1;

  if (password) { updates.push(`password_hash = $${idx++}`); values.push(await bcrypt.hash(password, 12)); }
  if (role) { updates.push(`role = $${idx++}`); values.push(role); }
  if (clientName !== undefined) { updates.push(`client_name = $${idx++}`); values.push(clientName); }
  if (fullName !== undefined) { updates.push(`full_name = $${idx++}`); values.push(fullName); }
  if (active !== undefined) { updates.push(`active = $${idx++}`); values.push(active); }

  if (!updates.length) return res.status(400).json({ error: 'Nothing to update' });
  values.push(req.params.id);

  const result = await pool.query(
    `UPDATE users SET ${updates.join(', ')} WHERE id = $${idx} RETURNING id, username, role, client_name, full_name, active`,
    values
  );
  res.json(result.rows[0]);
});

// DELETE /api/users/:id
app.delete('/api/users/:id', requireAuth(['admin']), async (req, res) => {
  await pool.query('UPDATE users SET active = false WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

// ── Report Routes ─────────────────────────────────────────────────────────────

// POST /api/reports — orchestrator posts here (uses API key)
app.post('/api/reports', async (req, res) => {
  const apiKey = req.headers['x-api-key'];
  if (apiKey !== process.env.WEBSITE_API_KEY) return res.status(401).json({ error: 'Unauthorized' });

  const { client, data, timestamp } = req.body;
  if (!client || !data) return res.status(400).json({ error: 'Missing client or data' });

  await pool.query(
    'INSERT INTO reports (client_name, data, created_at) VALUES ($1, $2, $3)',
    [client, JSON.stringify(data), timestamp || new Date().toISOString()]
  );
  console.log(`Report saved: ${client}`);
  res.json({ success: true });
});

// GET /api/reports — list available reports (staff/admin see all, clients see own)
app.get('/api/reports', requireAuth(['admin', 'staff', 'client']), async (req, res) => {
  let result;
  if (req.user.role === 'client') {
    result = await pool.query(
      'SELECT DISTINCT ON (client_name) client_name, created_at FROM reports WHERE client_name = $1 ORDER BY client_name, created_at DESC',
      [req.user.clientName]
    );
  } else {
    result = await pool.query(
      'SELECT DISTINCT ON (client_name) client_name, created_at FROM reports ORDER BY client_name, created_at DESC'
    );
  }
  res.json(result.rows);
});

// GET /api/reports/:clientName — get latest report for client
app.get('/api/reports/:clientName', requireAuth(['admin', 'staff', 'client']), async (req, res) => {
  // Clients can only see their own data
  if (req.user.role === 'client' && req.user.clientName !== req.params.clientName) {
    return res.status(403).json({ error: 'Access denied' });
  }

  const result = await pool.query(
    'SELECT data, created_at FROM reports WHERE client_name = $1 ORDER BY created_at DESC LIMIT 1',
    [req.params.clientName]
  );
  if (!result.rows.length) return res.status(404).json({ error: 'No data found' });
  res.json({ client: req.params.clientName, data: result.rows[0].data, lastUpdated: result.rows[0].created_at });
});

// ── Pages ─────────────────────────────────────────────────────────────────────
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, '../public/login.html')));
app.get('/admin', requireAuth(['admin']), (req, res) => res.sendFile(path.join(__dirname, '../public/admin.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, '../public/index.html')));

const PORT = process.env.PORT || 3000;
initDB().then(() => app.listen(PORT, () => console.log(`Server running on port ${PORT}`)));
