import express from 'express';
import cors from 'cors';
import pg from 'pg';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(cors({
  origin: [
    'https://cspresources.com',
    'https://www.cspresources.com',
    'https://website-6m1d.onrender.com',
    'http://localhost:3000'
  ],
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

  res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none', maxAge: 8 * 60 * 60 * 1000 });
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

// ── Dispatch File Parse ───────────────────────────────────────────────────────
import multer from 'multer';
import { Readable } from 'stream';
import AdmZip from 'adm-zip';

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

app.post('/api/dispatch/parse', requireAuth(['admin', 'staff', 'client']), upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const zip = new AdmZip(req.file.buffer);

    // Parse shared strings
    const stringsXml = zip.getEntry('xl/sharedStrings.xml');
    const sheetXml = zip.getEntry('xl/worksheets/sheet1.xml');
    if (!sheetXml) return res.status(400).json({ error: 'Invalid xlsx file' });

    // Simple XML text extraction
    function extractTexts(xml) {
      const matches = [...xml.matchAll(/<t[^>]*>([^<]*)<\/t>/g)];
      return matches.map(m => m[1]);
    }

    function extractCells(xml) {
      const rows = [...xml.matchAll(/<row[^>]*>(.*?)<\/row>/gs)];
      return rows.map(row => {
        const cells = [...row[1].matchAll(/<c\s([^>]*)>(.*?)<\/c>/gs)];
        return cells.map(cell => {
          const attrs = cell[1];
          const inner = cell[2];
          const t = (attrs.match(/t="([^"]*)"/) || [])[1];
          const v = (inner.match(/<v>([^<]*)<\/v>/) || [])[1];
          return { t, v };
        });
      });
    }

    const shared = stringsXml ? extractTexts(stringsXml.getData().toString('utf8')) : [];
    const sheetData = sheetXml.getData().toString('utf8');
    const allRows = extractCells(sheetData);

    if (allRows.length < 2) return res.status(400).json({ error: 'No data rows found' });

    // First row = headers
    const headers = allRows[0].map(c => {
      if (c.t === 's' && c.v !== undefined) return shared[parseInt(c.v)] || '';
      return c.v || '';
    });

    // Find column indices
    const fdxIdx = headers.findIndex(h => h.toLowerCase().includes('fdx') || h.toLowerCase().includes('fedex'));
    const firstIdx = headers.findIndex(h => h.toLowerCase().includes('first'));
    const lastIdx = headers.findIndex(h => h.toLowerCase().includes('last'));
    const statusIdx = headers.findIndex(h => h.toLowerCase().includes('status'));

    const drivers = allRows.slice(1).map(row => {
      function getCell(idx) {
        if (idx < 0 || idx >= row.length) return '';
        const c = row[idx];
        if (!c || c.v === undefined) return '';
        if (c.t === 's') return shared[parseInt(c.v)] || '';
        return c.v || '';
      }
      return {
        fdxId: getCell(fdxIdx),
        firstName: getCell(firstIdx),
        lastName: getCell(lastIdx),
        status: getCell(statusIdx)
      };
    }).filter(d => d.fdxId || d.firstName || d.lastName);

    res.json({ drivers, headers, count: drivers.length });
  } catch (err) {
    console.error('Dispatch parse error:', err);
    res.status(500).json({ error: 'Failed to parse file: ' + err.message });
  }
});


// ── Compliance Auto-Fetch from Tomcat ────────────────────────────────────────
async function parseXlsxFromBuffer(buffer) {
  const AdmZip = (await import('adm-zip')).default;
  const zip = new AdmZip(buffer);
  function extractTexts(xml) {
    return [...xml.matchAll(/<t[^>]*>([^<]*)<\/t>/g)].map(m => m[1]);
  }
  function extractCells(xml) {
    return [...xml.matchAll(/<row[^>]*>(.*?)<\/row>/gs)].map(row =>
      [...row[1].matchAll(/<c\s([^>]*)>(.*?)<\/c>/gs)].map(cell => ({
        t: (cell[1].match(/t="([^"]*)"/) || [])[1],
        v: (cell[2].match(/<v>([^<]*)<\/v>/) || [])[1]
      }))
    );
  }
  const stringsEntry = zip.getEntry('xl/sharedStrings.xml');
  const sheetEntry = zip.getEntry('xl/worksheets/sheet1.xml');
  if (!sheetEntry) throw new Error('Invalid xlsx format');
  const shared = stringsEntry ? extractTexts(stringsEntry.getData().toString('utf8')) : [];
  const allRows = extractCells(sheetEntry.getData().toString('utf8'));
  if (allRows.length < 2) throw new Error('No data rows found');
  const headers = allRows[0].map(c => c.t === 's' && c.v !== undefined ? (shared[parseInt(c.v)] || '') : (c.v || ''));
  function getCell(row, idx) {
    if (idx < 0 || idx >= row.length) return '';
    const c = row[idx]; if (!c || c.v === undefined) return '';
    return c.t === 's' ? (shared[parseInt(c.v)] || '') : (c.v || '');
  }
  function findCol(keywords) {
    return headers.findIndex(h => keywords.some(k => h.toLowerCase().includes(k.toLowerCase())));
  }
  const fedexIdIndices = headers.reduce((acc,h,i) => { if(h.toLowerCase()==='fedex id') acc.push(i); return acc; }, []);
  const dotStateIndices = headers.reduce((acc,h,i) => { if(h.toLowerCase()==='dot state') acc.push(i); return acc; }, []);
  // Hardcoded exact column indices from known file structure:
  // 0:First Name, 1:Last Name, 2:State, 3:FDX ID, 4:FedEx ID, 5:FedEx Site ID
  // 6:DOT State, 7:DOT Expiration, 8:Driver Name, 9:Company
  // 10:Domicile Station ID, 11:Associated Station ID, 12:Workforce Doc Status
  // 13:SIG Expiration Date, 14:Driver Status, 15:MVR Expiration Date
  // 16:Med Card Expiration Date, 17:CDAS Status
  // 18:FedEx ID(FADV), 19:FA ID, 20:Full Name, 21:DOT ID, 22:DOT State(FADV)
  // 23:Job Status, 24:Job Title, 25:FEC MVR expires, 26:FEC MEC expires, 27:FEC Training CERT expires
  const cols = {
    firstName: 0, lastName: 1, state: 2, fdxId: 3,
    fedexId: 4, fedexSiteId: 5, dotState: 6, dotExp: 7,
    driverName: 8, company: 9, domStation: 10, assocStation: 11,
    workforceStatus: 12, sigExp: 13, driverStatus: 14, mvrExp: 15,
    medExp: 16, cdas: 17,
    faFedexId: 18, faId: 19, faName: 20, dotId: 21,
    fadvDotState: 22, jobStatus: 23, jobTitle: 24,
    fadvMvr: 25, fadvMec: 26, fadvCert: 27
  };
  const drivers = allRows.slice(1).map(row => ({
    fn: getCell(row,cols.firstName), ln: getCell(row,cols.lastName),
    state: getCell(row,cols.state), fdxId: getCell(row,cols.fdxId),
    mgb: {
      fedexId: getCell(row,cols.fedexId), siteId: getCell(row,cols.fedexSiteId),
      dotState: getCell(row,cols.dotState), dotExp: getCell(row,cols.dotExp),
      name: getCell(row,cols.driverName), company: getCell(row,cols.company),
      domStation: getCell(row,cols.domStation), assocStation: getCell(row,cols.assocStation),
      workforceStatus: getCell(row,cols.workforceStatus), sigExp: getCell(row,cols.sigExp),
      driverStatus: getCell(row,cols.driverStatus), mvrExp: getCell(row,cols.mvrExp),
      medExp: getCell(row,cols.medExp), cdas: getCell(row,cols.cdas)
    },
    fadv: {
      fedexId: getCell(row,cols.faFedexId), faId: getCell(row,cols.faId),
      name: getCell(row,cols.faName), dotId: getCell(row,cols.dotId),
      dotState: getCell(row,cols.fadvDotState), jobStatus: getCell(row,cols.jobStatus),
      jobTitle: getCell(row,cols.jobTitle), mvrExp: getCell(row,cols.fadvMvr),
      medExp: getCell(row,cols.fadvMec), certExp: getCell(row,cols.fadvCert)
    }
  })).filter(d => d.fdxId || d.fn || d.ln);
  return { drivers };
}

async function fetchLatestXlsx(account, partial=false) {
  const listRes = await fetch(TOMCAT_BASE + '/dispatch/index.json');
  if (!listRes.ok) throw new Error('Could not reach file index');
  const allFiles = await listRes.json();
  const filtered = allFiles.filter(f => {
    const upperF = f.toUpperCase();
    const upperA = account.toUpperCase();
    if (!upperF.startsWith(upperA)) return false;
    if (partial) return f.includes('partial');
    return !f.includes('partial') && !f.includes('error') && f.endsWith('.xlsx');
  }).sort().reverse();
  if (!filtered.length) throw new Error('No files found for account ' + account);
  return filtered[0];
}

// GET /api/compliance/accounts
app.get('/api/compliance/accounts', requireAuth(['admin','staff']), async (req, res) => {
  try {
    const listRes = await fetch(TOMCAT_BASE + '/dispatch/index.json');
    if (!listRes.ok) throw new Error('Could not reach file index');
    const allFiles = await listRes.json();
    const files = allFiles.filter(f => !f.includes('partial') && !f.includes('error') && f.endsWith('.xlsx'));
    const accounts = {};
    files.forEach(f => {
      const acct = f.match(/^(\d+[A-Z]+)/)?.[1];
      if (acct && (!accounts[acct] || f > accounts[acct])) accounts[acct] = f;
    });
    res.json(Object.entries(accounts).map(([account, filename]) => ({
      account, filename, lastUpdated: filename.match(/(\d{4}-\d{2}-\d{2})/)?.[1] || 'Unknown'
    })));
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// GET /api/compliance/auto/:accountNumber
app.get('/api/compliance/auto/:accountNumber', requireAuth(['admin','staff','client']), async (req, res) => {
  const account = req.params.accountNumber.toUpperCase();
  if (req.user.role === 'client') {
    const userAcct = (req.user.clientName||'').toUpperCase().replace(/[^A-Z0-9]/g,'');
    if (!account.includes(userAcct) && !userAcct.includes(account))
      return res.status(403).json({ error: 'Access denied' });
  }
  try {
    const latestFile = await fetchLatestXlsx(account, false);
    const fileRes = await fetch(TOMCAT_BASE + '/dispatch/' + latestFile);
    if (!fileRes.ok) throw new Error('Could not fetch file');
    const buffer = Buffer.from(await fileRes.arrayBuffer());
    const { drivers } = await parseXlsxFromBuffer(buffer);
    const lastUpdated = latestFile.match(/(\d{4}-\d{2}-\d{2})/)?.[1] || 'Unknown';
    res.json({ account, filename: latestFile, lastUpdated, drivers, count: drivers.length });
  } catch(err) {
    console.error('Compliance auto-fetch error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Dispatch Auto-Fetch ───────────────────────────────────────────────────────
const TOMCAT_BASE = 'https://tomcat-j018.onrender.com';

// GET /api/dispatch/:accountNumber — fetch latest partial file for account
app.get('/api/dispatch/:accountNumber', requireAuth(['admin', 'staff', 'client']), async (req, res) => {
  const account = req.params.accountNumber.toUpperCase();

  // Clients can only see their own account
  if (req.user.role === 'client') {
    const userAccount = (req.user.clientName || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (!account.includes(userAccount) && !userAccount.includes(account)) {
      return res.status(403).json({ error: 'Access denied' });
    }
  }

  try {
    // Fetch directory listing from Tomcat
    const listRes = await fetch(`${TOMCAT_BASE}/dispatch/index.json`);
    if (!listRes.ok) throw new Error('Could not reach dispatch server');
    const allFiles = await listRes.json();

    // Filter to this account and sort by date (newest first)
    const accountFiles = allFiles.filter(f => f.includes('partial') && f.endsWith('.xlsx'))
      .filter(f => f.toUpperCase().startsWith(account))
      .sort()
      .reverse();

    if (accountFiles.length === 0) {
      return res.status(404).json({ error: `No dispatch files found for account ${account}` });
    }

    const latestFile = accountFiles[0];
    console.log(`Fetching dispatch file: ${latestFile}`);

    // Fetch the actual xlsx file
    const fileRes = await fetch(`${TOMCAT_BASE}/dispatch/${latestFile}`);
    if (!fileRes.ok) throw new Error('Could not fetch file');
    const buffer = Buffer.from(await fileRes.arrayBuffer());

    // Parse xlsx using AdmZip
    const AdmZip = (await import('adm-zip')).default;
    const zip = new AdmZip(buffer);

    function extractTexts(xml) {
      const matches = [...xml.matchAll(/<t[^>]*>([^<]*)<\/t>/g)];
      return matches.map(m => m[1]);
    }

    function extractCells(xml) {
      const rows = [...xml.matchAll(/<row[^>]*>(.*?)<\/row>/gs)];
      return rows.map(row => {
        const cells = [...row[1].matchAll(/<c\s([^>]*)>(.*?)<\/c>/gs)];
        return cells.map(cell => {
          const attrs = cell[1];
          const inner = cell[2];
          const t = (attrs.match(/t="([^"]*)"/) || [])[1];
          const v = (inner.match(/<v>([^<]*)<\/v>/) || [])[1];
          return { t, v };
        });
      });
    }

    const stringsEntry = zip.getEntry('xl/sharedStrings.xml');
    const sheetEntry = zip.getEntry('xl/worksheets/sheet1.xml');
    if (!sheetEntry) throw new Error('Invalid xlsx format');

    const shared = stringsEntry ? extractTexts(stringsEntry.getData().toString('utf8')) : [];
    const sheetData = sheetEntry.getData().toString('utf8');
    const allRows = extractCells(sheetData);

    if (allRows.length < 2) return res.status(400).json({ error: 'No data in file' });

    const headers = allRows[0].map(c => {
      if (c.t === 's' && c.v !== undefined) return shared[parseInt(c.v)] || '';
      return c.v || '';
    });

    const fdxIdx = headers.findIndex(h => h.toLowerCase().includes('fdx') || h.toLowerCase().includes('fedex'));
    const firstIdx = headers.findIndex(h => h.toLowerCase().includes('first'));
    const lastIdx = headers.findIndex(h => h.toLowerCase().includes('last'));
    const statusIdx = headers.findIndex(h => h.toLowerCase().includes('status'));

    const drivers = allRows.slice(1).map(row => {
      function getCell(idx) {
        if (idx < 0 || idx >= row.length) return '';
        const c = row[idx];
        if (!c || c.v === undefined) return '';
        if (c.t === 's') return shared[parseInt(c.v)] || '';
        return c.v || '';
      }
      return {
        fdxId: getCell(fdxIdx),
        firstName: getCell(firstIdx),
        lastName: getCell(lastIdx),
        status: getCell(statusIdx)
      };
    }).filter(d => d.fdxId || d.firstName || d.lastName);

    res.json({
      account,
      filename: latestFile,
      lastUpdated: latestFile.match(/\d{4}-\d{2}-\d{2}/)?.[0] || 'Unknown',
      drivers,
      count: drivers.length
    });

  } catch (err) {
    console.error('Dispatch auto-fetch error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/dispatch — list all available accounts (staff/admin only)
app.get('/api/dispatch', requireAuth(['admin', 'staff']), async (req, res) => {
  try {
    const listRes = await fetch(`${TOMCAT_BASE}/dispatch/index.json`);
    if (!listRes.ok) throw new Error('Could not reach dispatch server');
    const allFiles = await listRes.json();
    const fileMatches = allFiles.filter(f => f.includes('partial') && f.endsWith('.xlsx'));

    // Group by account number and get latest per account
    const accounts = {};
    fileMatches.forEach(f => {
      const acct = f.match(/^(\d+[A-Z]+)/)?.[1];
      if (acct) {
        if (!accounts[acct] || f > accounts[acct]) accounts[acct] = f;
      }
    });

    res.json(Object.entries(accounts).map(([account, filename]) => ({
      account,
      filename,
      lastUpdated: filename.match(/\d{4}-\d{2}-\d{2}/)?.[0] || 'Unknown'
    })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Pages ─────────────────────────────────────────────────────────────────────
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, '../public/login.html')));
app.get('/admin', requireAuth(['admin']), (req, res) => res.sendFile(path.join(__dirname, '../public/admin.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, '../public/index.html')));

const PORT = process.env.PORT || 3000;
initDB().then(() => app.listen(PORT, () => console.log(`Server running on port ${PORT}`)));
