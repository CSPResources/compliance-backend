import express from 'express';
import pg from 'pg';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(express.json());

// Serve static files
app.use(express.static(path.join(__dirname, '../public')));

// PostgreSQL connection
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

// Initialize database table
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS reports (
      id SERIAL PRIMARY KEY,
      client_name TEXT NOT NULL,
      data JSONB NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_reports_client ON reports(client_name);
    CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at DESC);
  `);
  console.log('Database ready.');
}

// -----------------------------------------------
// POST /api/reports — orchestrator posts data here
// -----------------------------------------------
app.post('/api/reports', async (req, res) => {
  const apiKey = req.headers['x-api-key'];
  if (apiKey !== process.env.WEBSITE_API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { client, data, timestamp } = req.body;
  if (!client || !data) {
    return res.status(400).json({ error: 'Missing client or data' });
  }

  try {
    await pool.query(
      'INSERT INTO reports (client_name, data, created_at) VALUES ($1, $2, $3)',
      [client, JSON.stringify(data), timestamp || new Date().toISOString()]
    );
    console.log(`Report saved for client: ${client}`);
    res.json({ success: true });
  } catch (err) {
    console.error('DB insert error:', err.message);
    res.status(500).json({ error: 'Database error' });
  }
});

// -----------------------------------------------
// GET /api/reports/:clientName — dashboard fetches data
// -----------------------------------------------
app.get('/api/reports/:clientName', async (req, res) => {
  const apiKey = req.headers['x-api-key'];
  if (apiKey !== process.env.WEBSITE_API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const result = await pool.query(
      `SELECT data, created_at FROM reports 
       WHERE client_name = $1 
       ORDER BY created_at DESC LIMIT 1`,
      [req.params.clientName]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No data found for this client' });
    }

    res.json({
      client: req.params.clientName,
      data: result.rows[0].data,
      lastUpdated: result.rows[0].created_at
    });
  } catch (err) {
    console.error('DB query error:', err.message);
    res.status(500).json({ error: 'Database error' });
  }
});

// -----------------------------------------------
// GET /api/clients — list all clients with data
// -----------------------------------------------
app.get('/api/clients', async (req, res) => {
  const apiKey = req.headers['x-api-key'];
  if (apiKey !== process.env.WEBSITE_API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const result = await pool.query(
      `SELECT DISTINCT ON (client_name) client_name, created_at 
       FROM reports ORDER BY client_name, created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// -----------------------------------------------
// GET / — serve the dashboard
// -----------------------------------------------
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

const PORT = process.env.PORT || 3000;
initDB().then(() => {
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
});
