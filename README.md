# Compliance Dashboard Backend

## What This Is
A Node.js/Express API that:
- Receives compliance report data from the orchestrator (Brad's script)
- Stores it in PostgreSQL
- Serves the compliance dashboard to clients

## Deploy to Render

### Step 1: Create PostgreSQL Database
1. Render Dashboard → New → PostgreSQL
2. Name it `compliance-db`
3. Copy the **Internal Database URL**

### Step 2: Deploy This Web Service
1. Render Dashboard → New → Web Service
2. Connect this GitHub repo
3. Set:
   - **Environment**: Node
   - **Build Command**: `npm install`
   - **Start Command**: `node src/server.js`
4. Add Environment Variables:
   - `DATABASE_URL` = your PostgreSQL connection string
   - `WEBSITE_API_KEY` = a secret key you make up (e.g. `my-secret-key-123`)
   - `NODE_ENV` = `production`
   - `NODE_VERSION` = `20.11.1`

### Step 3: Configure the Orchestrator
In the fleet-reporting repo, set these environment variables (in Render or .env):
- `WEBSITE_API_URL` = your Render web service URL (e.g. `https://compliance-backend.onrender.com`)
- `WEBSITE_API_KEY` = same secret key as above

## Environment Variables Summary

| Variable | Where | Value |
|---|---|---|
| `DATABASE_URL` | Backend | From Render PostgreSQL |
| `WEBSITE_API_KEY` | Backend + Orchestrator | Same secret key |
| `WEBSITE_API_URL` | Orchestrator | Your backend's Render URL |
| `NODE_ENV` | Both | `production` |
