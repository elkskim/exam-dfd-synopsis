/**
 * SQL Injection Vulnerable Implementation - Node.js Express (sql.js)
 * INTENTIONALLY INSECURE - For educational purposes only
 */

const express = require('express');
const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

const DB_FILE = path.join(__dirname, 'data', 'sqlite.db');
let SQL; // sql.js module
let db;  // in-memory DB instance

function loadDatabase() {
  const filebuffer = fs.readFileSync(DB_FILE);
  const u8 = new Uint8Array(filebuffer);
  return new SQL.Database(u8);
}

const PORT = 3001;

(async () => {
  SQL = await initSqlJs();
  db = loadDatabase();

  app.listen(PORT, () => {
      console.log('='.repeat(60));
      console.log('WARNING: This is an INTENTIONALLY VULNERABLE application!');
      console.log('For educational purposes only - DO NOT use in production');
      console.log('='.repeat(60));
      console.log(`Server running on http://localhost:${PORT}`);
  });
})();

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    // VULNERABILITY: Direct string interpolation
    const query = `SELECT UserId, Username, Email, Role FROM Users WHERE Username = '${username}' AND PasswordHash = '${password}'`;

    try {
        const stmt = db.prepare(query);
        const hasRow = stmt.step();

        if (hasRow) {
            const row = stmt.getAsObject();
            res.json({
                success: true,
                user: {
                    id: row.UserId,
                    username: row.Username,
                    email: row.Email,
                    role: row.Role
                }
            });
        } else {
            res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        stmt.free();
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/posts/search', async (req, res) => {
    const searchTerm = req.query.q || '';
    const query = `SELECT PostId, Title, Content FROM Posts WHERE Title LIKE '%${searchTerm}%' OR Content LIKE '%${searchTerm}%'`;

    try {
        const stmt = db.prepare(query);
        const posts = [];
        while (stmt.step()) {
            const row = stmt.getAsObject();
            posts.push({ id: row.PostId, title: row.Title, content: row.Content });
        }
        stmt.free();
        res.json({ success: true, posts });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'running', version: 'vulnerable' });
});
