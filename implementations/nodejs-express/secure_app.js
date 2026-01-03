/**
 * SQL Injection Secure Implementation - Node.js Express with sql.js
 * Demonstrates proper defense mechanisms using parameterized queries
 */

const express = require('express');
const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

const DB_FILE = path.join(__dirname, 'data', 'sqlite.db');
let SQL;
let db;

function loadDatabase() {
  const filebuffer = fs.readFileSync(DB_FILE);
  const u8 = new Uint8Array(filebuffer);
  return new SQL.Database(u8);
}

const PORT = 3002;

(async () => {
  SQL = await initSqlJs();
  db = loadDatabase();

  app.listen(PORT, () => {
      console.log('='.repeat(60));
      console.log('Secure Express Application - SQL Injection Protected');
      console.log('Using parameterized queries via sql.js');
      console.log('='.repeat(60));
      console.log(`Server running on http://localhost:${PORT}`);
  });
})();

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const stmt = db.prepare('SELECT UserId, Username, Email, Role FROM Users WHERE Username = :username AND PasswordHash = :password');
        stmt.bind({':username': username, ':password': password});

        const hasRow = stmt.step();
        if (hasRow) {
            const row = stmt.getAsObject();
            res.json({ success: true, user: { id: row.UserId, username: row.Username, email: row.Email, role: row.Role } });
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

    try {
        const searchPattern = `%${searchTerm}%`;
        const stmt = db.prepare('SELECT PostId, Title, Content FROM Posts WHERE Title LIKE :p OR Content LIKE :p');
        stmt.bind({ ':p': searchPattern });

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
    res.json({ status: 'running', version: 'secure' });
});
