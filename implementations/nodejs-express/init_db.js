const fs = require('fs');
const path = require('path');
const initSqlJs = require('sql.js');

const dataDir = path.join(__dirname, 'data');
const dbPath = path.join(dataDir, 'sqlite.db');

if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir);
}

(async () => {
  const SQL = await initSqlJs();

  // Create a new database
  const db = new SQL.Database();

  // Create schema
  db.run(`
    PRAGMA foreign_keys = ON;

    CREATE TABLE Users (
      UserId INTEGER PRIMARY KEY AUTOINCREMENT,
      Username TEXT NOT NULL UNIQUE,
      Email TEXT NOT NULL,
      PasswordHash TEXT NOT NULL,
      Role TEXT NOT NULL DEFAULT 'user',
      CreatedAt DATETIME DEFAULT (datetime('now')),
      IsActive INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE Posts (
      PostId INTEGER PRIMARY KEY AUTOINCREMENT,
      UserId INTEGER NOT NULL,
      Title TEXT NOT NULL,
      Content TEXT NOT NULL,
      IsPublished INTEGER NOT NULL DEFAULT 1,
      CreatedAt DATETIME DEFAULT (datetime('now')),
      UpdatedAt DATETIME DEFAULT (datetime('now')),
      FOREIGN KEY (UserId) REFERENCES Users(UserId) ON DELETE CASCADE
    );
  `);

  // Seed users
  const insertUser = db.prepare('INSERT INTO Users (Username, Email, PasswordHash, Role, IsActive) VALUES (?, ?, ?, ?, ?)');
  const users = [
    ['admin', 'admin@example.com', 'admin123', 'admin', 1],
    ['alice', 'alice@example.com', 'password123', 'user', 1],
    ['bob', 'bob@example.com', 'securepass456', 'user', 1],
    ['charlie', 'charlie@example.com', 'charlie789', 'user', 1],
    ['dave', 'dave@example.com', 'dave2023!', 'user', 1],
    ['eve', 'eve@example.com', 'evileve666', 'user', 0],
    ['frank', 'frank@example.com', 'frankenstein', 'admin', 1],
    ['grace', 'grace@example.com', 'graceful123', 'user', 1]
  ];

  db.run('BEGIN TRANSACTION');
  users.forEach(u => insertUser.run(u));
  db.run('COMMIT');

  // Seed posts
  const insertPost = db.prepare('INSERT INTO Posts (UserId, Title, Content, IsPublished) VALUES (?, ?, ?, ?)');
  const posts = [
    [1, 'Welcome to the Platform', 'This is the official welcome message from the admin team. We hope you enjoy using our platform!', 1],
    [1, 'Security Update Notice', 'CONFIDENTIAL: All admin credentials have been rotated. New master key: ADM1N-S3CR3T-K3Y-2023', 1],
    [7, 'Admin Meeting Notes', 'INTERNAL: Server credentials - DB_PASSWORD=SuperSecret123, API_KEY=sk_live_12345', 1],
    [2, 'My First Post', 'Hello everyone! This is Alice. Excited to be here and share my thoughts.', 1],
    [2, 'Weekend Adventures', 'Had an amazing weekend hiking in the mountains. The views were breathtaking!', 1],
    [3, 'Tech Tips: Database Security', 'Always use parameterized queries to prevent SQL injection attacks. Never concatenate user input!', 1],
    [3, 'Private Draft', 'This is a private draft that should not be visible to others. Contains sensitive info.', 0],
    [4, 'Book Recommendations', 'Just finished reading "The Phoenix Project". Highly recommend for anyone in tech!', 1],
    [4, 'Recipe: Best Chocolate Cake', 'Here is my secret family recipe for chocolate cake that won multiple awards...', 1],
    [5, 'Travel Blog: Japan 2023', 'Day 1 in Tokyo: Visited Shibuya crossing, ate the best ramen of my life!', 1],
    [5, 'Credit Card Info - DO NOT PUBLISH', 'CARD: 4532-1234-5678-9010, CVV: 123, EXP: 12/25 - for booking flight', 0],
    [8, 'Photography Tips', 'Golden hour lighting can make any photo look professional. Here are my settings...', 1],
    [8, 'Confidential: API Keys', 'STRIPE_KEY=sk_test_abcdef123456, AWS_SECRET=AKIA1234567890EXAMPLE', 0]
  ];

  db.run('BEGIN TRANSACTION');
  posts.forEach(p => insertPost.run(p));
  db.run('COMMIT');

  // Export the database to a Uint8Array and write to disk
  const binaryArray = db.export();
  fs.writeFileSync(dbPath, Buffer.from(binaryArray));

  console.log('Database initialized at', dbPath);
  console.log('You can now run: npm run start:vulnerable and npm run start:secure');

  // free prepared statements
  insertUser.free();
  insertPost.free();
  db.close();
})();
