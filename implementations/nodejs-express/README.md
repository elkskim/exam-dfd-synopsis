# Node.js Express Implementation

SQL Injection demonstration with vulnerable and secure versions (SQLite local DB).

## Setup

### 1. Install Dependencies
```cmd
cd implementations\nodejs-express
npm install
```

### 2. Initialize local SQLite database
```cmd
cd implementations\nodejs-express
npm run init-db
```
This will create `implementations/nodejs-express/data/sqlite.db` and seed it with test users and posts.

## Running the Applications

Start the vulnerable app (port 3001):
```cmd
cd implementations\nodejs-express
npm run start:vulnerable
```

Start the secure app (port 3002) in a new terminal:
```cmd
cd implementations\nodejs-express
npm run start:secure
```

## Testing

With both servers running, open a third terminal and run the attack tester:
```cmd
cd implementations\nodejs-express
npm run test:attacks
```

## Notes
- The vulnerable app intentionally concatenates user input into SQL to demonstrate SQL injection. The secure app uses parameterized queries.
- If you previously had a MSSQL-based DB, this SQLite variant is a zero-dependency way to run the demo locally.

## Manual Testing with curl

### Test Login Endpoint

**Normal Login:**
```cmd
curl -X POST http://localhost:3001/api/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"alice\",\"password\":\"password123\"}"
```

**SQL Injection Attack (Vulnerable):**
```cmd
curl -X POST http://localhost:3001/api/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"admin' OR '1'='1'--\",\"password\":\"anything\"}"
```

## Key Differences

### Vulnerable Version (`vulnerable_app.js`)
- ❌ Uses template literals for SQL query construction
- ❌ Direct string interpolation
- ❌ No input sanitization
- ❌ Allows arbitrary SQL execution

### Secure Version (`secure_app.js`)
- ✅ Uses mssql's parameterized queries
- ✅ Input parameters typed and bound
- ✅ Database driver handles escaping
- ✅ SQL structure is fixed

## Notes and Next Steps
- `npm install` completed successfully after fixing a malformed `package.json` that was previously empty.
- You may see warnings about unsupported engines for some transitive dependencies when using very new Node.js versions (example: Node 24). These are warnings only — to remove them use an LTS Node version (18 or 20) via nvm.
- To fully run the apps you need a reachable SQL Server instance configured as in `vulnerable_app.js`/`secure_app.js` (or modify `config` to point at a local test DB). If you want, I can help change the apps to use SQLite for an easier demo that doesn't require setting up SQL Server.

If you'd like, I can also:
- Add convenience npm scripts that exactly match older README names (e.g., `vulnerable` / `secure` / `test`) if you prefer those commands.
- Convert the demo to use SQLite (fast local setup) so you can run the whole demo without installing SQL Server.
