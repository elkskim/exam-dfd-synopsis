# Node.js Express SQL Injection Demo - Test Results

## Setup Complete ✅

Both servers are running and tested successfully:
- **Vulnerable Server**: `http://localhost:3001` 
- **Secure Server**: `http://localhost:3002`
- **Database**: SQLite via sql.js (implementations/nodejs-express/data/sqlite.db)

## Test Results Summary

### Vulnerable Application (Port 3001)

#### ✅ Normal Login Works
```bash
curl -X POST http://localhost:3001/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}'
```
**Result**: Successfully authenticated as alice

#### 🚨 SQL Injection Auth Bypass (VULNERABLE)
```bash
curl -X POST http://localhost:3001/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' OR '\''1'\''='\''1'\''--","password":"anything"}'
```
**Result**: ✅ Bypassed authentication! Logged in as admin without valid credentials

#### 🚨 UNION-Based Data Extraction (VULNERABLE)
```bash
curl "http://localhost:3001/api/posts/search?q=' UNION SELECT UserId, Username, Email FROM Users--"
```
**Result**: ✅ Extracted 21 records (including sensitive user data)

#### 🚨 Boolean Blind SQL Injection (VULNERABLE)
```bash
curl "http://localhost:3001/api/posts/search?q=' AND 1=1--"   # Returns 13 posts
curl "http://localhost:3001/api/posts/search?q=' AND 1=2--"   # Returns 0 posts
```
**Result**: ✅ Different results confirm query manipulation possible

### Secure Application (Port 3002)

#### ✅ Normal Login Works
```bash
curl -X POST http://localhost:3002/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}'
```
**Result**: Successfully authenticated as alice

#### ✅ SQL Injection Auth Bypass (BLOCKED)
```bash
curl -X POST http://localhost:3002/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' OR '\''1'\''='\''1'\''--","password":"anything"}'
```
**Result**: ❌ Attack failed - returned "Invalid credentials" (Status 401)

#### ✅ UNION-Based Data Extraction (BLOCKED)
```bash
curl "http://localhost:3002/api/posts/search?q=' UNION SELECT UserId, Username, Email FROM Users--"
```
**Result**: ❌ Attack failed - malicious input treated as literal string

#### ✅ Boolean Blind SQL Injection (BLOCKED)
```bash
curl "http://localhost:3002/api/posts/search?q=' AND 1=1--"   # Returns 0 posts
curl "http://localhost:3002/api/posts/search?q=' AND 1=2--"   # Returns 0 posts
```
**Result**: ❌ Attack failed - same results for both (no query manipulation)

## Key Differences in Code

### Vulnerable Version (vulnerable_app.js)
```javascript
// ❌ INSECURE: String interpolation
const query = `SELECT UserId, Username, Email, Role FROM Users 
               WHERE Username = '${username}' AND PasswordHash = '${password}'`;
const stmt = db.prepare(query);
```

### Secure Version (secure_app.js)
```javascript
// ✅ SECURE: Parameterized queries
const stmt = db.prepare('SELECT UserId, Username, Email, Role FROM Users 
                         WHERE Username = :username AND PasswordHash = :password');
stmt.bind({':username': username, ':password': password});
```

## Commands Reference

### Start Servers
```bash
cd implementations\nodejs-express

# Terminal 1: Vulnerable server
npm run start:vulnerable

# Terminal 2: Secure server  
npm run start:secure
```

### Run All Tests
```bash
cd implementations\nodejs-express
npm run test:attacks
```

### Manual Testing Examples

**Test legitimate login:**
```bash
curl -X POST http://localhost:3001/api/login -H "Content-Type: application/json" -d "{\"username\":\"alice\",\"password\":\"password123\"}"
```

**Test SQL injection attack:**
```bash
curl -X POST http://localhost:3001/api/login -H "Content-Type: application/json" -d "{\"username\":\"admin' OR '1'='1'--\",\"password\":\"anything\"}"
```

**Test search (normal):**
```bash
curl "http://localhost:3001/api/posts/search?q=security"
```

**Test search (injection):**
```bash
curl "http://localhost:3001/api/posts/search?q=' UNION SELECT UserId, Username, Email FROM Users--"
```

## Database Credentials (for testing)

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | admin |
| alice | password123 | user |
| bob | securepass456 | user |
| charlie | charlie789 | user |

## Notes for Your Synopsis

1. **Vulnerable app demonstrates**:
   - Authentication bypass via SQL injection
   - Data exfiltration via UNION-based injection
   - Boolean blind SQL injection for database enumeration
   - All attacks succeed because of string concatenation

2. **Secure app demonstrates**:
   - Parameterized queries prevent all SQL injection attacks
   - Malicious input treated as literal data, not SQL code
   - Same functionality for legitimate users
   - Simple code change (`.bind()` with named parameters) provides complete protection

3. **Technology stack**:
   - Node.js + Express.js (popular JavaScript backend framework)
   - sql.js (SQLite via WebAssembly - no native dependencies needed)
   - Pure JavaScript - no compilation required
   - Easy to run and demonstrate

## Stopping the Servers

To stop the servers, you can either:
1. Close the terminal windows, or
2. Press `Ctrl+C` in each terminal running a server

