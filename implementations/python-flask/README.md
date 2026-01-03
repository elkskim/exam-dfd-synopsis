# Python Flask Implementation - SQLite

SQL Injection demonstration with vulnerable and secure versions using SQLite database.

## Setup

### 1. Install Dependencies
```bash
cd implementations/python-flask
pip install -r requirements.txt
```

**Dependencies:**
- Flask 3.0.0
- SQLAlchemy 2.0.45+
- requests 2.31.0

### 2. Database
The SQLite database (`data/sqlite.db`) is shared with the Node.js implementation and contains:
- 8 users (admin, alice, bob, charlie, david, eve, frank, grace)
- 13 posts with various content

## Running the Applications

### Start Vulnerable Version (Port 5001)
```bash
python vulnerable_app.py
```

### Start Secure Version (Port 5002)
Open a new terminal:
```bash
python secure_app.py
```

## Testing

### Quick Test (Single Server)
Test one server at a time:
```bash
# Test vulnerable version
python quick_test.py 5001

# Test secure version
python quick_test.py 5002
```

### Comprehensive Test (Both Servers)
With both servers running:
```bash
python test_attacks.py
```

See `TEST_RESULTS.md` for detailed test results and analysis.

## Manual Testing with curl

### Test Login Endpoint

**Normal Login:**
```bash
curl -X POST http://localhost:5001/api/login \
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"alice\",\"password\":\"password123\"}"
```

**SQL Injection Attack (Vulnerable):**
```cmd
curl -X POST http://localhost:5001/api/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"admin' OR '1'='1'--\",\"password\":\"anything\"}"
```

**Same Attack Against Secure Version:**
```cmd
curl -X POST http://localhost:5002/api/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"admin' OR '1'='1'--\",\"password\":\"anything\"}"
```

### Test Search Endpoint

**Normal Search:**
```cmd
curl "http://localhost:5001/api/posts/search?q=security"
```

**UNION Injection Attack (Vulnerable):**
```cmd
curl "http://localhost:5001/api/posts/search?q=' UNION SELECT UserId, Username, Email FROM Users--"
```

**Same Attack Against Secure Version:**
```cmd
curl "http://localhost:5002/api/posts/search?q=' UNION SELECT UserId, Username, Email FROM Users--"
```

## Key Differences

### Vulnerable Version (`vulnerable_app.py`)
- ❌ Uses f-strings for SQL query construction
- ❌ Direct string concatenation
- ❌ No input sanitization
- ❌ Allows arbitrary SQL execution

```python
# VULNERABLE CODE
query = f"SELECT * FROM Users WHERE Username = '{username}'"
cursor.execute(query)
```

### Secure Version (`secure_app.py`)
- ✅ Uses SQLAlchemy's parameterized queries
- ✅ Bound parameters prevent injection
- ✅ Database driver handles escaping
- ✅ SQL structure is fixed

```python
# SECURE CODE
query = text("SELECT * FROM Users WHERE Username = :username")
result = session.execute(query, {'username': username})
```

## What You'll Observe

### Vulnerable Version
- Auth bypass works with `admin' OR '1'='1'--`
- UNION injection extracts user data
- Boolean blind injection works
- Error messages may leak database structure

### Secure Version
- All attacks fail gracefully
- Malicious input treated as literal strings
- No data leakage
- Returns "Invalid credentials" or empty results

## Developer Experience Notes

**Pros:**
- Flask is lightweight and fast to set up
- SQLAlchemy has excellent documentation
- Parameterized queries are natural in Python
- Clear error messages during development

**Cons:**
- No compile-time type checking (dynamic typing)
- Requires understanding of SQLAlchemy's `text()` API
- Easy to accidentally use f-strings instead of parameters

**Verdict:** Easy to secure if you know the pattern, but also easy to make mistakes with dynamic typing.

