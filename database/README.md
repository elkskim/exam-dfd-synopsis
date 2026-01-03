# Database Schema

Simple but realistic SQL Server database for SQL injection testing.

## Schema Overview

### Tables

**Users**
- Authentication target (username/password lookups)
- Contains admin and regular users
- Perfect for testing authentication bypass attacks

**Posts**  
- Content storage and retrieval
- Mix of public and private posts
- Good for testing data exfiltration attacks

## Setup Instructions

### Option 1: SQL Server Management Studio (SSMS)
1. Open SSMS and connect to your SQL Server 2022 instance
2. Create a new database: `CREATE DATABASE SQLInjectionTest;`
3. Select the database: `USE SQLInjectionTest;`
4. Run `schema.sql` to create tables
5. Run `seed.sql` to populate test data

### Option 2: Command Line (sqlcmd)
```cmd
sqlcmd -S localhost -E -Q "CREATE DATABASE SQLInjectionTest;"
sqlcmd -S localhost -E -d SQLInjectionTest -i schema.sql
sqlcmd -S localhost -E -d SQLInjectionTest -i seed.sql
```

### Option 3: From your application
Each implementation can run these scripts on startup for testing.

## Connection String Template

```
Server=localhost;Database=SQLInjectionTest;Integrated Security=true;TrustServerCertificate=true;
```

Or with SQL Auth:
```
Server=localhost;Database=SQLInjectionTest;User Id=your_user;Password=your_password;TrustServerCertificate=true;
```

## Test Scenarios

### Authentication Bypass
Attack the login endpoint with:
- `admin' OR '1'='1' --`
- `admin'--`
- `' OR 1=1--`

Target endpoint: Login with username/password

### Data Extraction
Attack the search/lookup endpoints with:
- `1' UNION SELECT Username, PasswordHash, Email FROM Users--`
- `1' AND 1=1--` (boolean-based blind)
- Time-based blind attacks

Target endpoint: Post search or user lookup

### Data Modification
Test UPDATE/DELETE injection:
- Modify post content
- Delete user accounts
- Privilege escalation

## Quick Verification Query

```sql
-- Check everything is set up correctly
SELECT 
    'Users' AS Table_Name, COUNT(*) AS Row_Count FROM Users
UNION ALL
SELECT 'Posts', COUNT(*) FROM Posts;

-- View test accounts
SELECT Username, Email, Role FROM Users ORDER BY Role DESC, Username;

-- View posts with authors
SELECT u.Username, p.Title, p.IsPublished 
FROM Posts p 
JOIN Users u ON p.UserId = u.UserId 
ORDER BY p.CreatedAt DESC;
```

## Notes for Testing

- **admin** user has sensitive posts that should not leak
- Some posts are marked `IsPublished=0` (drafts/private)
- Contains deliberately "sensitive" data in posts to verify data leakage
- Password field is plaintext for easy attack verification (obviously bad in real apps!)

## Cleanup

```sql
DROP DATABASE SQLInjectionTest;
```

