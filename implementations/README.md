# SQL Injection Defense Mechanisms - Implementations

This directory contains the practical implementations for the comparative study of SQL injection defense mechanisms across three programming ecosystems.

## Structure

```
implementations/
├── csharp-dotnet/          # C# .NET 8 with ASP.NET Core & Entity Framework
│   ├── vulnerable/         # Vulnerable baseline (string concatenation)
│   └── secured/            # Secured version (EF Core, parameterized queries)
├── python-flask/           # Python 3.12 with Flask & SQLAlchemy
│   ├── vulnerable/         # Vulnerable baseline (string formatting)
│   └── secured/            # Secured version (SQLAlchemy ORM)
└── nodejs-express/         # Node.js 20 LTS with Express & Sequelize
    ├── vulnerable/         # Vulnerable baseline (template literals)
    └── secured/            # Secured version (Sequelize ORM)
```

## Database Schema

All implementations use the same SQL Server database schema:

```sql
CREATE TABLE Users (
    Id INT PRIMARY KEY IDENTITY(1,1),
    Username NVARCHAR(50) NOT NULL UNIQUE,
    Password NVARCHAR(255) NOT NULL,
    Email NVARCHAR(100),
    CreatedAt DATETIME DEFAULT GETDATE()
);
```

## Common API Endpoints

Each implementation provides the following REST endpoints:

1. **POST /api/auth/login**
   - Vulnerable: Direct string concatenation/interpolation
   - Secured: Parameterized queries or ORM
   - Payload: `{ "username": "...", "password": "..." }`

2. **GET /api/users/:id**
   - Retrieve user by ID
   - Tests numeric parameter handling

3. **GET /api/users/search?name=...**
   - Search users by name
   - Most vulnerable to injection attacks

## Testing Approach

- **Manual Testing**: Use Postman/curl with malicious payloads
- **Automated Testing**: sqlmap for comprehensive attack simulation
- **Performance Testing**: Apache Bench for load testing

## Attack Vectors to Test

1. **Authentication Bypass**: `' OR '1'='1'--`
2. **Union-based**: `' UNION SELECT NULL, NULL, NULL--`
3. **Boolean-based Blind**: `' AND 1=1--` vs `' AND 1=2--`
4. **Time-based Blind**: `'; WAITFOR DELAY '00:00:05'--`

## Development Order

1. Set up database (see `/database/` folder)
2. Implement vulnerable versions (quick, intentionally insecure)
3. Test vulnerable versions with attack payloads
4. Implement secured versions (proper defensive measures)
5. Verify secured versions resist attacks
6. Conduct performance comparison

