# Node.js Express Implementation

Express 4.18 with Sequelize 6.35

## Structure

```
nodejs-express/
├── vulnerable/         # Vulnerable implementation (template literals)
│   ├── server.js
│   ├── routes/
│   ├── package.json
│   └── .env
└── secured/           # Secured implementation (Sequelize ORM)
    ├── server.js
    ├── models/
    ├── routes/
    ├── config/
    ├── package.json
    └── .env
```

## Setup

```bash
# Initialize Node.js projects
cd vulnerable
npm init -y
npm install express mssql dotenv

cd ../secured
npm init -y
npm install express sequelize mssql dotenv
```

## Environment Variables

Create `.env` file:
```
DB_SERVER=localhost
DB_DATABASE=SQLInjectionTest
DB_TRUSTED_CONNECTION=true
PORT=3000
```

## Run

```bash
# Vulnerable version (runs on http://localhost:3000)
cd vulnerable
node server.js

# Secured version (runs on http://localhost:3001)
cd secured
node server.js
```

## Key Differences

### Vulnerable
- Template literal SQL injection
- Direct string interpolation with ${}
- Manual query execution

### Secured
- Sequelize ORM models
- Parameterized queries
- Query builder prevents injection
- Promise-based async operations

