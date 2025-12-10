# Database Setup

This folder contains SQL scripts for setting up the test database.

## Setup Instructions

1. **Install SQL Server 2022** (or use existing instance)

2. **Create Database**:
   ```sql
   CREATE DATABASE SQLInjectionTest;
   GO
   ```

3. **Run Schema Script**:
   Execute `schema.sql` to create tables

4. **Run Seed Script**:
   Execute `seed.sql` to populate test data

## Connection String Format

```
Server=localhost;Database=SQLInjectionTest;Integrated Security=true;TrustServerCertificate=true;
```

Or with credentials:
```
Server=localhost;Database=SQLInjectionTest;User Id=sa;Password=YourPassword;TrustServerCertificate=true;
```

## Test Data

The seed script creates:
- 5 test users with known credentials
- Usernames: admin, user1, user2, testuser, guest
- Default password for testing: "password123"

**IMPORTANT**: This is a test database for security research. Never use these patterns in production!

