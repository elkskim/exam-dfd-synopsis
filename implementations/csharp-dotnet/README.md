# C# .NET Implementation

ASP.NET Core 8.0 with Entity Framework Core 8.0

## Structure

```
csharp-dotnet/
├── vulnerable/         # Vulnerable implementation (string concatenation)
│   ├── Controllers/
│   ├── Models/
│   ├── Program.cs
│   └── appsettings.json
└── secured/           # Secured implementation (EF Core LINQ)
    ├── Controllers/
    ├── Models/
    ├── Data/
    ├── Program.cs
    └── appsettings.json
```

## Setup

```bash
# Create new Web API projects
dotnet new webapi -n VulnerableApi -o vulnerable
dotnet new webapi -n SecuredApi -o secured

# Add Entity Framework Core packages (secured version)
cd secured
dotnet add package Microsoft.EntityFrameworkCore.SqlServer
dotnet add package Microsoft.EntityFrameworkCore.Design

# Add SQL client (vulnerable version)
cd ../vulnerable
dotnet add package Microsoft.Data.SqlClient
```

## Connection String

Add to `appsettings.json`:
```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=SQLInjectionTest;Integrated Security=true;TrustServerCertificate=true;"
  }
}
```

## Run

```bash
# Vulnerable version (runs on http://localhost:5001)
cd vulnerable
dotnet run

# Secured version (runs on http://localhost:5002)
cd secured
dotnet run
```

## Key Differences

### Vulnerable
- Direct SQL string concatenation
- No parameterization
- Manual database connection management

### Secured
- Entity Framework Core LINQ queries
- Automatic parameterization
- Type-safe query construction
- Compile-time query validation

