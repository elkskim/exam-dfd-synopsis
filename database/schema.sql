-- Database schema for SQL Injection testing
-- SQL Server 2022

USE SQLInjectionTest;
GO

-- Drop table if exists (for clean setup)
IF OBJECT_ID('Users', 'U') IS NOT NULL
    DROP TABLE Users;
GO

-- Create Users table
CREATE TABLE Users (
    Id INT PRIMARY KEY IDENTITY(1,1),
    Username NVARCHAR(50) NOT NULL UNIQUE,
    Password NVARCHAR(255) NOT NULL,
    Email NVARCHAR(100),
    Role NVARCHAR(20) DEFAULT 'user',
    CreatedAt DATETIME DEFAULT GETDATE(),
    LastLogin DATETIME NULL
);
GO

-- Create index for common queries
CREATE INDEX IX_Users_Username ON Users(Username);
GO

-- Verify table creation
SELECT 'Table created successfully' AS Status;
SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'Users';
GO

