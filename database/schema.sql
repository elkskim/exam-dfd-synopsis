-- SQL Injection Test Database Schema
-- Simple but realistic design for security testing
-- Microsoft SQL Server 2022

-- Drop tables if they exist (for clean re-runs)
IF OBJECT_ID('dbo.Posts', 'U') IS NOT NULL DROP TABLE dbo.Posts;
IF OBJECT_ID('dbo.Users', 'U') IS NOT NULL DROP TABLE dbo.Users;

-- Users table - primary target for authentication bypass attacks
CREATE TABLE Users (
    UserId INT PRIMARY KEY IDENTITY(1,1),
    Username NVARCHAR(50) NOT NULL UNIQUE,
    Email NVARCHAR(100) NOT NULL,
    PasswordHash NVARCHAR(255) NOT NULL,  -- In real app would be properly hashed
    Role NVARCHAR(20) NOT NULL DEFAULT 'user',  -- 'user' or 'admin'
    CreatedAt DATETIME2 NOT NULL DEFAULT GETDATE(),
    IsActive BIT NOT NULL DEFAULT 1
);

-- Posts table - target for data extraction and manipulation attacks
CREATE TABLE Posts (
    PostId INT PRIMARY KEY IDENTITY(1,1),
    UserId INT NOT NULL,
    Title NVARCHAR(200) NOT NULL,
    Content NVARCHAR(MAX) NOT NULL,
    IsPublished BIT NOT NULL DEFAULT 1,
    CreatedAt DATETIME2 NOT NULL DEFAULT GETDATE(),
    UpdatedAt DATETIME2 NOT NULL DEFAULT GETDATE(),
    CONSTRAINT FK_Posts_Users FOREIGN KEY (UserId) 
        REFERENCES Users(UserId) ON DELETE CASCADE
);

-- Indexes for better query performance (and realistic schema)
CREATE INDEX IX_Users_Username ON Users(Username);
CREATE INDEX IX_Users_Email ON Users(Email);
CREATE INDEX IX_Posts_UserId ON Posts(UserId);
CREATE INDEX IX_Posts_CreatedAt ON Posts(CreatedAt DESC);

GO

