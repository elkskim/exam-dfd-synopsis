-- Seed data for SQL Injection testing
-- SQL Server 2022

USE SQLInjectionTest;
GO

-- Clear existing data
DELETE FROM Users;
GO

-- Insert test users
-- NOTE: In real applications, passwords should be hashed!
-- These are plain text for testing purposes only
INSERT INTO Users (Username, Password, Email, Role) VALUES
('admin', 'admin123', 'admin@test.com', 'admin'),
('user1', 'password123', 'user1@test.com', 'user'),
('user2', 'password123', 'user2@test.com', 'user'),
('testuser', 'test456', 'test@test.com', 'user'),
('guest', 'guest789', 'guest@test.com', 'guest'),
('john.doe', 'john123', 'john@test.com', 'user'),
('jane.smith', 'jane456', 'jane@test.com', 'user'),
('bob.wilson', 'bob789', 'bob@test.com', 'user');
GO

-- Verify data insertion
SELECT COUNT(*) AS TotalUsers FROM Users;
SELECT * FROM Users ORDER BY Id;
GO

-- Display connection test query
SELECT 'Database seeded successfully!' AS Status,
       GETDATE() AS SeedTime;
GO

