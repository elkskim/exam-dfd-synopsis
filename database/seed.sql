-- Seed data for SQL Injection testing
-- Includes various scenarios for authentication bypass and data extraction attacks

-- Insert test users
-- Note: In a real app, passwords would be properly hashed (bcrypt, Argon2, etc.)
-- For testing purposes, these are plaintext-ish to make attack verification easier
INSERT INTO Users (Username, Email, PasswordHash, Role, IsActive) VALUES
('admin', 'admin@example.com', 'admin123', 'admin', 1),
('alice', 'alice@example.com', 'password123', 'user', 1),
('bob', 'bob@example.com', 'securepass456', 'user', 1),
('charlie', 'charlie@example.com', 'charlie789', 'user', 1),
('dave', 'dave@example.com', 'dave2023!', 'user', 1),
('eve', 'eve@example.com', 'evileve666', 'user', 0),  -- Inactive user for edge case testing
('frank', 'frank@example.com', 'frankenstein', 'admin', 1),
('grace', 'grace@example.com', 'graceful123', 'user', 1);

-- Insert test posts with varying content
INSERT INTO Posts (UserId, Title, Content, IsPublished) VALUES
-- Admin posts
(1, 'Welcome to the Platform', 'This is the official welcome message from the admin team. We hope you enjoy using our platform!', 1),
(1, 'Security Update Notice', 'CONFIDENTIAL: All admin credentials have been rotated. New master key: ADM1N-S3CR3T-K3Y-2023', 1),
(7, 'Admin Meeting Notes', 'INTERNAL: Server credentials - DB_PASSWORD=SuperSecret123, API_KEY=sk_live_12345', 1),

-- User posts
(2, 'My First Post', 'Hello everyone! This is Alice. Excited to be here and share my thoughts.', 1),
(2, 'Weekend Adventures', 'Had an amazing weekend hiking in the mountains. The views were breathtaking!', 1),
(3, 'Tech Tips: Database Security', 'Always use parameterized queries to prevent SQL injection attacks. Never concatenate user input!', 1),
(3, 'Private Draft', 'This is a private draft that should not be visible to others. Contains sensitive info.', 0),
(4, 'Book Recommendations', 'Just finished reading "The Phoenix Project". Highly recommend for anyone in tech!', 1),
(4, 'Recipe: Best Chocolate Cake', 'Here is my secret family recipe for chocolate cake that won multiple awards...', 1),
(5, 'Travel Blog: Japan 2023', 'Day 1 in Tokyo: Visited Shibuya crossing, ate the best ramen of my life!', 1),
(5, 'Credit Card Info - DO NOT PUBLISH', 'CARD: 4532-1234-5678-9010, CVV: 123, EXP: 12/25 - for booking flight', 0),
(8, 'Photography Tips', 'Golden hour lighting can make any photo look professional. Here are my settings...', 1),
(8, 'Confidential: API Keys', 'STRIPE_KEY=sk_test_abcdef123456, AWS_SECRET=AKIA1234567890EXAMPLE', 0);

-- Add some older posts for testing date-based queries
INSERT INTO Posts (UserId, Title, Content, IsPublished, CreatedAt) VALUES
(2, 'Ancient Post from 2020', 'This is an old post for testing historical data queries.', 1, '2020-01-15 10:30:00'),
(3, 'Legacy Content', 'Archived content from the early days of the platform.', 1, '2021-06-20 14:45:00');

GO

-- Display summary for verification
SELECT 'Users Created' AS Summary, COUNT(*) AS Count FROM Users
UNION ALL
SELECT 'Posts Created', COUNT(*) FROM Posts
UNION ALL
SELECT 'Published Posts', COUNT(*) FROM Posts WHERE IsPublished = 1
UNION ALL
SELECT 'Admin Users', COUNT(*) FROM Users WHERE Role = 'admin';

GO

