CREATE DATABASE IF NOT EXISTS socioconnect;
USE socioconnect;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    location VARCHAR(100) NOT NULL,
    interests TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_location (location),
    INDEX idx_email (email),
    INDEX idx_username (username)
);
