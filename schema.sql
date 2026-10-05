-- ============================================================
-- CyberShield Database Schema
-- Database: cybershield_db
-- Run this file in MySQL to create all tables and sample data.
-- ============================================================

CREATE DATABASE IF NOT EXISTS cybershield_db;
USE cybershield_db;

-- -----------------------------------------------------------
-- Table: users
-- Stores admin and analyst accounts for the system.
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    username    VARCHAR(50)  NOT NULL UNIQUE,
    password    VARCHAR(100) NOT NULL,
    role        ENUM('ADMIN', 'ANALYST') NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------------------------------------
-- Table: threats
-- Records each detected cybersecurity threat.
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS threats (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    threat_type   VARCHAR(50)  NOT NULL,
    source_ip     VARCHAR(45)  NOT NULL,
    target_system VARCHAR(100) NOT NULL,
    severity      ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    status        ENUM('DETECTED', 'INVESTIGATING', 'RESOLVED') NOT NULL DEFAULT 'DETECTED',
    detected_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------------------------------------
-- Table: incidents
-- Tracks incident reports linked to threats.
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    threat_id   INT NOT NULL,
    title       VARCHAR(200) NOT NULL,
    description TEXT,
    assigned_to INT,
    priority    ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    status      ENUM('OPEN', 'IN_PROGRESS', 'CLOSED') NOT NULL DEFAULT 'OPEN',
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    closed_at   TIMESTAMP NULL,
    FOREIGN KEY (threat_id)   REFERENCES threats(id),
    FOREIGN KEY (assigned_to) REFERENCES users(id)
);

-- -----------------------------------------------------------
-- Table: blocked_ips
-- Stores IP addresses that have been blocked.
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS blocked_ips (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45)  NOT NULL UNIQUE,
    reason     VARCHAR(255) NOT NULL,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------------------------------------
-- Table: logs
-- Audit log of user actions in the system.
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS logs (
    id       INT AUTO_INCREMENT PRIMARY KEY,
    user_id  INT NOT NULL,
    action   VARCHAR(255) NOT NULL,
    log_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ============================================================
-- SAMPLE DATA
-- ============================================================

-- 2 Users: admin and analyst
INSERT INTO users (username, password, role) VALUES
('admin',   'admin123',   'ADMIN'),
('analyst', 'analyst123', 'ANALYST');

-- 15 Threats with realistic cybersecurity data
INSERT INTO threats (threat_type, source_ip, target_system, severity, status, detected_at) VALUES
('Phishing',       '192.168.1.45',   'Mail Server',        'HIGH',     'DETECTED',      '2025-10-01 08:15:00'),
('Malware',        '10.0.0.112',     'Workstation-PC07',   'CRITICAL', 'INVESTIGATING', '2025-10-01 09:30:00'),
('DDoS',           '203.0.113.50',   'Web Server',         'CRITICAL', 'DETECTED',      '2025-10-01 10:45:00'),
('SQL Injection',  '198.51.100.23',  'Customer Database',  'HIGH',     'RESOLVED',      '2025-10-02 07:20:00'),
('Brute Force',    '172.16.0.99',    'SSH Gateway',        'MEDIUM',   'INVESTIGATING', '2025-10-02 11:00:00'),
('Ransomware',     '10.0.0.55',      'File Server',        'CRITICAL', 'DETECTED',      '2025-10-02 14:30:00'),
('Phishing',       '192.168.2.101',  'HR Portal',          'MEDIUM',   'RESOLVED',      '2025-10-03 08:00:00'),
('Malware',        '10.0.1.34',      'Workstation-PC12',   'HIGH',     'DETECTED',      '2025-10-03 10:15:00'),
('DDoS',           '203.0.113.77',   'API Gateway',        'HIGH',     'INVESTIGATING', '2025-10-03 13:45:00'),
('SQL Injection',  '198.51.100.88',  'Payment Gateway',    'CRITICAL', 'DETECTED',      '2025-10-04 06:30:00'),
('Brute Force',    '172.16.1.15',    'Admin Panel',        'LOW',      'RESOLVED',      '2025-10-04 09:00:00'),
('Ransomware',     '10.0.2.200',     'Backup Server',      'CRITICAL', 'INVESTIGATING', '2025-10-04 12:00:00'),
('Phishing',       '192.168.3.67',   'Finance Portal',     'HIGH',     'DETECTED',      '2025-10-05 07:45:00'),
('Malware',        '10.0.3.89',      'Workstation-PC22',   'MEDIUM',   'RESOLVED',      '2025-10-05 10:30:00'),
('Brute Force',    '172.16.2.44',    'VPN Server',         'HIGH',     'DETECTED',      '2025-10-05 14:00:00');

-- 6 Incidents linked to threats
INSERT INTO incidents (threat_id, title, description, assigned_to, priority, status, created_at, closed_at) VALUES
(1,  'Phishing Campaign Targeting Employees',     'Multiple employees received spoofed emails with malicious links.',            2, 'HIGH',     'OPEN',        '2025-10-01 08:30:00', NULL),
(2,  'Trojan Detected on Workstation',             'Trojan horse malware found on PC07, network access isolated.',               2, 'CRITICAL', 'IN_PROGRESS', '2025-10-01 09:45:00', NULL),
(3,  'DDoS Attack on Production Web Server',       'Sustained volumetric DDoS attack causing service degradation.',              1, 'CRITICAL', 'IN_PROGRESS', '2025-10-01 11:00:00', NULL),
(4,  'SQL Injection on Customer Database',          'Attacker exploited input field to extract customer records.',                1, 'HIGH',     'CLOSED',      '2025-10-02 07:30:00', '2025-10-02 18:00:00'),
(6,  'Ransomware Encryption on File Server',        'Critical files encrypted, ransom note left on desktop.',                    2, 'CRITICAL', 'OPEN',        '2025-10-02 15:00:00', NULL),
(10, 'SQL Injection Attempt on Payment Gateway',    'Automated SQLi scanner detected probing payment processing API.',           1, 'CRITICAL', 'OPEN',        '2025-10-04 07:00:00', NULL);

-- 5 Blocked IPs
INSERT INTO blocked_ips (ip_address, reason, blocked_at) VALUES
('203.0.113.50',  'DDoS attack source',                  '2025-10-01 11:30:00'),
('198.51.100.23', 'SQL Injection attack',                 '2025-10-02 08:00:00'),
('172.16.0.99',   'Repeated brute force login attempts',  '2025-10-02 12:00:00'),
('10.0.0.55',     'Ransomware command-and-control server','2025-10-02 15:00:00'),
('198.51.100.88', 'Automated SQLi scanner',               '2025-10-04 07:30:00');

-- 10 Log entries
INSERT INTO logs (user_id, action, log_time) VALUES
(1, 'Logged in',                              '2025-10-01 08:00:00'),
(2, 'Logged in',                              '2025-10-01 08:10:00'),
(2, 'Viewed threat #1 details',               '2025-10-01 08:20:00'),
(1, 'Blocked IP 203.0.113.50',                '2025-10-01 11:30:00'),
(1, 'Assigned incident #3 to admin',          '2025-10-01 11:05:00'),
(2, 'Updated threat #2 status to INVESTIGATING', '2025-10-01 09:35:00'),
(1, 'Blocked IP 198.51.100.23',               '2025-10-02 08:00:00'),
(1, 'Closed incident #4',                     '2025-10-02 18:00:00'),
(2, 'Created incident for threat #6',         '2025-10-02 15:00:00'),
(1, 'Logged out',                             '2025-10-02 19:00:00');
