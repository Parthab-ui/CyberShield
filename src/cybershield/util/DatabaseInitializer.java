package cybershield.util;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;

/**
 * DatabaseInitializer — Programmatically initializes database schemas and tables.
 * Replaces manual MySQL Workbench execution of schema.sql.
 * Features:
 * - Idempotent table creation (CREATE TABLE IF NOT EXISTS).
 * - Automatic seeding of default accounts (admin / analyst) if missing.
 * - Automatic seeding of realistic sample threats, incidents, blocked IPs, and logs if tables are empty.
 * - Non-destructive: preserves existing data and never executes DROP operations.
 */
public class DatabaseInitializer {

    private DatabaseInitializer() { }

    /**
     * Verifies that all required tables exist and contains default records.
     * Safe to run repeatedly upon every application launch.
     */
    public static void initializeDatabase(Connection conn) throws SQLException {
        if (conn == null || conn.isClosed()) {
            throw new SQLException("Cannot initialize database with null or closed connection.");
        }

        createTables(conn);
        seedDefaultUsers(conn);
        seedSampleThreats(conn);
        seedSampleIncidents(conn);
        seedSampleBlockedIPs(conn);
        seedSampleLogs(conn);

        System.out.println("[DatabaseInitializer] Database tables and default records verified successfully.");
    }

    /** Creates all required tables if they do not already exist. */
    private static void createTables(Connection conn) throws SQLException {
        try (Statement st = conn.createStatement()) {

            // 1. users table
            st.execute("CREATE TABLE IF NOT EXISTS users ("
                    + "id INT AUTO_INCREMENT PRIMARY KEY, "
                    + "username VARCHAR(50) NOT NULL UNIQUE, "
                    + "password VARCHAR(100) NOT NULL, "
                    + "role VARCHAR(20) NOT NULL, "
                    + "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
                    + ")");

            // 2. threats table
            st.execute("CREATE TABLE IF NOT EXISTS threats ("
                    + "id INT AUTO_INCREMENT PRIMARY KEY, "
                    + "threat_type VARCHAR(50) NOT NULL, "
                    + "source_ip VARCHAR(45) NOT NULL, "
                    + "target_system VARCHAR(100) NOT NULL, "
                    + "severity VARCHAR(20) NOT NULL, "
                    + "status VARCHAR(20) NOT NULL DEFAULT 'DETECTED', "
                    + "detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
                    + ")");

            // 3. incidents table
            st.execute("CREATE TABLE IF NOT EXISTS incidents ("
                    + "id INT AUTO_INCREMENT PRIMARY KEY, "
                    + "threat_id INT NOT NULL, "
                    + "title VARCHAR(200) NOT NULL, "
                    + "description TEXT, "
                    + "assigned_to INT, "
                    + "priority VARCHAR(20) NOT NULL, "
                    + "status VARCHAR(20) NOT NULL DEFAULT 'OPEN', "
                    + "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
                    + "closed_at TIMESTAMP NULL"
                    + ")");

            // 4. blocked_ips table
            st.execute("CREATE TABLE IF NOT EXISTS blocked_ips ("
                    + "id INT AUTO_INCREMENT PRIMARY KEY, "
                    + "ip_address VARCHAR(45) NOT NULL UNIQUE, "
                    + "reason VARCHAR(255) NOT NULL, "
                    + "blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
                    + ")");

            // 5. logs table
            st.execute("CREATE TABLE IF NOT EXISTS logs ("
                    + "id INT AUTO_INCREMENT PRIMARY KEY, "
                    + "user_id INT NOT NULL, "
                    + "action VARCHAR(255) NOT NULL, "
                    + "log_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
                    + ")");
        }
    }

    /** Ensures default administrator and analyst accounts exist without duplicating. */
    private static void seedDefaultUsers(Connection conn) throws SQLException {
        // Check admin
        if (!userExists(conn, "admin")) {
            insertUser(conn, "admin", "admin123", "ADMIN");
            System.out.println("[DatabaseInitializer] Created default administrator account (admin / admin123).");
        }

        // Check analyst
        if (!userExists(conn, "analyst")) {
            insertUser(conn, "analyst", "analyst123", "ANALYST");
            System.out.println("[DatabaseInitializer] Created default analyst account (analyst / analyst123).");
        }
    }

    private static boolean userExists(Connection conn, String username) throws SQLException {
        String sql = "SELECT COUNT(*) FROM users WHERE username = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() && rs.getInt(1) > 0;
            }
        }
    }

    private static void insertUser(Connection conn, String username, String password, String role) throws SQLException {
        String sql = "INSERT INTO users (username, password, role) VALUES (?, ?, ?)";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, username);
            ps.setString(2, password);
            ps.setString(3, role);
            ps.executeUpdate();
        }
    }

    /** Seeds realistic cybersecurity threats if threats table is empty. */
    private static void seedSampleThreats(Connection conn) throws SQLException {
        if (getRowCount(conn, "threats") > 0) return;

        long now = System.currentTimeMillis();
        String sql = "INSERT INTO threats (threat_type, source_ip, target_system, severity, status, detected_at) VALUES (?, ?, ?, ?, ?, ?)";
        Object[][] threats = {
            {"Phishing",      "192.168.1.45",  "Mail Server",       "HIGH",     "DETECTED",      2},
            {"Malware",       "10.0.0.112",    "Workstation-PC07",  "CRITICAL", "INVESTIGATING", 5},
            {"DDoS",          "203.0.113.50",  "Web Server",        "CRITICAL", "DETECTED",      8},
            {"SQL Injection", "198.51.100.23", "Customer Database", "HIGH",     "RESOLVED",      12},
            {"Brute Force",   "172.16.0.99",   "SSH Gateway",       "MEDIUM",   "INVESTIGATING", 18},
            {"Ransomware",    "10.0.0.55",     "File Server",       "CRITICAL", "DETECTED",      24},
            {"Phishing",      "192.168.2.101", "HR Portal",         "MEDIUM",   "RESOLVED",      32},
            {"Malware",       "10.0.1.34",     "Workstation-PC12",  "HIGH",     "DETECTED",      40},
            {"DDoS",          "203.0.113.77",  "API Gateway",       "HIGH",     "INVESTIGATING", 52},
            {"SQL Injection", "198.51.100.88", "Payment Gateway",   "CRITICAL", "DETECTED",      65},
            {"Brute Force",   "172.16.1.15",   "Admin Panel",       "LOW",      "RESOLVED",      80},
            {"Ransomware",    "10.0.2.200",    "Backup Server",     "CRITICAL", "INVESTIGATING", 95},
            {"Phishing",      "192.168.3.67",  "Finance Portal",    "HIGH",     "DETECTED",      115},
            {"Malware",       "10.0.3.89",     "Workstation-PC22",  "MEDIUM",   "RESOLVED",      135},
            {"Brute Force",   "172.16.2.44",   "VPN Server",        "HIGH",     "DETECTED",      150}
        };

        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            for (Object[] row : threats) {
                ps.setString(1, (String) row[0]);
                ps.setString(2, (String) row[1]);
                ps.setString(3, (String) row[2]);
                ps.setString(4, (String) row[3]);
                ps.setString(5, (String) row[4]);
                int hoursAgo = (Integer) row[5];
                ps.setTimestamp(6, new Timestamp(now - hoursAgo * 3600000L));
                ps.executeUpdate();
            }
        }
        System.out.println("[DatabaseInitializer] Seeded 15 sample threats.");
    }

    /** Seeds sample incidents if incidents table is empty. */
    private static void seedSampleIncidents(Connection conn) throws SQLException {
        if (getRowCount(conn, "incidents") > 0) return;

        long now = System.currentTimeMillis();
        String sql = "INSERT INTO incidents (threat_id, title, description, assigned_to, priority, status, created_at, closed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
        Object[][] incidents = {
            {1,  "Phishing Campaign Targeting Employees",  "Multiple employees received spoofed emails with malicious links.",         2, "HIGH",     "OPEN",        3,  null},
            {2,  "Trojan Detected on Workstation",          "Trojan horse malware found on PC07, network access isolated.",            2, "CRITICAL", "IN_PROGRESS", 6,  null},
            {3,  "DDoS Attack on Production Web Server",    "Sustained volumetric DDoS attack causing service degradation.",           1, "CRITICAL", "IN_PROGRESS", 10, null},
            {4,  "SQL Injection on Customer Database",       "Attacker exploited input field to extract customer records.",             1, "HIGH",     "CLOSED",      20, 12},
            {6,  "Ransomware Encryption on File Server",     "Critical files encrypted, ransom note left on desktop.",                 2, "CRITICAL", "OPEN",        28, null},
            {10, "SQL Injection Attempt on Payment Gateway", "Automated SQLi scanner detected probing payment processing API.",        1, "CRITICAL", "OPEN",        70, null}
        };

        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            for (Object[] row : incidents) {
                ps.setInt(1, (Integer) row[0]);
                ps.setString(2, (String) row[1]);
                ps.setString(3, (String) row[2]);
                ps.setInt(4, (Integer) row[3]);
                ps.setString(5, (String) row[4]);
                ps.setString(6, (String) row[5]);
                int createdHoursAgo = (Integer) row[6];
                ps.setTimestamp(7, new Timestamp(now - createdHoursAgo * 3600000L));
                if (row[7] != null) {
                    int closedHoursAgo = (Integer) row[7];
                    ps.setTimestamp(8, new Timestamp(now - closedHoursAgo * 3600000L));
                } else {
                    ps.setNull(8, java.sql.Types.TIMESTAMP);
                }
                ps.executeUpdate();
            }
        }
        System.out.println("[DatabaseInitializer] Seeded 6 sample incident tickets.");
    }

    /** Seeds sample blocked IPs if blocked_ips table is empty. */
    private static void seedSampleBlockedIPs(Connection conn) throws SQLException {
        if (getRowCount(conn, "blocked_ips") > 0) return;

        long now = System.currentTimeMillis();
        String sql = "INSERT INTO blocked_ips (ip_address, reason, blocked_at) VALUES (?, ?, ?)";
        Object[][] ips = {
            {"203.0.113.50",  "DDoS attack source",                   10},
            {"198.51.100.23", "SQL Injection attack",                  15},
            {"172.16.0.99",   "Repeated brute force login attempts",   25},
            {"10.0.0.55",     "Ransomware command-and-control server", 35},
            {"198.51.100.88", "Automated SQLi scanner",                75}
        };

        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            for (Object[] row : ips) {
                ps.setString(1, (String) row[0]);
                ps.setString(2, (String) row[1]);
                int hoursAgo = (Integer) row[2];
                ps.setTimestamp(3, new Timestamp(now - hoursAgo * 3600000L));
                ps.executeUpdate();
            }
        }
        System.out.println("[DatabaseInitializer] Seeded 5 sample blocked IP records.");
    }

    /** Seeds sample audit logs if logs table is empty. */
    private static void seedSampleLogs(Connection conn) throws SQLException {
        if (getRowCount(conn, "logs") > 0) return;

        long now = System.currentTimeMillis();
        String sql = "INSERT INTO logs (user_id, action, log_time) VALUES (?, ?, ?)";
        Object[][] logs = {
            {1, "Logged in",                              120},
            {2, "Logged in",                              110},
            {2, "Viewed threat #1 details",               95},
            {1, "Blocked IP 203.0.113.50",                80},
            {1, "Assigned incident #3 to admin",          65},
            {2, "Updated threat #2 status to INVESTIGATING", 50},
            {1, "Blocked IP 198.51.100.23",               35},
            {1, "Closed incident #4",                     20},
            {2, "Created incident for threat #6",         10},
            {1, "Logged out",                             1}
        };

        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            for (Object[] row : logs) {
                ps.setInt(1, (Integer) row[0]);
                ps.setString(2, (String) row[1]);
                int hoursAgo = (Integer) row[2];
                ps.setTimestamp(3, new Timestamp(now - hoursAgo * 3600000L));
                ps.executeUpdate();
            }
        }
        System.out.println("[DatabaseInitializer] Seeded 10 sample audit logs.");
    }

    private static int getRowCount(Connection conn, String table) throws SQLException {
        String sql = "SELECT COUNT(*) FROM " + table;
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(sql)) {
            return rs.next() ? rs.getInt(1) : 0;
        }
    }
}
