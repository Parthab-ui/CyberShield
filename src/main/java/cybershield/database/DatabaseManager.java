package cybershield.database;

import cybershield.security.PasswordUtils;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashSet;
import java.util.Set;

/**
 * DatabaseManager — Manages the SQLite database lifecycle, JDBC connection per call via DriverManager
 * (no connection pool), schema generation, and idempotent sample data seeding.
 * Demonstrates: JDBC connection handling, parameterized queries, and safe schema migration.
 */
public class DatabaseManager {

    private static final String DATA_DIR = "data";
    private static final String DB_FILE = "data/cybershield.db";
    private static final String JDBC_URL = "jdbc:sqlite:" + DB_FILE;
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static boolean initialized = false;

    private DatabaseManager() {
        // Private constructor prevents instantiation
    }

    /**
     * Obtains an active connection to the persistent SQLite database.
     * Automatically ensures directory and schema initialization if needed.
     */
    public static synchronized Connection getConnection() throws SQLException {
        if (!initialized) {
            initialize();
        }
        Connection conn = DriverManager.getConnection(JDBC_URL);
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("PRAGMA foreign_keys = ON;");
        }
        return conn;
    }

    /**
     * Initializes the database directory, creates tables idempotently,
     * and seeds default demo accounts and starter incident data.
     */
    public static synchronized void initialize() throws SQLException {
        if (initialized) {
            return;
        }

        // Step 1: Ensure the data directory exists
        File dir = new File(DATA_DIR);
        if (!dir.exists()) {
            dir.mkdirs();
        }

        // Step 2: Establish connection and create tables
        try (Connection conn = DriverManager.getConnection(JDBC_URL);
             Statement stmt = conn.createStatement()) {

            // Enable WAL (Write-Ahead Logging) mode for improved concurrent read/write performance
            stmt.execute("PRAGMA journal_mode = WAL;");
            stmt.execute("PRAGMA foreign_keys = ON;");

            // Table 1: Users table for credentials and role-based permissions
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """);

            // Table 2: Incidents table for tracking security incidents
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """);

            // Table 3: Access Events table for login attempts and simulated intrusions
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS access_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    attempted_username TEXT NOT NULL,
                    source TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    result TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """);

            // Table 4: Activity Log table for general audit trailing
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS activity_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """);

            // Table 5: Failed Logins table for Intrusion Detection System (Review 2 Upgrade)
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS failed_logins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    username TEXT NOT NULL,
                    attempted_at TEXT NOT NULL,
                    timestamp_epoch INTEGER NOT NULL
                );
            """);
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_failed_logins_ip_time ON failed_logins (ip_address, timestamp_epoch);");

            // Table 6: Security Alerts table for Automated Threat Detections (Review 2 Upgrade)
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS security_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_type TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    failed_attempts INTEGER NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    incident_id INTEGER,
                    details TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    created_at_epoch INTEGER NOT NULL
                );
            """);
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_security_alerts_ip ON security_alerts (source_ip);");

            // =========================================================================
            // REVIEW 3 SCHEMA EXPANSION: THREAT MITIGATION & INCIDENT INVESTIGATION
            // =========================================================================

            // Table 7: Blocked IPs table for Automated/Manual Threat Mitigation (Review 3 Upgrade)
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    reason TEXT,
                    blocked_at INTEGER NOT NULL,
                    expires_at INTEGER,
                    blocked_by TEXT,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    unblocked_at INTEGER,
                    unblocked_by TEXT
                );
            """);
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips (ip_address);");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_blocked_ips_status ON blocked_ips (status);");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_blocked_ips_expires ON blocked_ips (expires_at);");

            // Table 8: Threat Responses table for Defense Auditing (Review 3 Upgrade)
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS threat_responses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER,
                    threat_type TEXT NOT NULL,
                    action_taken TEXT NOT NULL,
                    target_identifier TEXT NOT NULL,
                    status TEXT NOT NULL,
                    executed_at INTEGER NOT NULL,
                    completed_at INTEGER,
                    details TEXT,
                    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL
                );
            """);
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_threat_responses_incident ON threat_responses (incident_id);");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_threat_responses_target ON threat_responses (target_identifier);");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_threat_responses_executed ON threat_responses (executed_at);");

            // Table 9: Incident Investigations table for Multi-Note Case Dossiers (Review 3 Upgrade)
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS incident_investigations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL,
                    analyst_username TEXT NOT NULL,
                    notes TEXT NOT NULL,
                    evidence_data TEXT,
                    created_at INTEGER NOT NULL,
                    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
                );
            """);
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_incident_investigations_incident ON incident_investigations (incident_id);");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_incident_investigations_created ON incident_investigations (created_at);");

            // Step 2.5: Apply Review 3 schema migrations to existing tables (idempotent)
            migrateUsersTable(conn);
            migrateIncidentsTable(conn);

            // Step 3: Seed initial default data if database is fresh
            seedDefaultUsers(conn);
            seedInitialIncidents(conn);
            seedInitialAccessEvents(conn);
            seedInitialActivity(conn);
            seedInitialSecurityAlerts(conn);

            initialized = true;
            System.out.println("[DatabaseManager] SQLite database initialized successfully at: " + DB_FILE);
        }
    }

    /**
     * Idempotently migrates the users table to add Review 3 account lockout columns:
     * - is_locked (INTEGER NOT NULL DEFAULT 0)
     * - locked_until (INTEGER NOT NULL DEFAULT 0)
     * - failed_attempt_count (INTEGER NOT NULL DEFAULT 0)
     *
     * Pre-condition safety:
     * 1. Inspects existing table schema via PRAGMA table_info before applying DDL.
     * 2. Preserves all existing user records, passwords, salt hashes, roles, and IDs.
     * 3. Guarantees existing accounts remain unlocked (is_locked = 0).
     */
    private static void migrateUsersTable(Connection conn) throws SQLException {
        Set<String> existingColumns = new HashSet<>();
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("PRAGMA table_info(users)")) {
            while (rs.next()) {
                existingColumns.add(rs.getString("name").toLowerCase());
            }
        }

        try (Statement stmt = conn.createStatement()) {
            if (!existingColumns.contains("is_locked")) {
                stmt.execute("ALTER TABLE users ADD COLUMN is_locked INTEGER NOT NULL DEFAULT 0;");
                System.out.println("[DatabaseManager] Migrated users table: added 'is_locked' column.");
            }
            if (!existingColumns.contains("locked_until")) {
                stmt.execute("ALTER TABLE users ADD COLUMN locked_until INTEGER NOT NULL DEFAULT 0;");
                System.out.println("[DatabaseManager] Migrated users table: added 'locked_until' column.");
            }
            if (!existingColumns.contains("failed_attempt_count")) {
                stmt.execute("ALTER TABLE users ADD COLUMN failed_attempt_count INTEGER NOT NULL DEFAULT 0;");
                System.out.println("[DatabaseManager] Migrated users table: added 'failed_attempt_count' column.");
            }
        }
    }

    /**
     * Idempotently migrates the incidents table for Review 3 Phase 5:
     * - assigned_to TEXT
     * - root_cause_category TEXT
     * - resolution_summary TEXT
     *
     * Pre-condition safety:
     * 1. Inspects existing table schema via PRAGMA table_info before applying DDL.
     * 2. Preserves all existing incident records, descriptions, titles, and IDs.
     * 3. Defaults new fields safely to NULL for existing records.
     */
    private static void migrateIncidentsTable(Connection conn) throws SQLException {
        Set<String> existingColumns = new HashSet<>();
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("PRAGMA table_info(incidents)")) {
            while (rs.next()) {
                existingColumns.add(rs.getString("name").toLowerCase());
            }
        }

        try (Statement stmt = conn.createStatement()) {
            if (!existingColumns.contains("assigned_to")) {
                stmt.execute("ALTER TABLE incidents ADD COLUMN assigned_to TEXT;");
                System.out.println("[DatabaseManager] Migrated incidents table: added 'assigned_to' column.");
            }
            if (!existingColumns.contains("root_cause_category")) {
                stmt.execute("ALTER TABLE incidents ADD COLUMN root_cause_category TEXT;");
                System.out.println("[DatabaseManager] Migrated incidents table: added 'root_cause_category' column.");
            }
            if (!existingColumns.contains("resolution_summary")) {
                stmt.execute("ALTER TABLE incidents ADD COLUMN resolution_summary TEXT;");
                System.out.println("[DatabaseManager] Migrated incidents table: added 'resolution_summary' column.");
            }
            // Add helpful index on assigned_to
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_incidents_assigned ON incidents (assigned_to);");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status);");
        }
    }

    /**
     * Seeds the default Administrator and Security Analyst accounts if they do not exist.
     */
    private static void seedDefaultUsers(Connection conn) throws SQLException {
        String adminPassword = System.getenv("CYBERSHIELD_ADMIN_PASSWORD");
        if (adminPassword == null || adminPassword.trim().isEmpty()) {
            adminPassword = "Admin@123";
        }
        String analystPassword = System.getenv("CYBERSHIELD_ANALYST_PASSWORD");
        if (analystPassword == null || analystPassword.trim().isEmpty()) {
            analystPassword = "Analyst@123";
        }

        // Seed Administrator account: admin
        if (!userExists(conn, "admin")) {
            String salt = PasswordUtils.generateSalt();
            String hash = PasswordUtils.hashPassword(adminPassword, salt);
            String now = LocalDateTime.now().format(FORMATTER);

            String sql = "INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)";
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, "admin");
                pstmt.setString(2, hash);
                pstmt.setString(3, salt);
                pstmt.setString(4, "ADMIN");
                pstmt.setString(5, now);
                pstmt.executeUpdate();
            }
            System.out.println("[DatabaseManager] Seeded default administrator account: 'admin' (PBKDF2)");
        }

        // Seed Security Analyst account: analyst
        if (!userExists(conn, "analyst")) {
            String salt = PasswordUtils.generateSalt();
            String hash = PasswordUtils.hashPassword(analystPassword, salt);
            String now = LocalDateTime.now().format(FORMATTER);

            String sql = "INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)";
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, "analyst");
                pstmt.setString(2, hash);
                pstmt.setString(3, salt);
                pstmt.setString(4, "ANALYST");
                pstmt.setString(5, now);
                pstmt.executeUpdate();
            }
            System.out.println("[DatabaseManager] Seeded default analyst account: 'analyst' (PBKDF2)");
        }
    }

    /**
     * Helper to verify if a user already exists in the database.
     */
    private static boolean userExists(Connection conn, String username) throws SQLException {
        String sql = "SELECT COUNT(*) FROM users WHERE username = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            try (ResultSet rs = pstmt.executeQuery()) {
                return rs.next() && rs.getInt(1) > 0;
            }
        }
    }

    /**
     * Seeds realistic starter security incidents if table is empty.
     */
    private static void seedInitialIncidents(Connection conn) throws SQLException {
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM incidents")) {
            if (rs.next() && rs.getInt(1) == 0) {
                String now = LocalDateTime.now().format(FORMATTER);
                String sql = "INSERT INTO incidents (title, description, severity, status, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)";
                try (PreparedStatement ps = conn.prepareStatement(sql)) {
                    // Incident 1: Critical Ransomware attempt
                    ps.setString(1, "Suspected Ransomware Beaconing");
                    ps.setString(2, "Outbound C2 communication detected from endpoint WS-FINANCE-04 to known malicious IP 198.51.100.42.");
                    ps.setString(3, "CRITICAL");
                    ps.setString(4, "OPEN");
                    ps.setString(5, "admin");
                    ps.setString(6, now);
                    ps.setString(7, now);
                    ps.executeUpdate();

                    // Incident 2: High Brute Force on SSH
                    ps.setString(1, "SSH Credential Stuffing on Gateway");
                    ps.setString(2, "Over 450 failed authentication attempts within 3 minutes targeting port 22 on external gateway.");
                    ps.setString(3, "HIGH");
                    ps.setString(4, "INVESTIGATING");
                    ps.setString(5, "analyst");
                    ps.setString(6, now);
                    ps.setString(7, now);
                    ps.executeUpdate();

                    // Incident 3: Medium Unauthorized File Access
                    ps.setString(1, "Sensitive Data Export Spike");
                    ps.setString(2, "Unusual data transfer volume observed on customer records archive exceeding standard threshold.");
                    ps.setString(3, "MEDIUM");
                    ps.setString(4, "OPEN");
                    ps.setString(5, "admin");
                    ps.setString(6, now);
                    ps.setString(7, now);
                    ps.executeUpdate();

                    // Incident 4: Low Phishing Mail Reported
                    ps.setString(1, "Phishing Email Campaign Reported");
                    ps.setString(2, "Multiple users reported suspicious emails impersonating payroll department. Malicious links quarantined.");
                    ps.setString(3, "LOW");
                    ps.setString(4, "RESOLVED");
                    ps.setString(5, "analyst");
                    ps.setString(6, now);
                    ps.setString(7, now);
                    ps.executeUpdate();
                }
                System.out.println("[DatabaseManager] Seeded starter security incidents.");
            }
        }
    }

    /**
     * Seeds initial access and threat events if table is empty.
     */
    private static void seedInitialAccessEvents(Connection conn) throws SQLException {
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM access_events")) {
            if (rs.next() && rs.getInt(1) == 0) {
                String now = LocalDateTime.now().format(FORMATTER);
                String sql = "INSERT INTO access_events (attempted_username, source, event_type, result, created_at) VALUES (?, ?, ?, ?, ?)";
                try (PreparedStatement ps = conn.prepareStatement(sql)) {
                    ps.setString(1, "root");
                    ps.setString(2, "192.168.1.105 (EXT-WAN)");
                    ps.setString(3, "UNAUTHORIZED_LOGIN");
                    ps.setString(4, "BLOCKED");
                    ps.setString(5, now);
                    ps.executeUpdate();

                    ps.setString(1, "guest");
                    ps.setString(2, "10.0.0.45 (WIFI-GUEST)");
                    ps.setString(3, "PRIVILEGE_ESCALATION");
                    ps.setString(4, "FAILED");
                    ps.setString(5, now);
                    ps.executeUpdate();

                    ps.setString(1, "admin");
                    ps.setString(2, "127.0.0.1 (LOCAL)");
                    ps.setString(3, "LOGIN_SUCCESS");
                    ps.setString(4, "SUCCESS");
                    ps.setString(5, now);
                    ps.executeUpdate();
                }
            }
        }
    }

    /**
     * Seeds initial activity history log.
     */
    private static void seedInitialActivity(Connection conn) throws SQLException {
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM activity_log")) {
            if (rs.next() && rs.getInt(1) == 0) {
                String now = LocalDateTime.now().format(FORMATTER);
                String sql = "INSERT INTO activity_log (username, action, details, created_at) VALUES (?, ?, ?, ?)";
                try (PreparedStatement ps = conn.prepareStatement(sql)) {
                    ps.setString(1, "system");
                    ps.setString(2, "SYSTEM_INIT");
                    ps.setString(3, "CyberShield database initialized with default security schema.");
                    ps.setString(4, now);
                    ps.executeUpdate();
                }
            }
        }
    }

    /**
     * Seeds initial sample security alert if table is empty (Review 2).
     */
    private static void seedInitialSecurityAlerts(Connection conn) throws SQLException {
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM security_alerts")) {
            if (rs.next() && rs.getInt(1) == 0) {
                String now = LocalDateTime.now().format(FORMATTER);
                long epoch = System.currentTimeMillis();
                String sql = "INSERT INTO security_alerts (alert_type, source_ip, failed_attempts, severity, status, incident_id, details, created_at, created_at_epoch) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
                try (PreparedStatement ps = conn.prepareStatement(sql)) {
                    ps.setString(1, "BRUTE_FORCE_ATTACK");
                    ps.setString(2, "192.168.1.105");
                    ps.setInt(3, 5);
                    ps.setString(4, "HIGH");
                    ps.setString(5, "OPEN");
                    ps.setInt(6, 2); // Corresponds to Incident #2 (SSH Brute Force)
                    ps.setString(7, "Multiple failed authentication attempts (5) detected within 2 minutes from 192.168.1.105. Automated incident generated.");
                    ps.setString(8, now);
                    ps.setLong(9, epoch);
                    ps.executeUpdate();
                }
            }
        }
    }

    /**
     * Returns the SQLite database file path.
     */
    public static String getDatabasePath() {
        return new File(DB_FILE).getAbsolutePath();
    }
}
