package com.cybershield.repository;

import com.cybershield.exception.DatabaseOperationException;
import com.cybershield.model.enums.UserRole;
import com.cybershield.util.SecurityUtils;
import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * SQLite JDBC Database Manager for CyberShield.
 * Handles local database connection, schema migration, and initial seed data.
 */
public class DatabaseManager {

    private static final String DB_DIR = "data";
    private static final String DB_PATH = DB_DIR + File.separator + "cybershield.db";
    private static final String JDBC_URL = "jdbc:sqlite:" + DB_PATH;

    private static DatabaseManager instance;

    private DatabaseManager() {
        // Private constructor for singleton
    }

    public static synchronized DatabaseManager getInstance() {
        if (instance == null) {
            instance = new DatabaseManager();
        }
        return instance;
    }

    /**
     * Obtains an active SQLite JDBC database connection.
     */
    public Connection getConnection() throws SQLException {
        ensureDataDirectoryExists();
        return DriverManager.getConnection(JDBC_URL);
    }

    private void ensureDataDirectoryExists() {
        File dir = new File(DB_DIR);
        if (!dir.exists()) {
            dir.mkdirs();
        }
    }

    /**
     * Initializes all relational tables if they do not already exist.
     */
    public void initializeDatabase() throws DatabaseOperationException {
        ensureDataDirectoryExists();

        String createUsersTable = """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                role TEXT NOT NULL,
                active INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                last_login TEXT
            );
        """;

        String createEventsTable = """
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                username TEXT NOT NULL,
                description TEXT NOT NULL,
                raw_payload TEXT,
                severity TEXT NOT NULL
            );
        """;

        String createThreatsTable = """
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_id TEXT UNIQUE NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                target_asset TEXT NOT NULL,
                detected_at TEXT NOT NULL,
                description TEXT NOT NULL,
                failed_attempts INTEGER DEFAULT 0,
                window_duration INTEGER DEFAULT 0,
                sender_email TEXT,
                suspicious_url TEXT,
                keyword_hits TEXT,
                file_hash TEXT,
                file_path TEXT,
                quarantined_flag INTEGER DEFAULT 0,
                geo_anomaly INTEGER DEFAULT 0,
                unusual_hour INTEGER DEFAULT 0,
                device_fingerprint TEXT
            );
        """;

        String createIncidentsTable = """
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                threat_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
        """;

        String createResponseActionsTable = """
            CREATE TABLE IF NOT EXISTS response_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_id TEXT UNIQUE NOT NULL,
                incident_id TEXT NOT NULL,
                action_type TEXT NOT NULL,
                target TEXT NOT NULL,
                executed_by TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT,
                executed_at TEXT NOT NULL
            );
        """;

        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement()) {

            conn.setAutoCommit(false);

            stmt.execute(createUsersTable);
            stmt.execute(createEventsTable);
            stmt.execute(createThreatsTable);
            stmt.execute(createIncidentsTable);
            stmt.execute(createResponseActionsTable);

            conn.commit();

            seedInitialData(conn);
            conn.commit();
            conn.setAutoCommit(true);

        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to initialize SQLite database schema: " + e.getMessage(), e);
        }
    }

    /**
     * Seeds default credentials and sample demonstration data on first startup.
     */
    private void seedInitialData(Connection conn) throws SQLException {
        // Check if users exist
        String countUsersSql = "SELECT COUNT(*) FROM users";
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(countUsersSql)) {
            if (rs.next() && rs.getInt(1) == 0) {
                // Insert default analyst and admin
                String insertUserSql = """
                    INSERT INTO users (username, password_hash, full_name, role, active, created_at)
                    VALUES (?, ?, ?, ?, 1, datetime('now'));
                """;
                try (PreparedStatement pstmt = conn.prepareStatement(insertUserSql)) {
                    // Default Analyst: analyst / cyber123
                    pstmt.setString(1, "analyst");
                    pstmt.setString(2, SecurityUtils.hashPassword("cyber123"));
                    pstmt.setString(3, "Alex Vance (SOC Analyst)");
                    pstmt.setString(4, UserRole.ANALYST.name());
                    pstmt.executeUpdate();

                    // Default Admin: admin / admin123
                    pstmt.setString(1, "admin");
                    pstmt.setString(2, SecurityUtils.hashPassword("admin123"));
                    pstmt.setString(3, "Dr. Gordon Freeman (SOC Admin)");
                    pstmt.setString(4, UserRole.ADMIN.name());
                    pstmt.executeUpdate();
                }
            }
        }

        // Check if sample events exist
        String countEventsSql = "SELECT COUNT(*) FROM security_events";
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(countEventsSql)) {
            if (rs.next() && rs.getInt(1) == 0) {
                // Seed initial baseline telemetry
                String insertEventSql = """
                    INSERT INTO security_events (event_id, timestamp, event_type, source_ip, username, description, raw_payload, severity)
                    VALUES (?, datetime('now', '-10 minute'), ?, ?, ?, ?, ?, ?);
                """;
                try (PreparedStatement pstmt = conn.prepareStatement(insertEventSql)) {
                    pstmt.setString(1, "EVT-BASE-001");
                    pstmt.setString(2, "AUTH_SUCCESS");
                    pstmt.setString(3, "192.168.1.50");
                    pstmt.setString(4, "analyst");
                    pstmt.setString(5, "Routine internal workstation login");
                    pstmt.setString(6, "SYSTEM_LOG: Workstation 50 auth OK");
                    pstmt.setString(7, "LOW");
                    pstmt.executeUpdate();

                    pstmt.setString(1, "EVT-BASE-002");
                    pstmt.setString(2, "NETWORK_SCAN");
                    pstmt.setString(3, "10.0.0.12");
                    pstmt.setString(4, "svc_backup");
                    pstmt.setString(5, "Scheduled port discovery sweep across subnet");
                    pstmt.setString(6, "NET_PROBE: ports 22, 80, 443, 3389 queried");
                    pstmt.setString(7, "LOW");
                    pstmt.executeUpdate();
                }
            }
        }
    }
}
