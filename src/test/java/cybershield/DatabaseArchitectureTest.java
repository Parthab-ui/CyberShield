package cybershield;

import com.google.gson.Gson;
import cybershield.database.DatabaseManager;
import cybershield.model.BlockedIp;
import cybershield.model.Incident;
import cybershield.model.InvestigationNote;
import cybershield.model.SecurityAlert;
import cybershield.model.ThreatResponse;
import cybershield.model.User;
import cybershield.security.PasswordUtils;
import cybershield.service.IncidentService;
import cybershield.service.UserService;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * DatabaseArchitectureTest — Automated validation suite for Review 3 Phase 1.
 * Verifies schema expansion, table creation, user table migration, index creation,
 * foreign key integrity, idempotency, and domain model serialization.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class DatabaseArchitectureTest {

    private static final Gson gson = new Gson();

    @BeforeAll
    public static void setup() throws Exception {
        DatabaseManager.initialize();
    }

    @Test
    @Order(1)
    @DisplayName("Test 1: blocked_ips table exists with all required columns")
    public void testBlockedIpsTableSchema() throws SQLException {
        try (Connection conn = DatabaseManager.getConnection()) {
            Set<String> columns = getTableColumns(conn, "blocked_ips");
            assertFalse(columns.isEmpty(), "blocked_ips table must exist in SQLite database.");
            assertTrue(columns.contains("id"), "Column 'id' missing from blocked_ips.");
            assertTrue(columns.contains("ip_address"), "Column 'ip_address' missing from blocked_ips.");
            assertTrue(columns.contains("reason"), "Column 'reason' missing from blocked_ips.");
            assertTrue(columns.contains("blocked_at"), "Column 'blocked_at' missing from blocked_ips.");
            assertTrue(columns.contains("expires_at"), "Column 'expires_at' missing from blocked_ips.");
            assertTrue(columns.contains("blocked_by"), "Column 'blocked_by' missing from blocked_ips.");
            assertTrue(columns.contains("status"), "Column 'status' missing from blocked_ips.");
            assertTrue(columns.contains("unblocked_at"), "Column 'unblocked_at' missing from blocked_ips.");
            assertTrue(columns.contains("unblocked_by"), "Column 'unblocked_by' missing from blocked_ips.");
        }
    }

    @Test
    @Order(2)
    @DisplayName("Test 2: threat_responses table exists with all required columns")
    public void testThreatResponsesTableSchema() throws SQLException {
        try (Connection conn = DatabaseManager.getConnection()) {
            Set<String> columns = getTableColumns(conn, "threat_responses");
            assertFalse(columns.isEmpty(), "threat_responses table must exist in SQLite database.");
            assertTrue(columns.contains("id"), "Column 'id' missing from threat_responses.");
            assertTrue(columns.contains("incident_id"), "Column 'incident_id' missing from threat_responses.");
            assertTrue(columns.contains("threat_type"), "Column 'threat_type' missing from threat_responses.");
            assertTrue(columns.contains("action_taken"), "Column 'action_taken' missing from threat_responses.");
            assertTrue(columns.contains("target_identifier"), "Column 'target_identifier' missing from threat_responses.");
            assertTrue(columns.contains("status"), "Column 'status' missing from threat_responses.");
            assertTrue(columns.contains("executed_at"), "Column 'executed_at' missing from threat_responses.");
            assertTrue(columns.contains("completed_at"), "Column 'completed_at' missing from threat_responses.");
            assertTrue(columns.contains("details"), "Column 'details' missing from threat_responses.");
        }
    }

    @Test
    @Order(3)
    @DisplayName("Test 3: incident_investigations table exists with all required columns")
    public void testIncidentInvestigationsTableSchema() throws SQLException {
        try (Connection conn = DatabaseManager.getConnection()) {
            Set<String> columns = getTableColumns(conn, "incident_investigations");
            assertFalse(columns.isEmpty(), "incident_investigations table must exist in SQLite database.");
            assertTrue(columns.contains("id"), "Column 'id' missing from incident_investigations.");
            assertTrue(columns.contains("incident_id"), "Column 'incident_id' missing from incident_investigations.");
            assertTrue(columns.contains("analyst_username"), "Column 'analyst_username' missing from incident_investigations.");
            assertTrue(columns.contains("notes"), "Column 'notes' missing from incident_investigations.");
            assertTrue(columns.contains("evidence_data"), "Column 'evidence_data' missing from incident_investigations.");
            assertTrue(columns.contains("created_at"), "Column 'created_at' missing from incident_investigations.");
        }
    }

    @Test
    @Order(4)
    @DisplayName("Test 4: users table contains Review 3 account lockout columns")
    public void testUsersTableMigrationColumns() throws SQLException {
        try (Connection conn = DatabaseManager.getConnection()) {
            Set<String> columns = getTableColumns(conn, "users");
            assertTrue(columns.contains("is_locked"), "Column 'is_locked' missing from users.");
            assertTrue(columns.contains("locked_until"), "Column 'locked_until' missing from users.");
            assertTrue(columns.contains("failed_attempt_count"), "Column 'failed_attempt_count' missing from users.");
        }
    }

    @Test
    @Order(5)
    @DisplayName("Test 5: Existing demo users (admin, analyst) are preserved and remain unlocked")
    public void testExistingUsersPreservedAndUnlocked() throws SQLException {
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement("SELECT username, password_hash, salt, role, is_locked, locked_until, failed_attempt_count FROM users WHERE username = ?")) {

            // Check admin
            pstmt.setString(1, "admin");
            try (ResultSet rs = pstmt.executeQuery()) {
                assertTrue(rs.next(), "Existing user 'admin' must be preserved.");
                assertEquals("ADMIN", rs.getString("role"));
                assertEquals(0, rs.getInt("is_locked"), "Existing admin account must be unlocked by default.");
                assertEquals(0L, rs.getLong("locked_until"), "locked_until must default to 0.");
                assertEquals(0, rs.getInt("failed_attempt_count"), "failed_attempt_count must default to 0.");

                // Verify password hash is intact
                assertTrue(PasswordUtils.verifyPassword("Admin@123", rs.getString("salt"), rs.getString("password_hash")),
                        "Existing admin password verification must still succeed.");
            }

            // Check analyst
            pstmt.setString(1, "analyst");
            try (ResultSet rs = pstmt.executeQuery()) {
                assertTrue(rs.next(), "Existing user 'analyst' must be preserved.");
                assertEquals("ANALYST", rs.getString("role"));
                assertEquals(0, rs.getInt("is_locked"), "Existing analyst account must be unlocked by default.");
                assertEquals(0L, rs.getLong("locked_until"), "locked_until must default to 0.");
                assertEquals(0, rs.getInt("failed_attempt_count"), "failed_attempt_count must default to 0.");

                // Verify password hash is intact
                assertTrue(PasswordUtils.verifyPassword("Analyst@123", rs.getString("salt"), rs.getString("password_hash")),
                        "Existing analyst password verification must still succeed.");
            }
        }
    }

    @Test
    @Order(6)
    @DisplayName("Test 6: Existing incidents and security alerts are fully preserved")
    public void testExistingIncidentsAndAlertsPreserved() throws SQLException {
        try (Connection conn = DatabaseManager.getConnection();
             Statement stmt = conn.createStatement()) {

            // Check incidents
            try (ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM incidents")) {
                assertTrue(rs.next() && rs.getInt(1) > 0, "Existing incidents table must have preserved records.");
            }

            // Check security alerts
            try (ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM security_alerts")) {
                assertTrue(rs.next() && rs.getInt(1) > 0, "Existing security alerts table must have preserved records.");
            }
        }
    }

    @Test
    @Order(7)
    @DisplayName("Test 7: Required indexes are created in SQLite database")
    public void testRequiredIndexesCreated() throws SQLException {
        Set<String> indexes = new HashSet<>();
        try (Connection conn = DatabaseManager.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT name FROM sqlite_master WHERE type = 'index'")) {
            while (rs.next()) {
                String name = rs.getString("name");
                if (name != null) indexes.add(name.toLowerCase());
            }
        }

        assertTrue(indexes.contains("idx_blocked_ips_ip"), "Missing index: idx_blocked_ips_ip");
        assertTrue(indexes.contains("idx_blocked_ips_status"), "Missing index: idx_blocked_ips_status");
        assertTrue(indexes.contains("idx_blocked_ips_expires"), "Missing index: idx_blocked_ips_expires");
        assertTrue(indexes.contains("idx_threat_responses_incident"), "Missing index: idx_threat_responses_incident");
        assertTrue(indexes.contains("idx_threat_responses_target"), "Missing index: idx_threat_responses_target");
        assertTrue(indexes.contains("idx_threat_responses_executed"), "Missing index: idx_threat_responses_executed");
        assertTrue(indexes.contains("idx_incident_investigations_incident"), "Missing index: idx_incident_investigations_incident");
        assertTrue(indexes.contains("idx_incident_investigations_created"), "Missing index: idx_incident_investigations_created");
    }

    @Test
    @Order(8)
    @DisplayName("Test 8: Database migrations are idempotent (repeated initialize() calls succeed)")
    public void testMigrationIdempotency() {
        assertDoesNotThrow(() -> {
            // Repeatedly initialize schema to verify safety and idempotence
            DatabaseManager.initialize();
            DatabaseManager.initialize();
            DatabaseManager.initialize();
        }, "Repeated initialization must not throw exceptions or duplicate columns.");
    }

    @Test
    @Order(9)
    @DisplayName("Test 9: Foreign key cascading from incidents to investigations works")
    public void testForeignKeyCascadingBehavior() throws SQLException {
        IncidentService incidentService = new IncidentService();
        Incident tempIncident = new Incident("Temporary Cascade Incident", "Test description", "LOW", "OPEN");
        Incident created = incidentService.create(tempIncident, "admin");
        assertNotNull(created, "Created incident must not be null.");
        int incId = created.getId();

        try (Connection conn = DatabaseManager.getConnection()) {
            // Enable foreign keys for this connection
            try (Statement st = conn.createStatement()) {
                st.execute("PRAGMA foreign_keys = ON;");
            }

            // Insert an investigation note for this incident
            String insertNote = "INSERT INTO incident_investigations (incident_id, analyst_username, notes, evidence_data, created_at) VALUES (?, ?, ?, ?, ?)";
            try (PreparedStatement ps = conn.prepareStatement(insertNote)) {
                ps.setInt(1, incId);
                ps.setString(2, "analyst");
                ps.setString(3, "Initial triage conducted. Source confirmed internal.");
                ps.setString(4, "{\"pcap_file\":\"capture_001.pcap\"}");
                ps.setLong(5, System.currentTimeMillis());
                ps.executeUpdate();
            }

            // Verify note exists
            try (PreparedStatement ps = conn.prepareStatement("SELECT COUNT(*) FROM incident_investigations WHERE incident_id = ?")) {
                ps.setInt(1, incId);
                try (ResultSet rs = ps.executeQuery()) {
                    assertTrue(rs.next() && rs.getInt(1) == 1, "Investigation note must exist.");
                }
            }

            // Delete the incident
            incidentService.delete(incId, "admin");

            // Verify note was cascaded (deleted) due to ON DELETE CASCADE
            try (PreparedStatement ps = conn.prepareStatement("SELECT COUNT(*) FROM incident_investigations WHERE incident_id = ?")) {
                ps.setInt(1, incId);
                try (ResultSet rs = ps.executeQuery()) {
                    assertTrue(rs.next() && rs.getInt(1) == 0, "Investigation note must be cascaded on incident deletion.");
                }
            }
        }
    }

    @Test
    @Order(10)
    @DisplayName("Test 10: Java domain models serialize and deserialize correctly with Gson")
    public void testDomainModelJsonCompatibility() {
        long now = System.currentTimeMillis();

        // 1. BlockedIp
        BlockedIp block = new BlockedIp(101, "192.168.1.55", "Repeated brute force", now, now + 900_000L, "IDS_ENGINE", "ACTIVE", null, null);
        String blockJson = gson.toJson(block);
        BlockedIp deserializedBlock = gson.fromJson(blockJson, BlockedIp.class);
        assertEquals("192.168.1.55", deserializedBlock.getIpAddress());
        assertEquals("ACTIVE", deserializedBlock.getStatus());
        assertTrue(deserializedBlock.isActive());
        assertFalse(deserializedBlock.isExpired(now));

        // 2. ThreatResponse
        ThreatResponse resp = new ThreatResponse(202, 5, "BRUTE_FORCE_ATTACK", "BLOCK_IP", "192.168.1.55", "EXECUTED", now, now + 100L, "Blocked for 15 mins");
        String respJson = gson.toJson(resp);
        ThreatResponse deserializedResp = gson.fromJson(respJson, ThreatResponse.class);
        assertEquals("BLOCK_IP", deserializedResp.getActionTaken());
        assertEquals("192.168.1.55", deserializedResp.getTargetIdentifier());
        assertEquals(Integer.valueOf(5), deserializedResp.getIncidentId());

        // 3. InvestigationNote
        InvestigationNote note = new InvestigationNote(303, 5, "analyst", "Analyst reviewed packet captures.", "Evidence payload", now);
        String noteJson = gson.toJson(note);
        InvestigationNote deserializedNote = gson.fromJson(noteJson, InvestigationNote.class);
        assertEquals("analyst", deserializedNote.getAnalystUsername());
        assertEquals(5, deserializedNote.getIncidentId());
        assertEquals("Analyst reviewed packet captures.", deserializedNote.getNotes());

        // 4. User with Review 3 lockout fields
        User user = new User(1, "test_admin", "hash123", "salt123", "ADMIN", "2026-11-14", 0, 0L, 0);
        String userJson = gson.toJson(user);
        User deserializedUser = gson.fromJson(userJson, User.class);
        assertEquals("test_admin", deserializedUser.getUsername());
        assertEquals(0, deserializedUser.getIsLocked());
        assertFalse(deserializedUser.isAccountLocked(now));
    }

    private Set<String> getTableColumns(Connection conn, String tableName) throws SQLException {
        Set<String> columns = new HashSet<>();
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("PRAGMA table_info(" + tableName + ")")) {
            while (rs.next()) {
                String name = rs.getString("name");
                if (name != null) columns.add(name.toLowerCase());
            }
        }
        return columns;
    }
}

