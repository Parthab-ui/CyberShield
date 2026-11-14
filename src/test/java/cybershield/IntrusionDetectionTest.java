package cybershield;

import cybershield.database.DatabaseManager;
import cybershield.model.DashboardStats;
import cybershield.model.Incident;
import cybershield.model.IntrusionDetectionConfig;
import cybershield.model.SecurityAlert;
import cybershield.model.User;
import cybershield.service.AccessEventService;
import cybershield.service.ActivityLogService;
import cybershield.service.DashboardService;
import cybershield.service.IncidentService;
import cybershield.service.IntrusionDetectionService;
import cybershield.service.UserService;
import cybershield.ui.ApiClient;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * IntrusionDetectionTest — Comprehensive Automated Test Suite for Review 2 Upgrade.
 *
 * Verifies all 12 evaluation criteria specified in the Master Review 2 prompt:
 * 1. 1 incorrect login -> Failed attempt recorded
 * 2. 2 incorrect logins -> Both attempts recorded
 * 3. 4 failures within 2 minutes -> No brute-force alert
 * 4. 5 failures within 2 minutes -> HIGH severity alert generated
 * 5. 6th failed attempt during cooldown -> No duplicate incident
 * 6. Failures from different IP addresses -> Independently tracked
 * 7. Failed attempts outside detection window -> Old attempts excluded
 * 8. Valid login -> No brute-force alert
 * 9. Automatically generated incident -> Stored in SQLite
 * 10. Dashboard refresh -> New alert displayed
 * 11. Analyst login -> Existing RBAC restrictions preserved
 * 12. Admin login -> Existing administrator functionality preserved
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class IntrusionDetectionTest {

    private static IntrusionDetectionService idsService;
    private static UserService userService;
    private static IncidentService incidentService;
    private static DashboardService dashboardService;
    private static AccessEventService accessEventService;
    private static ActivityLogService activityLogService;

    @BeforeAll
    public static void setUpClass() throws Exception {
        DatabaseManager.initialize();
        idsService = new IntrusionDetectionService();
        incidentService = new IncidentService();
        activityLogService = new ActivityLogService();
        accessEventService = new AccessEventService();
        userService = new UserService(accessEventService, activityLogService, idsService);
        dashboardService = new DashboardService(incidentService, activityLogService, idsService);
        // Clear old test failure records to ensure test suite repeatability
        idsService.clearDetectionHistory();
    }

    @BeforeEach
    public void resetIdsConfig() {
        // Ensure standard configuration: 5 failures, 2-minute window, 10-minute cooldown
        idsService.setConfig(new IntrusionDetectionConfig(5, 2, 10));
    }

    @Test
    @Order(1)
    @DisplayName("Test 1: Single incorrect login is recorded persistently without alert")
    public void test1_SingleIncorrectLoginRecorded() {
        String testIp = "192.168.10.1";
        long now = System.currentTimeMillis();

        SecurityAlert alert = idsService.recordFailedLogin(testIp, "attacker1", now);

        assertNull(alert, "1 failed attempt should NOT trigger an alert.");
        int failures = idsService.countRecentFailures(testIp, now - 120_000);
        assertEquals(1, failures, "Failed attempt must be recorded persistently in SQLite.");
    }

    @Test
    @Order(2)
    @DisplayName("Test 2: Two incorrect logins are both recorded persistently")
    public void test2_TwoIncorrectLoginsRecorded() {
        String testIp = "192.168.10.2";
        long now = System.currentTimeMillis();

        idsService.recordFailedLogin(testIp, "attacker2", now);
        SecurityAlert alert2 = idsService.recordFailedLogin(testIp, "attacker2", now + 1000);

        assertNull(alert2, "2 failed attempts should NOT trigger an alert.");
        int failures = idsService.countRecentFailures(testIp, now - 120_000);
        assertEquals(2, failures, "Both failed attempts must be recorded in SQLite.");
    }

    @Test
    @Order(3)
    @DisplayName("Test 3: 4 failures within 2 minutes do NOT trigger brute-force alert")
    public void test3_FourFailuresWithinTwoMinutesNoAlert() {
        String testIp = "192.168.10.3";
        long now = System.currentTimeMillis();

        for (int i = 1; i <= 4; i++) {
            SecurityAlert alert = idsService.recordFailedLogin(testIp, "test_victim", now + (i * 1000));
            assertNull(alert, "Attempt " + i + " should NOT trigger an alert (threshold is 5).");
        }

        int failures = idsService.countRecentFailures(testIp, now - 120_000);
        assertEquals(4, failures, "All 4 attempts must be recorded.");
    }

    @Test
    @Order(4)
    @DisplayName("Test 4: 5 failures within 2 minutes generate HIGH severity alert and incident")
    public void test4_FiveFailuresWithinTwoMinutesTriggersAlert() {
        String testIp = "192.168.10.4";
        long now = System.currentTimeMillis();

        for (int i = 1; i <= 4; i++) {
            idsService.recordFailedLogin(testIp, "admin", now + (i * 1000));
        }

        // 5th attempt reaches threshold
        SecurityAlert alert = idsService.recordFailedLogin(testIp, "admin", now + 5000);

        assertNotNull(alert, "5th failed attempt within 2 minutes MUST trigger a SecurityAlert!");
        assertEquals("BRUTE_FORCE_ATTACK", alert.getAlertType());
        assertEquals("HIGH", alert.getSeverity(), "Alert severity MUST be HIGH.");
        assertEquals("OPEN", alert.getStatus(), "Alert status MUST be OPEN.");
        assertEquals(testIp, alert.getSourceIp(), "Alert source IP must match.");
        assertEquals(5, alert.getFailedAttempts(), "Failed attempts count must be 5.");
        assertTrue(alert.getIncidentId() > 0, "A valid SQLite incident ID must be associated.");
    }

    @Test
    @Order(5)
    @DisplayName("Test 5: 6th failed attempt during cooldown suppresses duplicate incident")
    public void test5_SixthAttemptDuringCooldownSuppressed() {
        String testIp = "192.168.10.4"; // Reusing IP from Test 4 which just triggered an alert
        long now = System.currentTimeMillis() + 10_000; // 10 seconds later (well within 10-minute cooldown)

        // Count existing incidents before 6th attempt
        int incidentsBefore = countBruteForceIncidentsForIp(testIp);
        assertTrue(incidentsBefore >= 1, "There should already be 1 incident created for this IP.");

        // 6th attempt
        SecurityAlert alert6 = idsService.recordFailedLogin(testIp, "admin", now);

        assertNull(alert6, "6th attempt during cooldown MUST NOT generate a new SecurityAlert (duplicate suppressed).");

        // Verify no duplicate incident was created
        int incidentsAfter = countBruteForceIncidentsForIp(testIp);
        assertEquals(incidentsBefore, incidentsAfter, "Incident count must NOT increase during cooldown window.");
    }

    @Test
    @Order(6)
    @DisplayName("Test 6: Failures from different IP addresses are tracked independently")
    public void test6_DifferentIpsTrackedIndependently() {
        String ipA = "10.0.1.50";
        String ipB = "10.0.2.75";
        long now = System.currentTimeMillis();

        // 3 failures from IP A
        for (int i = 1; i <= 3; i++) {
            idsService.recordFailedLogin(ipA, "userA", now + (i * 1000));
        }

        // 3 failures from IP B
        for (int i = 1; i <= 3; i++) {
            idsService.recordFailedLogin(ipB, "userB", now + (i * 1000));
        }

        assertEquals(3, idsService.countRecentFailures(ipA, now - 120_000));
        assertEquals(3, idsService.countRecentFailures(ipB, now - 120_000));

        // Now give IP A 2 more failures -> total 5 -> triggers alert for IP A
        idsService.recordFailedLogin(ipA, "userA", now + 4000);
        SecurityAlert alertA = idsService.recordFailedLogin(ipA, "userA", now + 5000);

        assertNotNull(alertA, "IP A reached 5 failures and MUST trigger an alert.");
        assertEquals(ipA, alertA.getSourceIp());

        // IP B is still at 3 failures -> No alert for IP B
        assertEquals(3, idsService.countRecentFailures(ipB, now - 120_000));
    }

    @Test
    @Order(7)
    @DisplayName("Test 7: Failed attempts outside 2-minute detection window are excluded")
    public void test7_OldAttemptsOutsideWindowExcluded() {
        String testIp = "192.168.10.7";
        long now = System.currentTimeMillis();
        long threeMinutesAgo = now - (3 * 60 * 1000);

        // 3 attempts from 3 minutes ago (outside the 2-minute sliding window)
        idsService.recordFailedLogin(testIp, "attacker", threeMinutesAgo);
        idsService.recordFailedLogin(testIp, "attacker", threeMinutesAgo + 1000);
        idsService.recordFailedLogin(testIp, "attacker", threeMinutesAgo + 2000);

        // 2 attempts right now
        idsService.recordFailedLogin(testIp, "attacker", now);
        SecurityAlert alert = idsService.recordFailedLogin(testIp, "attacker", now + 1000);

        assertNull(alert, "Should NOT trigger alert: only 2 failures are in the 2-minute window (3 are expired).");
        int failuresInWindow = idsService.countRecentFailures(testIp, now - 120_000);
        assertEquals(2, failuresInWindow, "Only 2 recent attempts should be counted in the active sliding window.");
    }

    @Test
    @Order(8)
    @DisplayName("Test 8: Valid login does NOT trigger brute-force alert")
    public void test8_ValidLoginNoAlert() {
        User user = userService.authenticate("admin", "Admin@123", "192.168.10.8", "TEST");

        assertNotNull(user, "Valid credentials must return authenticated User.");
        assertEquals("admin", user.getUsername());
        assertEquals("ADMIN", user.getRole());

        // Verify no alert exists for this IP
        int failures = idsService.countRecentFailures("192.168.10.8", System.currentTimeMillis() - 120_000);
        assertEquals(0, failures, "Valid login must not generate failed login records.");
    }

    @Test
    @Order(9)
    @DisplayName("Test 9: Automatically generated incident is stored permanently in SQLite")
    public void test9_AutoIncidentStoredInSqlite() {
        String testIp = "192.168.10.9";
        long now = System.currentTimeMillis();

        SecurityAlert alert = null;
        for (int i = 1; i <= 5; i++) {
            alert = idsService.recordFailedLogin(testIp, "scanner_bot", now + (i * 1000));
        }

        assertNotNull(alert, "5 failures must produce alert.");
        int incidentId = alert.getIncidentId();

        // Query database via IncidentService to verify SQLite persistence
        Incident incident = incidentService.getById(incidentId);
        assertNotNull(incident, "Incident #" + incidentId + " must exist in SQLite database.");
        assertEquals("Brute Force Login Attack Detected", incident.getTitle());
        assertEquals("HIGH", incident.getSeverity());
        assertEquals("OPEN", incident.getStatus());
        assertEquals("IDS_ENGINE", incident.getCreatedBy());
        assertTrue(incident.getDescription().contains(testIp), "Description must contain source IP: " + testIp);
        assertTrue(incident.getDescription().contains("5"), "Description must note failed count.");
    }

    @Test
    @Order(10)
    @DisplayName("Test 10: Dashboard stats refresh displays detected threats and active alert")
    public void test10_DashboardRefreshDisplaysAlert() {
        DashboardStats stats = dashboardService.getStats();

        assertTrue(stats.getTotalDetectedThreats() > 0, "Dashboard must report detected threats > 0.");
        assertTrue(stats.getActiveSecurityAlerts() > 0, "Dashboard must report active alerts > 0.");
        assertTrue(stats.getAutoGeneratedIncidents() > 0, "Dashboard must report auto-generated incidents > 0.");
        assertNotNull(stats.getLatestAlert(), "Dashboard must provide latest active alert for banner.");
        assertNotNull(stats.getRecentAlerts(), "Dashboard must provide recent alerts list.");
    }

    @Test
    @Order(11)
    @DisplayName("Test 11: Security Analyst login works, but incident deletion is blocked (RBAC preserved)")
    public void test11_AnalystRbacRestrictionsPreserved() {
        // Authenticate as analyst
        User analyst = userService.authenticate("analyst", "Analyst@123", "127.0.0.1", "TEST");
        assertNotNull(analyst, "Analyst login must succeed with valid credentials.");
        assertEquals("ANALYST", analyst.getRole());
        assertFalse(analyst.isAdmin(), "Analyst must NOT have admin privileges.");

        // Simulate desktop client context for analyst
        ApiClient client = ApiClient.getInstance();
        User loggedIn = client.login("analyst", "Analyst@123");
        assertNotNull(loggedIn);

        // Attempting to delete an incident as analyst MUST throw SecurityException
        assertThrows(SecurityException.class, () -> {
            client.deleteIncident(1);
        }, "Only Administrator role can delete incident records.");

        client.logout();
    }

    @Test
    @Order(12)
    @DisplayName("Test 12: Administrator login and full management functionality preserved")
    public void test12_AdminFunctionalityPreserved() {
        ApiClient client = ApiClient.getInstance();
        User admin = client.login("admin", "Admin@123");

        assertNotNull(admin, "Admin login must succeed.");
        assertEquals("ADMIN", admin.getRole());
        assertTrue(client.isAdmin(), "Admin must have admin privileges.");

        // Admin can create an incident
        Incident testInc = new Incident("Admin Review Test", "Testing admin creation", "LOW", "OPEN");
        Incident created = client.createIncident(testInc);
        assertNotNull(created);
        int newId = created.getId();
        assertTrue(newId > 0);

        // Admin can delete an incident
        boolean deleted = client.deleteIncident(newId);
        assertTrue(deleted, "Admin must be able to delete incident records.");

        client.logout();
    }

    @Test
    @Order(13)
    @DisplayName("Test 13: Passwords are NEVER stored in failed_logins, access_events, or logs")
    public void test13_PasswordsNeverStoredInLogs() throws Exception {
        String secretPass = "SuperSecretPlainTextPass999";
        userService.authenticate("test_user_leak", secretPass, "192.168.10.13", "TEST");

        // Inspect SQLite tables to verify the plaintext password is never present
        try (Connection conn = DatabaseManager.getConnection();
             Statement stmt = conn.createStatement()) {

            // Check failed_logins table
            try (ResultSet rs = stmt.executeQuery("SELECT * FROM failed_logins WHERE username = 'test_user_leak'")) {
                while (rs.next()) {
                    String row = rs.getString("ip_address") + " " + rs.getString("username");
                    assertFalse(row.contains(secretPass), "failed_logins table must NEVER contain passwords!");
                }
            }

            // Check access_events table
            try (ResultSet rs = stmt.executeQuery("SELECT * FROM access_events WHERE attempted_username = 'test_user_leak'")) {
                while (rs.next()) {
                    String row = rs.getString("source") + " " + rs.getString("event_type");
                    assertFalse(row.contains(secretPass), "access_events table must NEVER contain passwords!");
                }
            }

            // Check activity_log table
            try (ResultSet rs = stmt.executeQuery("SELECT * FROM activity_log WHERE username = 'test_user_leak'")) {
                while (rs.next()) {
                    String row = rs.getString("action") + " " + rs.getString("details");
                    assertFalse(row.contains(secretPass), "activity_log table must NEVER contain passwords!");
                }
            }
        }
    }

    private int countBruteForceIncidentsForIp(String ip) {
        String sql = "SELECT COUNT(*) FROM incidents WHERE title = 'Brute Force Login Attack Detected' AND description LIKE '%" + ip + "%'";
        try (Connection conn = DatabaseManager.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            if (rs.next()) return rs.getInt(1);
        } catch (Exception e) {
            System.err.println("Error counting incidents: " + e.getMessage());
        }
        return 0;
    }
}
