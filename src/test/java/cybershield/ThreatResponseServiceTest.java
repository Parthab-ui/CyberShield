package cybershield;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpServer;
import cybershield.database.DatabaseManager;
import cybershield.model.BlockedIp;
import cybershield.model.Incident;
import cybershield.model.SecurityAlert;
import cybershield.model.ThreatResponse;
import cybershield.model.ThreatResponseStats;
import cybershield.model.User;
import cybershield.server.ApiHandler;
import cybershield.service.AccessEventService;
import cybershield.service.AccountLockoutService;
import cybershield.service.ActivityLogService;
import cybershield.service.IncidentService;
import cybershield.service.IntrusionDetectionService;
import cybershield.service.IpBlockService;
import cybershield.service.ThreatResponseService;
import cybershield.service.UserService;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ThreatResponseServiceTest — Automated validation suite for Review 3 Phase 4.
 *
 * Verifies all 18 requirements:
 * TEST 1: Five failed attempts from one IP triggers IDS detection.
 * TEST 2: High-severity incident created upon detection.
 * TEST 3: Automatic IP blocking active in blocked_ips.
 * TEST 4: 15-minute block expiration timestamp correctly calculated.
 * TEST 5: Defensive response history persisted in threat_responses.
 * TEST 6: Response record correctly linked to auto-generated incident.
 * TEST 7: Subsequent login from blocked IP returns HTTP 403 and bypasses password check.
 * TEST 8: Fewer than five failed attempts do not trigger automatic blocking.
 * TEST 9: Attempts from different IP addresses handled independently.
 * TEST 10: Cooldown suppresses duplicate incidents and response records.
 * TEST 11: Already blocked IP does not create duplicate active blocks (ALREADY_ACTIVE).
 * TEST 12: Whitelisted IP addresses are not blocked (SKIPPED_WHITELIST).
 * TEST 13: Response persistence preserved across new service instances.
 * TEST 14: Simultaneous threshold events do not create duplicate responses.
 * TEST 15: Existing account locking remains functional.
 * TEST 16: Account lockout and IDS counters remain independent.
 * TEST 17: Fifth failed login is recorded exactly once in failed_logins.
 * TEST 18: Response failure is not reported as successful blocking.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ThreatResponseServiceTest {

    private static ThreatResponseService threatResponseService;
    private static IpBlockService ipBlockService;
    private static IntrusionDetectionService idsService;
    private static IncidentService incidentService;
    private static ActivityLogService activityLogService;
    private static AccessEventService accessEventService;
    private static AccountLockoutService accountLockoutService;
    private static UserService userService;

    private static HttpServer testHttpServer;
    private static int testServerPort;
    private static final Gson gson = new Gson();

    @BeforeAll
    public static void setUpClass() throws Exception {
        DatabaseManager.initialize();

        activityLogService = new ActivityLogService();
        incidentService = new IncidentService(activityLogService);
        accessEventService = new AccessEventService();
        ipBlockService = new IpBlockService();
        accountLockoutService = new AccountLockoutService(activityLogService);
        threatResponseService = new ThreatResponseService(ipBlockService, incidentService, activityLogService);
        idsService = new IntrusionDetectionService(
                incidentService, activityLogService, accessEventService, null, threatResponseService
        );
        userService = new UserService(accessEventService, activityLogService, idsService, accountLockoutService);

        // Start embedded HTTP test server
        testHttpServer = HttpServer.create(new InetSocketAddress(0), 0);
        testHttpServer.createContext("/api", new ApiHandler(ipBlockService, accountLockoutService));
        testHttpServer.start();
        testServerPort = testHttpServer.getAddress().getPort();
    }

    @AfterAll
    public static void tearDownClass() {
        if (testHttpServer != null) {
            testHttpServer.stop(0);
        }
    }

    @BeforeEach
    public void cleanState() {
        ipBlockService.clearBlockHistory();
        threatResponseService.clearResponseHistory();
        idsService.clearDetectionHistory();
        accountLockoutService.unlockAccount("admin", "TEST_SUITE");
        accountLockoutService.unlockAccount("analyst", "TEST_SUITE");
    }

    @Test
    @Order(1)
    @DisplayName("TEST 1: Five failed attempts from one IP -> IDS detects brute-force activity")
    public void test1_FiveFailedAttempts_TriggersIdsDetection() {
        String testIp = "192.168.200.1";
        SecurityAlert alert = null;

        for (int i = 1; i <= 5; i++) {
            alert = idsService.recordFailedLogin(testIp, "admin", System.currentTimeMillis() + (i * 500));
            if (i < 5) {
                assertNull(alert, "Attempts 1-4 must not trigger detection.");
            }
        }

        assertNotNull(alert, "5th failed attempt must trigger a SecurityAlert.");
        assertEquals("BRUTE_FORCE_ATTACK", alert.getAlertType());
        assertEquals(testIp, alert.getSourceIp());
        assertEquals(5, alert.getFailedAttempts());
    }

    @Test
    @Order(2)
    @DisplayName("TEST 2: After detection, verify HIGH-severity incident creation")
    public void test2_HighSeverityIncidentCreation() {
        String testIp = "192.168.200.2";
        long now = System.currentTimeMillis();

        SecurityAlert alert = null;
        for (int i = 1; i <= 5; i++) {
            alert = idsService.recordFailedLogin(testIp, "admin", now + (i * 200));
        }

        assertNotNull(alert);
        assertTrue(alert.getIncidentId() > 0, "SecurityAlert must reference generated incident ID.");

        Incident incident = incidentService.getById(alert.getIncidentId());
        assertNotNull(incident, "Incident must exist in SQLite incidents table.");
        assertEquals("HIGH", incident.getSeverity());
        assertEquals("OPEN", incident.getStatus());
        assertEquals("IDS_ENGINE", incident.getCreatedBy());
        assertTrue(incident.getTitle().contains("Brute Force Login Attack Detected"));
    }

    @Test
    @Order(3)
    @DisplayName("TEST 3: Verify automatic IP blocking -> ACTIVE status in blocked_ips")
    public void test3_AutomaticIpBlockingActiveStatus() {
        String testIp = "192.168.200.3";
        for (int i = 1; i <= 5; i++) {
            idsService.recordFailedLogin(testIp, "admin", System.currentTimeMillis() + (i * 100));
        }

        assertTrue(ipBlockService.isBlocked(testIp), "Source IP must be actively blocked following 5 failed attempts.");
        BlockedIp block = ipBlockService.getActiveBlock(testIp);
        assertNotNull(block);
        assertEquals("ACTIVE", block.getStatus());
        assertEquals(testIp, block.getIpAddress());
        assertEquals("SYSTEM_AUTO_RESPONSE", block.getBlockedBy());
    }

    @Test
    @Order(4)
    @DisplayName("TEST 4: Verify block duration -> 15-minute expiration timestamp")
    public void test4_BlockDurationFifteenMinutes() {
        String testIp = "192.168.200.4";
        long now = System.currentTimeMillis();

        for (int i = 1; i <= 5; i++) {
            idsService.recordFailedLogin(testIp, "admin", now + (i * 200));
        }

        BlockedIp block = ipBlockService.getActiveBlock(testIp);
        assertNotNull(block, "Active block must exist for recently mitigated IP.");
        long expectedExpiration = block.getBlockedAt() + (15 * 60 * 1000L);
        assertEquals(expectedExpiration, block.getExpiresAt(), "Block expiration must be exactly 15 minutes after block time.");
    }

    @Test
    @Order(5)
    @DisplayName("TEST 5: Verify response history is persisted in threat_responses")
    public void test5_ResponseHistoryPersisted() {
        String testIp = "192.168.200.5";
        for (int i = 1; i <= 5; i++) {
            idsService.recordFailedLogin(testIp, "admin", System.currentTimeMillis() + (i * 100));
        }

        List<ThreatResponse> responses = threatResponseService.getResponseHistory(null, testIp, null);
        assertFalse(responses.isEmpty(), "threat_responses must contain record for mitigated attack.");
        ThreatResponse resp = responses.get(0);
        assertEquals("AUTO_BLOCK_IP", resp.getActionTaken());
        assertEquals("EXECUTED", resp.getStatus());
        assertEquals(testIp, resp.getTargetIdentifier());
        assertNotNull(resp.getDetails());
    }

    @Test
    @Order(6)
    @DisplayName("TEST 6: Verify response is linked to the correct incident")
    public void test6_ResponseLinkedToCorrectIncident() {
        String testIp = "192.168.200.6";
        SecurityAlert alert = null;
        for (int i = 1; i <= 5; i++) {
            alert = idsService.recordFailedLogin(testIp, "admin", System.currentTimeMillis() + (i * 100));
        }

        assertNotNull(alert);
        int incidentId = alert.getIncidentId();
        assertTrue(incidentId > 0);

        List<ThreatResponse> responses = threatResponseService.getResponseHistory(incidentId, null, null);
        assertFalse(responses.isEmpty(), "Must find response linked to incidentId #" + incidentId);
        assertEquals(incidentId, responses.get(0).getIncidentId());
        assertEquals(testIp, responses.get(0).getTargetIdentifier());
    }

    @Test
    @Order(7)
    @DisplayName("TEST 7: Send another request from the blocked IP -> HTTP 403 and auth bypassed")
    public void test7_SubsequentRequestFromBlockedIp_ReturnsHttp403() throws Exception {
        String testIp = "192.168.200.7";
        for (int i = 1; i <= 5; i++) {
            idsService.recordFailedLogin(testIp, "admin", System.currentTimeMillis() + (i * 100));
        }
        assertTrue(ipBlockService.isBlocked(testIp));

        // Submit HTTP login request with valid credentials from blocked IP
        JsonObject payload = new JsonObject();
        payload.addProperty("username", "admin");
        payload.addProperty("password", "Admin@123");
        payload.addProperty("clientIp", testIp);

        HttpURLConnection conn = (HttpURLConnection) new URL("http://localhost:" + testServerPort + "/api/auth/login").openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/json");

        try (OutputStream os = conn.getOutputStream()) {
            os.write(payload.toString().getBytes(StandardCharsets.UTF_8));
        }

        int statusCode = conn.getResponseCode();
        assertEquals(403, statusCode, "Subsequent request from auto-blocked IP must receive HTTP 403 Forbidden.");

        InputStream is = conn.getErrorStream();
        String body = new String(is.readAllBytes(), StandardCharsets.UTF_8);
        JsonObject json = gson.fromJson(body, JsonObject.class);
        assertEquals("IP_BLOCKED", json.get("error").getAsString());
    }

    @Test
    @Order(8)
    @DisplayName("TEST 8: Verify fewer than five failed attempts do not trigger automatic blocking")
    public void test8_FewerThanFiveFailedAttempts_DoNotTriggerBlocking() {
        String testIp = "192.168.200.8";
        for (int i = 1; i <= 4; i++) {
            idsService.recordFailedLogin(testIp, "admin", System.currentTimeMillis() + (i * 100));
        }

        assertFalse(ipBlockService.isBlocked(testIp), "4 failed attempts must NOT trigger IP blocking.");
        List<ThreatResponse> responses = threatResponseService.getResponseHistory(null, testIp, null);
        assertTrue(responses.isEmpty(), "No threat responses must be recorded for 4 failed attempts.");
    }

    @Test
    @Order(9)
    @DisplayName("TEST 9: Verify attempts from different IP addresses are handled independently")
    public void test9_AttemptsFromDifferentIpsHandledIndependently() {
        String ipA = "192.168.200.91";
        String ipB = "192.168.200.92";

        for (int i = 1; i <= 3; i++) {
            idsService.recordFailedLogin(ipA, "admin", System.currentTimeMillis() + (i * 100));
            idsService.recordFailedLogin(ipB, "admin", System.currentTimeMillis() + (i * 100));
        }

        assertFalse(ipBlockService.isBlocked(ipA), "IP A (3 attempts) must NOT be blocked.");
        assertFalse(ipBlockService.isBlocked(ipB), "IP B (3 attempts) must NOT be blocked.");
    }

    @Test
    @Order(10)
    @DisplayName("TEST 10: Verify the same IP does not create duplicate incidents or responses during cooldown")
    public void test10_CooldownSuppressesDuplicateIncidentsAndResponses() {
        String testIp = "192.168.200.10";
        long now = System.currentTimeMillis();

        // Attempts 1-5 trigger detection, incident #1, block #1, and response #1
        for (int i = 1; i <= 5; i++) {
            idsService.recordFailedLogin(testIp, "admin", now + (i * 200));
        }

        int incidentsBefore = incidentService.getAll().size();
        int responsesBefore = threatResponseService.getResponseHistory(null, testIp, null).size();
        assertEquals(1, responsesBefore);

        // 6th attempt during 10-minute cooldown
        SecurityAlert alert6 = idsService.recordFailedLogin(testIp, "admin", now + 10000);
        assertNull(alert6, "6th attempt during cooldown must not generate alert.");

        int incidentsAfter = incidentService.getAll().size();
        int responsesAfter = threatResponseService.getResponseHistory(null, testIp, null).size();

        assertEquals(incidentsBefore, incidentsAfter, "No new incident must be created during cooldown.");
        assertEquals(responsesBefore, responsesAfter, "No duplicate response must be created during cooldown.");
    }

    @Test
    @Order(11)
    @DisplayName("TEST 11: Verify an already blocked IP does not create duplicate active blocks")
    public void test11_AlreadyBlockedIpDoesNotCreateDuplicateActiveBlocks() {
        String testIp = "192.168.200.11";

        // Pre-block IP manually
        ipBlockService.blockIp(testIp, "Pre-existing manual quarantine", 15, "admin");
        assertTrue(ipBlockService.isBlocked(testIp));

        // Execute automated brute-force response against already blocked IP
        ThreatResponse resp = threatResponseService.executeBruteForceResponse(testIp, "BRUTE_FORCE_ATTACK", null, 9999);
        assertNotNull(resp);
        assertEquals("ALREADY_ACTIVE", resp.getStatus(), "Status must be ALREADY_ACTIVE when IP was already blocked.");

        // Verify only 1 active block exists in blocked_ips
        List<BlockedIp> blocks = ipBlockService.getAllBlockedIps("ACTIVE");
        long countForIp = blocks.stream().filter(b -> testIp.equals(b.getIpAddress())).count();
        assertEquals(1, countForIp, "Must not create duplicate active block records in blocked_ips.");
    }

    @Test
    @Order(12)
    @DisplayName("TEST 12: Verify whitelisted IP addresses are not blocked (SKIPPED_WHITELIST)")
    public void test12_WhitelistedIpAddressesAreNotBlocked() {
        String loopbackIp = "127.0.0.1";

        // Execute response against loopback
        ThreatResponse resp = threatResponseService.executeBruteForceResponse(loopbackIp, "BRUTE_FORCE_ATTACK", null, 100);
        assertNotNull(resp);
        assertEquals("SKIPPED_WHITELIST", resp.getStatus(), "Response must be SKIPPED_WHITELIST for loopback IP.");

        assertFalse(ipBlockService.isBlocked(loopbackIp), "Whitelisted IP must NEVER be blocked.");
    }

    @Test
    @Order(13)
    @DisplayName("TEST 13: Verify response persistence after creating a new service instance")
    public void test13_ResponsePersistenceAfterCreatingNewServiceInstance() {
        String testIp = "192.168.200.13";
        for (int i = 1; i <= 5; i++) {
            idsService.recordFailedLogin(testIp, "admin", System.currentTimeMillis() + (i * 100));
        }

        // New service instance
        ThreatResponseService newService = new ThreatResponseService();
        List<ThreatResponse> history = newService.getResponseHistory(null, testIp, null);
        assertFalse(history.isEmpty(), "New ThreatResponseService instance must read persisted history from SQLite.");
        assertEquals("EXECUTED", history.get(0).getStatus());
        assertEquals("AUTO_BLOCK_IP", history.get(0).getActionTaken());
    }

    @Test
    @Order(14)
    @DisplayName("TEST 14: Verify two simultaneous threshold events do not create duplicate responses")
    public void test14_SimultaneousThresholdEventsDoNotCreateDuplicateResponses() throws InterruptedException {
        String testIp = "192.168.200.14";
        int threads = 6;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threads);

        for (int i = 0; i < threads; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    threatResponseService.executeBruteForceResponse(testIp, "BRUTE_FORCE_ATTACK", null, 777);
                } catch (Exception ignored) {
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        boolean completed = doneLatch.await(5, TimeUnit.SECONDS);
        executor.shutdown();
        assertTrue(completed);

        // Verify only 1 active block exists in blocked_ips
        List<BlockedIp> activeBlocks = ipBlockService.getAllBlockedIps("ACTIVE");
        long count = activeBlocks.stream().filter(b -> testIp.equals(b.getIpAddress())).count();
        assertEquals(1, count, "Concurrent response executions must only produce 1 active block in SQLite.");
    }

    @Test
    @Order(15)
    @DisplayName("TEST 15: Verify existing account locking remains functional")
    public void test15_ExistingAccountLockingRemainsFunctional() {
        String targetUser = "analyst";
        // 5 failed attempts against 'analyst' from 5 DIFFERENT IPs (so no single IP triggers IDS threshold)
        for (int i = 1; i <= 5; i++) {
            String ip = "10.50.1." + i;
            userService.authenticate(targetUser, "WrongPassword" + i, ip, "TEST");
        }

        // Account must be locked
        assertTrue(accountLockoutService.isAccountLocked(targetUser), "User account 'analyst' must be locked after 5 consecutive failures.");
        // None of the individual IPs should be blocked (each only sent 1 request)
        for (int i = 1; i <= 5; i++) {
            assertFalse(ipBlockService.isBlocked("10.50.1." + i));
        }
    }

    @Test
    @Order(16)
    @DisplayName("TEST 16: Verify account-lockout and IDS counters remain independent")
    public void test16_AccountLockoutAndIdsCountersRemainIndependent() {
        String attackerIp = "192.168.200.16";
        // Attacker tries 2 attempts on 'admin' and 3 attempts on 'analyst' from the SAME IP
        userService.authenticate("admin", "WrongPass1", attackerIp, "TEST");
        userService.authenticate("admin", "WrongPass2", attackerIp, "TEST");
        userService.authenticate("analyst", "WrongPass1", attackerIp, "TEST");
        userService.authenticate("analyst", "WrongPass2", attackerIp, "TEST");
        userService.authenticate("analyst", "WrongPass3", attackerIp, "TEST");

        // IP has reached 5 total failures -> Attacker IP MUST BE BLOCKED!
        assertTrue(ipBlockService.isBlocked(attackerIp), "Attacker IP with 5 total failures must be auto-blocked.");

        // Neither user has reached 5 consecutive failures ('admin' has 2, 'analyst' has 3)
        assertFalse(accountLockoutService.isAccountLocked("admin"), "User 'admin' with only 2 failures must not be locked.");
        assertFalse(accountLockoutService.isAccountLocked("analyst"), "User 'analyst' with only 3 failures must not be locked.");
    }

    @Test
    @Order(17)
    @DisplayName("TEST 17: Verify the fifth failed login is recorded exactly once in the IDS")
    public void test17_FifthFailedLoginRecordedExactlyOnceInIds() throws SQLException {
        String testIp = "192.168.200.17";
        for (int i = 1; i <= 5; i++) {
            userService.authenticate("admin", "WrongPass" + i, testIp, "TEST");
        }

        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement stmt = conn.prepareStatement("SELECT COUNT(*) AS cnt FROM failed_logins WHERE ip_address = ?")) {
            stmt.setString(1, testIp);
            try (ResultSet rs = stmt.executeQuery()) {
                assertTrue(rs.next());
                assertEquals(5, rs.getInt("cnt"), "Exactly 5 failed login records must exist in failed_logins for this IP.");
            }
        }
    }

    @Test
    @Order(18)
    @DisplayName("TEST 18: Verify a response failure is not reported as successful blocking")
    public void test18_ResponseFailureNotReportedAsSuccessfulBlocking() {
        String invalidIp = "not_an_ip_address_999";
        ThreatResponse resp = threatResponseService.executeBruteForceResponse(invalidIp, "BRUTE_FORCE_ATTACK", null, 555);

        assertNotNull(resp);
        assertEquals("FAILED", resp.getStatus(), "Invalid IP format must yield FAILED response status.");
        assertNotEquals("EXECUTED", resp.getStatus(), "Failure must NEVER be reported as EXECUTED.");
        assertFalse(ipBlockService.isBlocked(invalidIp));
    }
}
