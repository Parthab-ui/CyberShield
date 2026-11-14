package cybershield;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpServer;
import cybershield.database.DatabaseManager;
import cybershield.model.AccountLockStatus;
import cybershield.model.User;
import cybershield.security.PasswordUtils;
import cybershield.security.SessionManager;
import cybershield.server.ApiHandler;
import cybershield.service.AccessEventService;
import cybershield.service.AccountLockoutService;
import cybershield.service.ActivityLogService;
import cybershield.service.IntrusionDetectionService;
import cybershield.service.IpBlockService;
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
import java.sql.Statement;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * AccountLockoutServiceTest — Automated validation suite for Review 3 Phase 3.
 *
 * Covers all 15 scenarios specified in the Credential Security & Account Lockout Engine requirements:
 * TEST 1: Four incorrect attempts -> Account remains unlocked.
 * TEST 2: Fifth incorrect attempt -> Account becomes locked.
 * TEST 3: Correct password during active lock -> Authentication rejected.
 * TEST 4: Incorrect password during active lock -> Authentication rejected without increasing counter.
 * TEST 5: Login after lock expiration -> Account automatically unlocks.
 * TEST 6: Verify counter resets after successful authentication.
 * TEST 7: Verify one account's lock does not affect another account.
 * TEST 8: Verify lock persists after service restart.
 * TEST 9: Verify administrator service-level unlock.
 * TEST 10: Verify account lock events appear in activity_log.
 * TEST 11: Verify unknown usernames are handled safely.
 * TEST 12: Verify existing IDS failed-login recording still works.
 * TEST 13: Verify an IP-blocked request does not increment an account's failed-attempt counter.
 * TEST 14: Verify simultaneous failed login requests do not bypass the threshold.
 * TEST 15: Verify locked accounts cannot generate authenticated sessions.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class AccountLockoutServiceTest {

    private static AccountLockoutService accountLockoutService;
    private static IpBlockService ipBlockService;
    private static UserService userService;
    private static AccessEventService accessEventService;
    private static ActivityLogService activityLogService;
    private static IntrusionDetectionService idsService;

    private static HttpServer testHttpServer;
    private static int testServerPort;
    private static final Gson gson = new Gson();

    private static final String TARGET_USER = "test_lockout_user";
    private static final String TARGET_PASS = "Lockout@123";

    private static final String OTHER_USER = "test_other_user";
    private static final String OTHER_PASS = "Other@123";

    private static final String CONCURRENT_USER = "test_concurrent_user";
    private static final String CONCURRENT_PASS = "Concurrent@123";

    @BeforeAll
    public static void setUpClass() throws Exception {
        DatabaseManager.initialize();

        activityLogService = new ActivityLogService();
        accessEventService = new AccessEventService();
        idsService = new IntrusionDetectionService();
        accountLockoutService = new AccountLockoutService(activityLogService);
        ipBlockService = new IpBlockService();
        userService = new UserService(accessEventService, activityLogService, idsService, accountLockoutService);

        // Ensure dedicated isolated test user accounts exist
        createOrResetTestUser(TARGET_USER, TARGET_PASS, "ANALYST");
        createOrResetTestUser(OTHER_USER, OTHER_PASS, "ANALYST");
        createOrResetTestUser(CONCURRENT_USER, CONCURRENT_PASS, "ANALYST");

        // Start embedded ephemeral HTTP server for API login integration tests
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
    public void resetUserState() {
        accountLockoutService.unlockAccount(TARGET_USER, "TEST_SUITE");
        accountLockoutService.unlockAccount(OTHER_USER, "TEST_SUITE");
        accountLockoutService.unlockAccount(CONCURRENT_USER, "TEST_SUITE");
        ipBlockService.clearBlockHistory();
    }

    private static void createOrResetTestUser(String username, String password, String role) throws SQLException {
        try (Connection conn = DatabaseManager.getConnection()) {
            String checkSql = "SELECT id FROM users WHERE username = ?";
            try (PreparedStatement check = conn.prepareStatement(checkSql)) {
                check.setString(1, username);
                try (ResultSet rs = check.executeQuery()) {
                    if (rs.next()) {
                        // Reset existing record
                        try (PreparedStatement reset = conn.prepareStatement(
                                "UPDATE users SET is_locked = 0, locked_until = 0, failed_attempt_count = 0 WHERE username = ?")) {
                            reset.setString(1, username);
                            reset.executeUpdate();
                        }
                        return;
                    }
                }
            }

            // Create fresh record
            String salt = PasswordUtils.generateSalt();
            String hash = PasswordUtils.hashPassword(password, salt);
            String insertSql = "INSERT INTO users (username, password_hash, salt, role, created_at, is_locked, locked_until, failed_attempt_count) " +
                    "VALUES (?, ?, ?, ?, datetime('now'), 0, 0, 0)";
            try (PreparedStatement pstmt = conn.prepareStatement(insertSql)) {
                pstmt.setString(1, username);
                pstmt.setString(2, hash);
                pstmt.setString(3, salt);
                pstmt.setString(4, role);
                pstmt.executeUpdate();
            }
        }
    }

    @Test
    @Order(1)
    @DisplayName("TEST 1: Four incorrect attempts -> Account remains unlocked")
    public void test1_FourIncorrectAttempts_RemainsUnlocked() {
        for (int i = 1; i <= 4; i++) {
            User result = userService.authenticate(TARGET_USER, "WrongPass" + i, "192.168.10.1", "TEST");
            assertNull(result, "Attempt " + i + " must fail authentication.");
        }

        assertFalse(accountLockoutService.isAccountLocked(TARGET_USER), "Account must remain unlocked after 4 failed attempts.");
        AccountLockStatus status = accountLockoutService.getAccountLockStatus(TARGET_USER);
        assertFalse(status.isLocked(), "Lock status must report false.");
        assertEquals(4, status.getFailedAttemptCount(), "Failed attempt count must be exactly 4.");
    }

    @Test
    @Order(2)
    @DisplayName("TEST 2: Fifth incorrect attempt -> Account becomes locked")
    public void test2_FifthIncorrectAttempt_BecomesLocked() {
        // Run 4 initial failures
        for (int i = 1; i <= 4; i++) {
            userService.authenticate(TARGET_USER, "WrongPass" + i, "192.168.10.2", "TEST");
        }

        // 5th attempt triggers lockout
        User fifth = userService.authenticate(TARGET_USER, "WrongPass5", "192.168.10.2", "TEST");
        assertNull(fifth, "5th attempt must fail authentication.");

        assertTrue(accountLockoutService.isAccountLocked(TARGET_USER), "Account must be locked on 5th failed attempt.");
        AccountLockStatus status = accountLockoutService.getAccountLockStatus(TARGET_USER);
        assertTrue(status.isLocked(), "Status must indicate locked=true.");
        assertEquals(5, status.getFailedAttemptCount(), "Failed attempt count must be 5.");
        assertTrue(status.getLockedUntil() > System.currentTimeMillis(), "locked_until must be in the future.");
        assertTrue(status.getRemainingSeconds() > 0, "Remaining seconds must be greater than zero.");
    }

    @Test
    @Order(3)
    @DisplayName("TEST 3: Correct password during active lock -> Authentication rejected")
    public void test3_CorrectPasswordDuringActiveLock_Rejected() {
        // Trigger lock
        for (int i = 1; i <= 5; i++) {
            userService.authenticate(TARGET_USER, "WrongPass" + i, "192.168.10.3", "TEST");
        }
        assertTrue(accountLockoutService.isAccountLocked(TARGET_USER));

        // Submit correct password during lock
        User result = userService.authenticate(TARGET_USER, TARGET_PASS, "192.168.10.3", "TEST");
        assertNull(result, "Correct password MUST be rejected when account is actively locked.");
        assertTrue(accountLockoutService.isAccountLocked(TARGET_USER), "Account must remain locked.");
    }

    @Test
    @Order(4)
    @DisplayName("TEST 4: Incorrect password during active lock -> Rejected without increasing counter")
    public void test4_IncorrectPasswordDuringActiveLock_CounterDoesNotIncrease() {
        // Trigger lock (counter = 5)
        for (int i = 1; i <= 5; i++) {
            userService.authenticate(TARGET_USER, "WrongPass" + i, "192.168.10.4", "TEST");
        }
        AccountLockStatus statusBefore = accountLockoutService.getAccountLockStatus(TARGET_USER);
        assertEquals(5, statusBefore.getFailedAttemptCount());

        // 6th incorrect attempt while locked
        User result = userService.authenticate(TARGET_USER, "WrongPass6", "192.168.10.4", "TEST");
        assertNull(result, "Authentication must be rejected.");

        AccountLockStatus statusAfter = accountLockoutService.getAccountLockStatus(TARGET_USER);
        assertEquals(5, statusAfter.getFailedAttemptCount(), "Failed attempt counter must NOT increment during active lock.");
        assertTrue(statusAfter.isLocked(), "Account must remain locked.");
    }

    @Test
    @Order(5)
    @DisplayName("TEST 5: Login after lock expiration -> Account automatically unlocks")
    public void test5_LoginAfterLockExpiration_AutomaticallyUnlocks() {
        // Trigger lock
        for (int i = 1; i <= 5; i++) {
            userService.authenticate(TARGET_USER, "WrongPass" + i, "192.168.10.5", "TEST");
        }
        assertTrue(accountLockoutService.isAccountLocked(TARGET_USER));

        // Simulate expiration: set locked_until to a timestamp in the past
        long pastTimestamp = System.currentTimeMillis() - 5000L;
        accountLockoutService.setLockUntilForTesting(TARGET_USER, pastTimestamp);

        // Next lock check should auto-unlock
        assertFalse(accountLockoutService.isAccountLocked(TARGET_USER), "Expired lock must automatically unlock.");

        // Login with correct password must now succeed
        User user = userService.authenticate(TARGET_USER, TARGET_PASS, "192.168.10.5", "TEST");
        assertNotNull(user, "User must successfully authenticate after lock expiration.");
        assertEquals(TARGET_USER, user.getUsername());

        AccountLockStatus status = accountLockoutService.getAccountLockStatus(TARGET_USER);
        assertFalse(status.isLocked());
        assertEquals(0, status.getFailedAttemptCount(), "Failure counter must reset to 0 after unlock.");
    }

    @Test
    @Order(6)
    @DisplayName("TEST 6: Verify counter resets after successful authentication")
    public void test6_CounterResetsAfterSuccessfulAuthentication() {
        // Execute 3 failed attempts
        for (int i = 1; i <= 3; i++) {
            userService.authenticate(TARGET_USER, "WrongPass" + i, "192.168.10.6", "TEST");
        }
        assertEquals(3, accountLockoutService.getAccountLockStatus(TARGET_USER).getFailedAttemptCount());

        // Log in with correct password
        User user = userService.authenticate(TARGET_USER, TARGET_PASS, "192.168.10.6", "TEST");
        assertNotNull(user, "Login with valid credentials must succeed.");

        AccountLockStatus status = accountLockoutService.getAccountLockStatus(TARGET_USER);
        assertEquals(0, status.getFailedAttemptCount(), "Counter must be reset to 0 on successful authentication.");
    }

    @Test
    @Order(7)
    @DisplayName("TEST 7: Verify one account's lock does not affect another account")
    public void test7_OneAccountLockDoesNotAffectAnother() {
        // Lock TARGET_USER
        for (int i = 1; i <= 5; i++) {
            userService.authenticate(TARGET_USER, "WrongPass" + i, "192.168.10.7", "TEST");
        }
        assertTrue(accountLockoutService.isAccountLocked(TARGET_USER));

        // Verify OTHER_USER is completely unaffected
        assertFalse(accountLockoutService.isAccountLocked(OTHER_USER), "OTHER_USER must not be locked.");
        User other = userService.authenticate(OTHER_USER, OTHER_PASS, "192.168.10.7", "TEST");
        assertNotNull(other, "OTHER_USER must authenticate cleanly with correct password.");
        assertEquals(OTHER_USER, other.getUsername());
    }

    @Test
    @Order(8)
    @DisplayName("TEST 8: Verify lock persists after service restart")
    public void test8_LockPersistsAfterServiceRestart() {
        // Lock TARGET_USER
        for (int i = 1; i <= 5; i++) {
            userService.authenticate(TARGET_USER, "WrongPass" + i, "192.168.10.8", "TEST");
        }
        assertTrue(accountLockoutService.isAccountLocked(TARGET_USER));

        // Create a completely new instance of AccountLockoutService (simulating application restart)
        AccountLockoutService restartedService = new AccountLockoutService();
        assertTrue(restartedService.isAccountLocked(TARGET_USER), "Lock state must persist in SQLite across service restarts.");
        AccountLockStatus status = restartedService.getAccountLockStatus(TARGET_USER);
        assertTrue(status.isLocked());
        assertEquals(5, status.getFailedAttemptCount());
    }

    @Test
    @Order(9)
    @DisplayName("TEST 9: Verify administrator service-level unlock")
    public void test9_AdministratorServiceLevelUnlock() {
        // Lock TARGET_USER
        for (int i = 1; i <= 5; i++) {
            userService.authenticate(TARGET_USER, "WrongPass" + i, "192.168.10.9", "TEST");
        }
        assertTrue(accountLockoutService.isAccountLocked(TARGET_USER));

        // Admin unlocks account
        boolean unlocked = accountLockoutService.unlockAccount(TARGET_USER, "admin");
        assertTrue(unlocked, "unlockAccount must return true on success.");

        assertFalse(accountLockoutService.isAccountLocked(TARGET_USER), "Account must now be unlocked.");
        AccountLockStatus status = accountLockoutService.getAccountLockStatus(TARGET_USER);
        assertFalse(status.isLocked());
        assertEquals(0, status.getFailedAttemptCount());

        // Target user can now log in
        User user = userService.authenticate(TARGET_USER, TARGET_PASS, "192.168.10.9", "TEST");
        assertNotNull(user, "User must authenticate after manual administrator unlock.");
    }

    @Test
    @Order(10)
    @DisplayName("TEST 10: Verify account lock events appear in activity_log")
    public void test10_AccountLockEventsAppearInActivityLog() throws SQLException {
        // Lock TARGET_USER
        for (int i = 1; i <= 5; i++) {
            userService.authenticate(TARGET_USER, "WrongPass" + i, "192.168.10.10", "TEST");
        }
        // Unlock TARGET_USER
        accountLockoutService.unlockAccount(TARGET_USER, "admin_auditor");

        // Query activity_log
        try (Connection conn = DatabaseManager.getConnection()) {
            String sqlLocked = "SELECT count(*) AS cnt FROM activity_log WHERE action = 'ACCOUNT_LOCKED' AND username = ?";
            try (PreparedStatement stmt = conn.prepareStatement(sqlLocked)) {
                stmt.setString(1, TARGET_USER);
                try (ResultSet rs = stmt.executeQuery()) {
                    assertTrue(rs.next());
                    assertTrue(rs.getInt("cnt") >= 1, "activity_log must record ACCOUNT_LOCKED event.");
                }
            }

            String sqlUnlocked = "SELECT count(*) AS cnt FROM activity_log WHERE action = 'ACCOUNT_UNLOCKED' AND username = 'admin_auditor'";
            try (PreparedStatement stmt = conn.prepareStatement(sqlUnlocked)) {
                try (ResultSet rs = stmt.executeQuery()) {
                    assertTrue(rs.next());
                    assertTrue(rs.getInt("cnt") >= 1, "activity_log must record ACCOUNT_UNLOCKED event by admin.");
                }
            }
        }
    }

    @Test
    @Order(11)
    @DisplayName("TEST 11: Verify unknown usernames are handled safely")
    public void test11_UnknownUsernamesHandledSafely() {
        String ghostUser = "non_existent_ghost_999";
        for (int i = 1; i <= 10; i++) {
            User user = userService.authenticate(ghostUser, "RandomPass" + i, "192.168.10.11", "TEST");
            assertNull(user, "Ghost user must never authenticate.");
        }

        assertFalse(accountLockoutService.isAccountLocked(ghostUser), "Non-existent user must return false for isAccountLocked.");
        assertNull(userService.findByUsername(ghostUser), "Ghost user must not have been created in SQLite database.");
    }

    @Test
    @Order(12)
    @DisplayName("TEST 12: Verify existing IDS failed-login recording still works")
    public void test12_ExistingIdsFailedLoginRecordingStillWorks() throws SQLException {
        String testIp = "192.168.88.77";
        userService.authenticate(TARGET_USER, "WrongPassForIds", testIp, "TEST");

        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement stmt = conn.prepareStatement("SELECT count(*) AS cnt FROM failed_logins WHERE ip_address = ?")) {
            stmt.setString(1, testIp);
            try (ResultSet rs = stmt.executeQuery()) {
                assertTrue(rs.next());
                assertTrue(rs.getInt("cnt") >= 1, "Failed login must be recorded in failed_logins table for IDS engine.");
            }
        }
    }

    @Test
    @Order(13)
    @DisplayName("TEST 13: Verify an IP-blocked request does not increment an account's failed-attempt counter")
    public void test13_IpBlockedRequestDoesNotIncrementFailedAttemptCounter() throws Exception {
        String blockedIp = "198.51.100.150";
        ipBlockService.blockIp(blockedIp, "Known botnet host", 15, "admin");
        assertTrue(ipBlockService.isBlocked(blockedIp));

        // Initial account counter is 0
        assertEquals(0, accountLockoutService.getAccountLockStatus(TARGET_USER).getFailedAttemptCount());

        // Send HTTP login request from blocked IP
        JsonObject payload = new JsonObject();
        payload.addProperty("username", TARGET_USER);
        payload.addProperty("password", "BadPassword");
        payload.addProperty("clientIp", blockedIp);

        HttpURLConnection conn = (HttpURLConnection) new URL("http://localhost:" + testServerPort + "/api/auth/login").openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/json");

        try (OutputStream os = conn.getOutputStream()) {
            os.write(payload.toString().getBytes(StandardCharsets.UTF_8));
        }

        int statusCode = conn.getResponseCode();
        assertEquals(403, statusCode, "Request from blocked IP must be rejected with HTTP 403 Forbidden.");

        // Target user counter must NOT have been incremented
        AccountLockStatus status = accountLockoutService.getAccountLockStatus(TARGET_USER);
        assertEquals(0, status.getFailedAttemptCount(), "Account failed_attempt_count must NOT increment when request is rejected by IP block.");
    }

    @Test
    @Order(14)
    @DisplayName("TEST 14: Verify simultaneous failed login requests do not bypass the threshold")
    public void test14_SimultaneousFailedLoginRequestsDoNotBypassThreshold() throws InterruptedException {
        int threads = 10;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threads);

        for (int i = 0; i < threads; i++) {
            final int index = i;
            executor.submit(() -> {
                try {
                    startLatch.await();
                    userService.authenticate(CONCURRENT_USER, "WrongConcurrent" + index, "127.0.0.1", "CONCURRENT_TEST");
                } catch (Exception ignored) {
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown(); // Trigger all threads simultaneously
        boolean completed = doneLatch.await(5, TimeUnit.SECONDS);
        executor.shutdown();
        assertTrue(completed, "All concurrent login attempts must complete within 5 seconds.");

        // Account must be locked and threshold strictly enforced
        assertTrue(accountLockoutService.isAccountLocked(CONCURRENT_USER), "Concurrent failed logins must lock the account.");
        AccountLockStatus status = accountLockoutService.getAccountLockStatus(CONCURRENT_USER);
        assertTrue(status.isLocked());

        // Subsequent valid login must be rejected
        User user = userService.authenticate(CONCURRENT_USER, CONCURRENT_PASS, "127.0.0.1", "TEST");
        assertNull(user, "User must NOT be able to log in even with correct password once locked.");
    }

    @Test
    @Order(15)
    @DisplayName("TEST 15: Verify locked accounts cannot generate authenticated sessions")
    public void test15_LockedAccountsCannotGenerateAuthenticatedSessions() throws Exception {
        // Lock TARGET_USER
        for (int i = 1; i <= 5; i++) {
            userService.authenticate(TARGET_USER, "WrongPass" + i, "192.168.10.15", "TEST");
        }
        assertTrue(accountLockoutService.isAccountLocked(TARGET_USER));

        // Attempt HTTP login with correct password
        JsonObject payload = new JsonObject();
        payload.addProperty("username", TARGET_USER);
        payload.addProperty("password", TARGET_PASS);

        HttpURLConnection conn = (HttpURLConnection) new URL("http://localhost:" + testServerPort + "/api/auth/login").openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/json");

        try (OutputStream os = conn.getOutputStream()) {
            os.write(payload.toString().getBytes(StandardCharsets.UTF_8));
        }

        int statusCode = conn.getResponseCode();
        assertEquals(423, statusCode, "Locked account login must return HTTP 423 Locked.");

        InputStream is = conn.getErrorStream() != null ? conn.getErrorStream() : conn.getInputStream();
        String responseBody = new String(is.readAllBytes(), StandardCharsets.UTF_8);
        JsonObject json = gson.fromJson(responseBody, JsonObject.class);

        assertNotNull(json);
        assertFalse(json.get("success").getAsBoolean(), "success must be false.");
        assertEquals("ACCOUNT_LOCKED", json.get("error").getAsString(), "error must be ACCOUNT_LOCKED.");
        assertTrue(json.has("lockedUntil"), "Response must contain lockedUntil timestamp.");
        assertTrue(json.has("remainingSeconds"), "Response must contain remainingSeconds.");
        assertFalse(json.has("token"), "Response MUST NOT contain an authentication token.");
    }
}
