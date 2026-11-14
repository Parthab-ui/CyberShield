package cybershield;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpServer;
import cybershield.database.DatabaseManager;
import cybershield.model.BlockedIp;
import cybershield.model.User;
import cybershield.server.ApiHandler;
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
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * IpBlockServiceTest — Automated validation suite for Review 3 Phase 2.
 * Verifies application-level IP blocking, whitelist protection, block expiration,
 * duplicate suppression, persistence across service instances, and HTTP 403 enforcement.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class IpBlockServiceTest {

    private static IpBlockService ipBlockService;
    private static HttpServer testHttpServer;
    private static int testServerPort;
    private static final Gson gson = new Gson();

    @BeforeAll
    public static void setUpClass() throws Exception {
        DatabaseManager.initialize();
        ipBlockService = new IpBlockService();
        ipBlockService.clearBlockHistory();

        // Start an embedded ephemeral HTTP server for end-to-end API login tests (Tests 11 & 12)
        testHttpServer = HttpServer.create(new InetSocketAddress(0), 0);
        testHttpServer.createContext("/api", new ApiHandler(ipBlockService));
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
        // Clear blocks before tests to ensure test isolation
        ipBlockService.clearBlockHistory();
    }

    @Test
    @Order(1)
    @DisplayName("TEST 1: Block a valid IP address -> record created successfully")
    public void test1_BlockValidIpAddress() {
        String ip = "198.51.100.10";
        BlockedIp block = ipBlockService.blockIp(ip, "Brute force detected on gateway", 15, "admin");

        assertNotNull(block, "BlockedIp record must not be null.");
        assertTrue(block.getId() > 0, "Record must have a valid generated SQLite ID.");
        assertEquals(ip, block.getIpAddress());
        assertEquals("ACTIVE", block.getStatus());
        assertEquals("admin", block.getBlockedBy());
        assertNotNull(block.getExpiresAt());
        assertTrue(block.getExpiresAt() > block.getBlockedAt());
    }

    @Test
    @Order(2)
    @DisplayName("TEST 2: Check an actively blocked IP -> isBlocked() returns true")
    public void test2_CheckActivelyBlockedIp() {
        String ip = "198.51.100.20";
        ipBlockService.blockIp(ip, "Port scan probe", 15, "IDS_ENGINE");

        assertTrue(ipBlockService.isBlocked(ip), "isBlocked() must return true for actively blocked IP.");
        BlockedIp active = ipBlockService.getActiveBlock(ip);
        assertNotNull(active);
        assertEquals("ACTIVE", active.getStatus());
    }

    @Test
    @Order(3)
    @DisplayName("TEST 3: Attempt to block the same IP twice -> No duplicate active records")
    public void test3_DuplicateBlockPrevention() {
        String ip = "198.51.100.30";
        BlockedIp first = ipBlockService.blockIp(ip, "First trigger", 15, "admin");
        BlockedIp second = ipBlockService.blockIp(ip, "Second trigger attempt", 15, "admin");

        assertNotNull(first);
        assertNotNull(second);
        assertEquals(first.getId(), second.getId(), "Subsequent block call must return existing active block.");

        // Query database directly to confirm only 1 active record exists
        List<BlockedIp> activeList = ipBlockService.getBlockedIps("ACTIVE", false);
        long countForIp = activeList.stream().filter(b -> ip.equals(b.getIpAddress())).count();
        assertEquals(1, countForIp, "Database must not contain duplicate active records for the same IP.");
    }

    @Test
    @Order(4)
    @DisplayName("TEST 4: Check a different IP address -> remains unblocked")
    public void test4_DifferentIpRemainsUnblocked() {
        String blockedIp = "198.51.100.40";
        String unblockedIp = "198.51.100.41";

        ipBlockService.blockIp(blockedIp, "Credential stuffing", 15, "admin");

        assertTrue(ipBlockService.isBlocked(blockedIp), "Target IP must be blocked.");
        assertFalse(ipBlockService.isBlocked(unblockedIp), "Unrelated IP must remain unblocked.");
        assertNull(ipBlockService.getActiveBlock(unblockedIp));
    }

    @Test
    @Order(5)
    @DisplayName("TEST 5: Check an expired IP block -> Access is allowed and status becomes EXPIRED")
    public void test5_ExpiredBlockAllowsAccessAndMarksExpired() {
        String ip = "198.51.100.50";
        long now = System.currentTimeMillis();

        // Create a 15-minute block starting 20 minutes ago (already expired)
        long twentyMinutesAgo = now - (20 * 60 * 1000L);
        ipBlockService.blockIp(ip, "Expired test probe", 15, "admin", twentyMinutesAgo);

        // Check isBlocked at current time
        boolean blocked = ipBlockService.isBlocked(ip, now);
        assertFalse(blocked, "Access must be allowed once block duration has lapsed.");

        // Verify status was transitioned to EXPIRED in SQLite
        List<BlockedIp> history = ipBlockService.getBlockedIps("EXPIRED", true);
        boolean foundExpired = history.stream().anyMatch(b -> ip.equals(b.getIpAddress()) && "EXPIRED".equals(b.getStatus()));
        assertTrue(foundExpired, "Expired block must be updated to EXPIRED status in database.");
    }

    @Test
    @Order(6)
    @DisplayName("TEST 6: Manually unblock an IP -> Status becomes UNBLOCKED and access is allowed")
    public void test6_ManuallyUnblockIp() {
        String ip = "198.51.100.60";
        ipBlockService.blockIp(ip, "Suspicious probe", 30, "admin");
        assertTrue(ipBlockService.isBlocked(ip));

        // Administrator manually unblocks the IP
        boolean unblocked = ipBlockService.unblockIp(ip, "admin_analyst");
        assertTrue(unblocked, "unblockIp() must return true for an active block.");

        // Access must now be allowed
        assertFalse(ipBlockService.isBlocked(ip), "Unblocked IP must no longer be blocked.");

        // Historical record preserved with UNBLOCKED status
        List<BlockedIp> unblockedList = ipBlockService.getBlockedIps("UNBLOCKED", true);
        BlockedIp record = unblockedList.stream().filter(b -> ip.equals(b.getIpAddress())).findFirst().orElse(null);
        assertNotNull(record);
        assertEquals("UNBLOCKED", record.getStatus());
        assertEquals("admin_analyst", record.getUnblockedBy());
        assertNotNull(record.getUnblockedAt());
    }

    @Test
    @Order(7)
    @DisplayName("TEST 7: Try blocking 127.0.0.1 -> Request rejected by whitelist protection")
    public void test7_WhitelistRejectsLoopbackIpv4() {
        assertThrows(IllegalArgumentException.class, () -> {
            ipBlockService.blockIp("127.0.0.1", "Accidental local block", 15, "admin");
        }, "Attempts to block 127.0.0.1 must throw IllegalArgumentException.");

        assertFalse(ipBlockService.isBlocked("127.0.0.1"), "127.0.0.1 must never be blocked.");
    }

    @Test
    @Order(8)
    @DisplayName("TEST 8: Try blocking ::1 -> Request rejected by whitelist protection")
    public void test8_WhitelistRejectsLoopbackIpv6() {
        assertThrows(IllegalArgumentException.class, () -> {
            ipBlockService.blockIp("::1", "Accidental local block", 15, "admin");
        }, "Attempts to block ::1 must throw IllegalArgumentException.");

        assertFalse(ipBlockService.isBlocked("::1"), "::1 must never be blocked.");
    }

    @Test
    @Order(9)
    @DisplayName("TEST 9: Try malformed IP addresses -> Invalid addresses are rejected")
    public void test9_MalformedIpAddressesRejected() {
        String[] invalidIps = {
                null,
                "",
                "   ",
                "999.999.999.999",
                "192.168.1",
                "192.168.1.1.1",
                "google.com",
                "not-an-ip-address",
                "192.168.1.256"
        };

        for (String invalid : invalidIps) {
            assertFalse(ipBlockService.isValidIp(invalid), "Expected invalid: " + invalid);
            assertThrows(IllegalArgumentException.class, () -> {
                ipBlockService.blockIp(invalid, "Testing invalid IP", 15, "admin");
            }, "Blocking malformed IP '" + invalid + "' must throw IllegalArgumentException.");
        }
    }

    @Test
    @Order(10)
    @DisplayName("TEST 10: Restart service and check an existing active block -> Persists in SQLite")
    public void test10_BlockPersistsAcrossServiceInstances() {
        String ip = "198.51.100.100";
        ipBlockService.blockIp(ip, "Persistent block test", 60, "admin");
        assertTrue(ipBlockService.isBlocked(ip));

        // Create a completely new instance of IpBlockService simulating application restart
        IpBlockService freshInstance = new IpBlockService();
        assertTrue(freshInstance.isBlocked(ip), "Block must persist across new service instances via SQLite.");

        BlockedIp retrieved = freshInstance.getActiveBlock(ip);
        assertNotNull(retrieved);
        assertEquals(ip, retrieved.getIpAddress());
        assertEquals("Persistent block test", retrieved.getReason());
        assertEquals("ACTIVE", retrieved.getStatus());
    }

    @Test
    @Order(11)
    @DisplayName("TEST 11: Attempt login using a blocked IP -> HTTP 403 and authentication is not executed")
    public void test11_LoginFromBlockedIpReturnsHttp403() throws Exception {
        String attackerIp = "198.51.100.111";
        ipBlockService.blockIp(attackerIp, "Attack detected", 15, "admin");

        // Send login HTTP request from blocked IP
        URL url = new URL("http://localhost:" + testServerPort + "/api/auth/login");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        // Supply valid admin credentials, but from the blocked client IP
        String payload = "{\"username\":\"admin\",\"password\":\"Admin@123\",\"clientIp\":\"" + attackerIp + "\"}";
        try (OutputStream os = conn.getOutputStream()) {
            os.write(payload.getBytes(StandardCharsets.UTF_8));
        }

        int responseCode = conn.getResponseCode();
        assertEquals(403, responseCode, "Login request from blocked IP must return HTTP 403 Forbidden!");

        // Read error stream
        try (InputStream is = conn.getErrorStream()) {
            String respBody = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            JsonObject json = gson.fromJson(respBody, JsonObject.class);
            assertFalse(json.get("success").getAsBoolean());
            assertEquals("IP_BLOCKED", json.get("error").getAsString());
            assertTrue(json.has("expiresAt"));
            assertTrue(json.get("expiresAt").getAsLong() > 0);
        }
    }

    @Test
    @Order(12)
    @DisplayName("TEST 12: Attempt login using an unblocked IP -> Normal authentication behavior continues")
    public void test12_LoginFromUnblockedIpSucceedsNormally() throws Exception {
        String allowedIp = "198.51.100.222";
        assertFalse(ipBlockService.isBlocked(allowedIp));

        // Send login HTTP request with valid credentials from allowed IP
        URL url = new URL("http://localhost:" + testServerPort + "/api/auth/login");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        String payload = "{\"username\":\"admin\",\"password\":\"Admin@123\",\"clientIp\":\"" + allowedIp + "\"}";
        try (OutputStream os = conn.getOutputStream()) {
            os.write(payload.getBytes(StandardCharsets.UTF_8));
        }

        int responseCode = conn.getResponseCode();
        assertEquals(200, responseCode, "Login request from unblocked IP must return HTTP 200 OK!");

        try (InputStream is = conn.getInputStream()) {
            String respBody = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            JsonObject json = gson.fromJson(respBody, JsonObject.class);
            assertTrue(json.get("success").getAsBoolean());
            assertTrue(json.has("token"));
            assertEquals("admin", json.getAsJsonObject("user").get("username").getAsString());
        }
    }
}

