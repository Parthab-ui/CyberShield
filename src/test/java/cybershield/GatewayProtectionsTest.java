package cybershield;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpServer;
import cybershield.database.DatabaseManager;
import cybershield.server.ApiHandler;
import cybershield.service.IpBlockService;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * GatewayProtectionsTest — Phase 4 Verification Suite.
 * Asserts that:
 * 1. Requests from a blocked IP receive HTTP 403 on non-login endpoints.
 * 2. The 11th login attempt from the same IP within 60s receives HTTP 429.
 * 3. A request body exceeding 64 KB returns HTTP 413.
 * 4. API responses include mandatory security headers.
 * 5. The catch block never leaks stack traces (generic 500 message).
 */
public class GatewayProtectionsTest {

    private static HttpServer server;
    private static int port;
    private static String adminToken;
    private static final Gson gson = new Gson();
    private static IpBlockService ipBlockService;

    @BeforeAll
    public static void setUp() throws Exception {
        DatabaseManager.initialize();
        ipBlockService = new IpBlockService();

        server = HttpServer.create(new InetSocketAddress(0), 0);
        ApiHandler handler = new ApiHandler(ipBlockService);
        server.createContext("/api", handler);
        server.start();
        port = server.getAddress().getPort();
        handler.addAllowedOrigin(port);

        // Authenticate as admin
        JsonObject login = new JsonObject();
        login.addProperty("username", "admin");
        login.addProperty("password", "Admin@123");
        HttpResponse res = send("POST", "/api/auth/login", login.toString(), null, 200);
        adminToken = gson.fromJson(res.body, JsonObject.class).get("token").getAsString();
    }

    @AfterAll
    public static void tearDown() {
        if (server != null) server.stop(0);
    }

    @Test
    @DisplayName("Test 1: Blocked IP gets 403 on a non-login endpoint")
    public void testBlockedIpGets403() throws Exception {
        ipBlockService.removeWhitelistedIp("127.0.0.1");
        try {
            // Block loopback IP via admin API
            JsonObject blockReq = new JsonObject();
            blockReq.addProperty("ipAddress", "127.0.0.1");
            blockReq.addProperty("reason", "GatewayTest block");
            blockReq.addProperty("durationMinutes", 1);
            send("POST", "/api/firewall/block", blockReq.toString(), adminToken, 201);

            // A GET to /api/incidents from loopback should now get 403
            HttpResponse res = send("GET", "/api/incidents", null, adminToken, -1);
            assertEquals(403, res.statusCode, "Blocked IP should receive 403 on non-login endpoints");
        } finally {
            // Unblock immediately and restore whitelist so other tests are not affected
            ipBlockService.unblockIp("127.0.0.1", "admin");
            ipBlockService.addWhitelistedIp("127.0.0.1");
        }
    }

    @Test
    @DisplayName("Test 2: 11th login attempt from the same IP in 60s returns HTTP 429")
    public void testRateLimitReturns429() throws Exception {
        // Use a fresh ApiHandler instance so this test has clean rate-limit state
        HttpServer testServer = HttpServer.create(new InetSocketAddress(0), 0);
        ApiHandler freshHandler = new ApiHandler(new IpBlockService());
        testServer.createContext("/api", freshHandler);
        testServer.start();
        int testPort = testServer.getAddress().getPort();
        freshHandler.addAllowedOrigin(testPort);
        try {
            JsonObject badLogin = new JsonObject();
            badLogin.addProperty("username", "nonexistent_rate_test_user");
            badLogin.addProperty("password", "wrongpass_rate_test");

            int lastStatus = -1;
            for (int i = 1; i <= 11; i++) {
                HttpResponse res = sendToPort(testPort, "POST", "/api/auth/login", badLogin.toString(), null, -1);
                lastStatus = res.statusCode;
            }
            assertEquals(429, lastStatus, "11th login attempt must return HTTP 429 rate limit");
        } finally {
            testServer.stop(0);
        }
    }

    @Test
    @DisplayName("Test 3: Request body > 64 KB returns HTTP 413")
    public void testOversizedBodyReturns413() throws Exception {
        // Create a 70 KB body
        byte[] bigBody = new byte[71680];
        Arrays.fill(bigBody, (byte) 'A');
        String bigStr = new String(bigBody, StandardCharsets.UTF_8);

        HttpResponse res = send("POST", "/api/auth/login", bigStr, null, -1);
        assertEquals(413, res.statusCode, "Body > 64 KB must return HTTP 413");
    }

    @Test
    @DisplayName("Test 4: API responses include mandatory security headers")
    public void testSecurityHeadersPresent() throws Exception {
        HttpResponse res = send("GET", "/api/dashboard/stats", null, adminToken, 200);
        assertNotNull(res.headers.get("x-content-type-options"), "X-Content-Type-Options header must be present");
        assertNotNull(res.headers.get("x-frame-options"), "X-Frame-Options header must be present");
        assertNotNull(res.headers.get("referrer-policy"), "Referrer-Policy header must be present");
        assertNotNull(res.headers.get("cache-control"), "Cache-Control header must be present");
    }

    @Test
    @DisplayName("Test 5: 500 error response does not expose stack trace details")
    public void testNo500StackTrace() throws Exception {
        // A malformed JSON body to a POST endpoint that parses JSON
        HttpResponse res = send("POST", "/api/incidents", "{invalid json!!!", adminToken, -1);
        if (res.statusCode == 500) {
            assertFalse(res.body.contains("java."), "500 response must not contain Java stack trace");
            assertFalse(res.body.contains("Exception"), "500 response must not contain exception class names");
        }
        assertTrue(res.statusCode == 400 || res.statusCode == 500 || res.statusCode == 201,
                "Response code should be 400, 201 or 500, got: " + res.statusCode);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static HttpResponse send(String method, String path, String body, String token, int expectedStatus)
            throws Exception {
        return sendToPort(port, method, path, body, token, expectedStatus);
    }

    private static HttpResponse sendToPort(int targetPort, String method, String path, String body,
                                            String token, int expectedStatus) throws Exception {
        URL url = new URL("http://localhost:" + targetPort + path);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod(method);
        conn.setRequestProperty("Content-Type", "application/json");
        if (token != null) conn.setRequestProperty("Authorization", "Bearer " + token);

        if (body != null) {
            conn.setDoOutput(true);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }
        }

        int status = conn.getResponseCode();
        InputStream is = (status >= 200 && status < 300) ? conn.getInputStream() : conn.getErrorStream();
        String responseBody = (is != null) ? new String(is.readAllBytes(), StandardCharsets.UTF_8) : "";

        java.util.Map<String, String> headers = new java.util.HashMap<>();
        conn.getHeaderFields().forEach((k, v) -> {
            if (k != null) headers.put(k.toLowerCase(), String.join(", ", v));
        });

        if (expectedStatus != -1) {
            assertEquals(expectedStatus, status,
                    "Expected HTTP " + expectedStatus + " from " + method + " " + path + ", got " + status + ". Body: " + responseBody);
        }

        return new HttpResponse(status, responseBody, headers);
    }

    private record HttpResponse(int statusCode, String body, java.util.Map<String, String> headers) {}
}
