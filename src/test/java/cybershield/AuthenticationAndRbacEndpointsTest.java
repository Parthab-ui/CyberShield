package cybershield;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpServer;
import cybershield.database.DatabaseManager;
import cybershield.model.Incident;
import cybershield.server.ApiHandler;
import cybershield.service.IncidentService;
import cybershield.ui.ApiClient;
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

import static org.junit.jupiter.api.Assertions.*;

/**
 * AuthenticationAndRbacEndpointsTest — Phase 3 Verification Suite.
 * Asserts that:
 * 1. Every sensitive API endpoint returns HTTP 401 without authentication.
 * 2. Every administrative endpoint returns HTTP 403 when invoked by ANALYST role.
 * 3. Desktop ApiClient enforces authentication before service dispatch.
 */
public class AuthenticationAndRbacEndpointsTest {

    private static HttpServer server;
    private static int port;
    private static String adminToken;
    private static String analystToken;
    private static final Gson gson = new Gson();
    private static int sampleIncidentId;

    @BeforeAll
    public static void setUp() throws Exception {
        DatabaseManager.initialize();

        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/api", new ApiHandler());
        server.start();
        port = server.getAddress().getPort();

        // Login as admin
        JsonObject adminLogin = new JsonObject();
        adminLogin.addProperty("username", "admin");
        adminLogin.addProperty("password", "Admin@123");
        String resAdmin = sendPost("/api/auth/login", adminLogin.toString(), null, 200);
        adminToken = gson.fromJson(resAdmin, JsonObject.class).get("token").getAsString();

        // Login as analyst
        JsonObject analystLogin = new JsonObject();
        analystLogin.addProperty("username", "analyst");
        analystLogin.addProperty("password", "Analyst@123");
        String resAnalyst = sendPost("/api/auth/login", analystLogin.toString(), null, 200);
        analystToken = gson.fromJson(resAnalyst, JsonObject.class).get("token").getAsString();

        // Create sample incident
        IncidentService incidentService = new IncidentService();
        Incident inc = new Incident("Auth RBAC Test Target", "Incident for RBAC verification", "LOW", "OPEN");
        Incident created = incidentService.create(inc, "admin");
        sampleIncidentId = created.getId();
    }

    @AfterAll
    public static void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("Test 1: Sensitive GET endpoints strictly return 401 when called without a token")
    public void testGetEndpointsRequireAuth() throws Exception {
        String[] endpoints = {
                "/api/dashboard/stats",
                "/api/incidents",
                "/api/incidents/" + sampleIncidentId,
                "/api/access-events",
                "/api/activity",
                "/api/alerts",
                "/api/alerts/latest",
                "/api/intrusion/config",
                "/api/threat-responses",
                "/api/threat-responses/stats",
                "/api/firewall/blocked-ips",
                "/api/auth/locked-accounts",
                "/api/investigators",
                "/api/incidents/" + sampleIncidentId + "/investigations",
                "/api/incidents/" + sampleIncidentId + "/timeline",
                "/api/incidents/" + sampleIncidentId + "/investigation-summary"
        };

        for (String endpoint : endpoints) {
            int code = sendGetRaw(endpoint, null);
            assertEquals(401, code, "Endpoint " + endpoint + " must return 401 when called unauthenticated");
        }
    }

    @Test
    @DisplayName("Test 2: Sensitive POST/PUT/DELETE endpoints strictly return 401 when called without a token")
    public void testMutationEndpointsRequireAuth() throws Exception {
        JsonObject dummy = new JsonObject();
        dummy.addProperty("title", "Test");
        dummy.addProperty("notes", "Test");
        dummy.addProperty("ip", "1.2.3.4");

        assertEquals(401, sendRequestRaw("POST", "/api/incidents", dummy.toString(), null));
        assertEquals(401, sendRequestRaw("PUT", "/api/incidents/" + sampleIncidentId, dummy.toString(), null));
        assertEquals(401, sendRequestRaw("DELETE", "/api/incidents/" + sampleIncidentId, null, null));
        assertEquals(401, sendRequestRaw("POST", "/api/access-events/simulate", null, null));
        assertEquals(401, sendRequestRaw("POST", "/api/intrusion/simulate-attack", dummy.toString(), null));
        assertEquals(401, sendRequestRaw("POST", "/api/firewall/block", dummy.toString(), null));
        assertEquals(401, sendRequestRaw("POST", "/api/firewall/unblock", dummy.toString(), null));
        assertEquals(401, sendRequestRaw("POST", "/api/auth/unlock", dummy.toString(), null));
        assertEquals(401, sendRequestRaw("POST", "/api/incidents/" + sampleIncidentId + "/assign", dummy.toString(), null));
        assertEquals(401, sendRequestRaw("POST", "/api/incidents/" + sampleIncidentId + "/investigations", dummy.toString(), null));
        assertEquals(401, sendRequestRaw("POST", "/api/incidents/" + sampleIncidentId + "/root-cause", dummy.toString(), null));
        assertEquals(401, sendRequestRaw("POST", "/api/incidents/" + sampleIncidentId + "/resolve", dummy.toString(), null));
    }

    @Test
    @DisplayName("Test 3: Admin-only operations return 403 when attempted by an Analyst")
    public void testAdminEndpointsRejectAnalystWith403() throws Exception {
        JsonObject blockReq = new JsonObject();
        blockReq.addProperty("ip", "10.99.99.99");
        blockReq.addProperty("reason", "Analyst test");

        JsonObject unlockReq = new JsonObject();
        unlockReq.addProperty("username", "admin");

        JsonObject assignReq = new JsonObject();
        assignReq.addProperty("assignedAnalyst", "analyst");

        // Analyst attempting admin operations:
        assertEquals(403, sendRequestRaw("POST", "/api/firewall/block", blockReq.toString(), analystToken));
        assertEquals(403, sendRequestRaw("POST", "/api/firewall/unblock", blockReq.toString(), analystToken));
        assertEquals(403, sendRequestRaw("POST", "/api/auth/unlock", unlockReq.toString(), analystToken));
        assertEquals(403, sendRequestRaw("GET", "/api/auth/locked-accounts", null, analystToken));
        assertEquals(403, sendRequestRaw("DELETE", "/api/incidents/" + sampleIncidentId, null, analystToken));
        assertEquals(403, sendRequestRaw("POST", "/api/incidents/" + sampleIncidentId + "/assign", assignReq.toString(), analystToken));
    }

    @Test
    @DisplayName("Test 4: Desktop ApiClient requires active login before dispatching operations")
    public void testDesktopApiClientRequiresLogin() {
        ApiClient client = ApiClient.getInstance();
        client.logout();
        assertFalse(client.isAuthenticated());

        assertThrows(SecurityException.class, client::getDashboardStats);
        assertThrows(SecurityException.class, () -> client.getIncidents(null, null, null));
        assertThrows(SecurityException.class, () -> client.getIncidentById(1));
        assertThrows(SecurityException.class, () -> client.getBlockedIps("ALL"));
    }

    // =========================================================================
    // HTTP HELPERS
    // =========================================================================

    private static int sendGetRaw(String path, String token) throws Exception {
        URL url = new URL("http://localhost:" + port + path);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        if (token != null) {
            conn.setRequestProperty("Authorization", "Bearer " + token);
        }
        return conn.getResponseCode();
    }

    private static int sendRequestRaw(String method, String path, String body, String token) throws Exception {
        URL url = new URL("http://localhost:" + port + path);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod(method);
        if (token != null) {
            conn.setRequestProperty("Authorization", "Bearer " + token);
        }
        if (body != null) {
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json");
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }
        }
        return conn.getResponseCode();
    }

    private static String sendPost(String path, String body, String token, int expectedCode) throws Exception {
        URL url = new URL("http://localhost:" + port + path);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/json");
        if (token != null) {
            conn.setRequestProperty("Authorization", "Bearer " + token);
        }
        try (OutputStream os = conn.getOutputStream()) {
            os.write(body.getBytes(StandardCharsets.UTF_8));
        }
        int code = conn.getResponseCode();
        assertEquals(expectedCode, code);
        try (InputStream is = conn.getInputStream()) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
