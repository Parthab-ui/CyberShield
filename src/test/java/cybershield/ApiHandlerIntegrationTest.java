package cybershield;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpServer;
import cybershield.database.DatabaseManager;
import cybershield.model.Incident;
import cybershield.model.User;
import cybershield.server.ApiHandler;
import cybershield.service.IncidentService;
import cybershield.service.IpBlockService;
import cybershield.service.AccountLockoutService;
import cybershield.service.UserService;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
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

import static org.junit.jupiter.api.Assertions.*;

/**
 * ApiHandlerIntegrationTest — Automated integration suite for Review 3 Phase 6A REST API endpoints.
 *
 * Verifies:
 * - Unauthenticated requests receive HTTP 401.
 * - Role-Based Access Control: ADMIN operations permitted, ANALYST restricted from administrative tasks (HTTP 403).
 * - IP blocking and unblocking API endpoints.
 * - Account locking inspection and unlocking API endpoints.
 * - Threat response retrieval and statistics API endpoints.
 * - Incident investigation notes, JSON evidence validation, timeline, assignment, root cause, resolution.
 * - Non-existent resources receive HTTP 404.
 * - Malformed JSON payloads receive HTTP 400.
 * - Username impersonation prevention (server always binds to authenticated token).
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ApiHandlerIntegrationTest {

    private static HttpServer server;
    private static int port;
    private static String adminToken;
    private static String analystToken;
    private static final Gson gson = new Gson();
    private static IncidentService incidentService;
    private static int testIncidentId;

    @BeforeAll
    public static void setUpClass() throws Exception {
        DatabaseManager.initialize();
        incidentService = new IncidentService();

        // Start embedded HTTP test server on dynamic free port
        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/api", new ApiHandler());
        server.start();
        port = server.getAddress().getPort();

        // Authenticate as Admin
        JsonObject adminLogin = new JsonObject();
        adminLogin.addProperty("username", "admin");
        adminLogin.addProperty("password", "Admin@123");
        adminLogin.addProperty("source", "TEST_SUITE");
        HttpResponse resAdmin = sendPost("/api/auth/login", adminLogin.toString(), null);
        assertEquals(200, resAdmin.statusCode);
        JsonObject adminJson = gson.fromJson(resAdmin.body, JsonObject.class);
        adminToken = adminJson.get("token").getAsString();
        assertNotNull(adminToken);

        // Authenticate as Analyst
        JsonObject analystLogin = new JsonObject();
        analystLogin.addProperty("username", "analyst");
        analystLogin.addProperty("password", "Analyst@123");
        analystLogin.addProperty("source", "TEST_SUITE");
        HttpResponse resAnalyst = sendPost("/api/auth/login", analystLogin.toString(), null);
        assertEquals(200, resAnalyst.statusCode);
        JsonObject analystJson = gson.fromJson(resAnalyst.body, JsonObject.class);
        analystToken = analystJson.get("token").getAsString();
        assertNotNull(analystToken);

        // Create a test incident for investigation endpoint tests
        Incident inc = new Incident();
        inc.setTitle("REST API Investigation Target");
        inc.setDescription("Synthetic target incident for REST API forensic triage tests");
        inc.setSeverity("HIGH");
        inc.setStatus("OPEN");
        Incident created = incidentService.create(inc, "admin");
        assertNotNull(created);
        testIncidentId = created.getId();
    }

    @AfterAll
    public static void tearDownClass() {
        if (server != null) {
            server.stop(0);
        }
    }

    // =========================================================================
    // 1. AUTHENTICATION & RBAC ENFORCEMENT TESTS
    // =========================================================================

    @Test
    @Order(1)
    @DisplayName("API TEST 1: Unauthenticated request to protected endpoint returns HTTP 401")
    public void test1_UnauthenticatedRequest_Returns401() throws Exception {
        HttpResponse res = sendGet("/api/firewall/blocked-ips", null);
        assertEquals(401, res.statusCode);
        assertTrue(res.body.contains("Authentication required"));
    }

    @Test
    @Order(2)
    @DisplayName("API TEST 2: Invalid or expired Bearer token returns HTTP 401")
    public void test2_InvalidToken_Returns401() throws Exception {
        HttpResponse res = sendGet("/api/firewall/blocked-ips", "bogus_invalid_token_xyz");
        assertEquals(401, res.statusCode);
    }

    @Test
    @Order(3)
    @DisplayName("API TEST 3: Analyst attempting administrative IP block returns HTTP 403 Forbidden")
    public void test3_AnalystUnauthorizedIpBlock_Returns403() throws Exception {
        JsonObject blockReq = new JsonObject();
        blockReq.addProperty("ipAddress", "198.51.100.99");
        blockReq.addProperty("reason", "Analyst unauthorized attempt");
        HttpResponse res = sendPost("/api/firewall/block", blockReq.toString(), analystToken);
        assertEquals(403, res.statusCode);
        assertTrue(res.body.contains("Permission Denied"));
    }

    @Test
    @Order(4)
    @DisplayName("API TEST 4: Analyst attempting administrative account unlock returns HTTP 403 Forbidden")
    public void test4_AnalystUnauthorizedAccountUnlock_Returns403() throws Exception {
        JsonObject unlockReq = new JsonObject();
        unlockReq.addProperty("username", "admin");
        HttpResponse res = sendPost("/api/auth/unlock", unlockReq.toString(), analystToken);
        assertEquals(403, res.statusCode);
        assertTrue(res.body.contains("Permission Denied"));
    }

    // =========================================================================
    // 2. FIREWALL & IP BLOCK MANAGEMENT TESTS
    // =========================================================================

    @Test
    @Order(5)
    @DisplayName("API TEST 5: Admin manually blocks an IP address (HTTP 201 Created)")
    public void test5_AdminBlockIp_Returns201() throws Exception {
        JsonObject blockReq = new JsonObject();
        blockReq.addProperty("ipAddress", "203.0.113.55");
        blockReq.addProperty("reason", "Malicious scanner probe");
        blockReq.addProperty("durationMinutes", 15);

        HttpResponse res = sendPost("/api/firewall/block", blockReq.toString(), adminToken);
        assertEquals(201, res.statusCode);
        JsonObject json = gson.fromJson(res.body, JsonObject.class);
        assertTrue(json.get("success").getAsBoolean());
        assertTrue(json.get("message").getAsString().contains("blocked successfully"));
    }

    @Test
    @Order(6)
    @DisplayName("API TEST 6: Retrieve blocked IPs via GET /api/firewall/blocked-ips")
    public void test6_GetBlockedIps_Returns200() throws Exception {
        HttpResponse res = sendGet("/api/firewall/blocked-ips?status=ACTIVE", analystToken);
        assertEquals(200, res.statusCode);
        JsonArray array = gson.fromJson(res.body, JsonArray.class);
        assertNotNull(array);
        boolean found = false;
        for (int i = 0; i < array.size(); i++) {
            JsonObject obj = array.get(i).getAsJsonObject();
            if ("203.0.113.55".equals(obj.get("ipAddress").getAsString())) {
                found = true;
                break;
            }
        }
        assertTrue(found, "Newly blocked IP must be present in active blocked IPs list");
    }

    @Test
    @Order(7)
    @DisplayName("API TEST 7: Admin manually unblocks an IP address (HTTP 200 OK)")
    public void test7_AdminUnblockIp_Returns200() throws Exception {
        JsonObject unblockReq = new JsonObject();
        unblockReq.addProperty("ipAddress", "203.0.113.55");

        HttpResponse res = sendPost("/api/firewall/unblock", unblockReq.toString(), adminToken);
        assertEquals(200, res.statusCode);
        JsonObject json = gson.fromJson(res.body, JsonObject.class);
        assertTrue(json.get("success").getAsBoolean());
        assertTrue(json.get("message").getAsString().contains("unblocked successfully"));
    }

    // =========================================================================
    // 3. ACCOUNT LOCKOUT & THREAT RESPONSES TESTS
    // =========================================================================

    @Test
    @Order(8)
    @DisplayName("API TEST 8: Admin views locked accounts via GET /api/auth/locked-accounts")
    public void test8_GetLockedAccounts_Returns200() throws Exception {
        HttpResponse res = sendGet("/api/auth/locked-accounts", adminToken);
        assertEquals(200, res.statusCode);
        JsonArray array = gson.fromJson(res.body, JsonArray.class);
        assertNotNull(array);
    }

    @Test
    @Order(9)
    @DisplayName("API TEST 9: Threat response history and statistics retrieval")
    public void test9_GetThreatResponsesAndStats_Returns200() throws Exception {
        HttpResponse resHistory = sendGet("/api/threat-responses", analystToken);
        assertEquals(200, resHistory.statusCode);

        HttpResponse resStats = sendGet("/api/threat-responses/stats", analystToken);
        assertEquals(200, resStats.statusCode);
        JsonObject stats = gson.fromJson(resStats.body, JsonObject.class);
        assertTrue(stats.has("totalResponses"));
        assertTrue(stats.has("successfulBlocks"));
    }

    // =========================================================================
    // 4. INCIDENT INVESTIGATION & FORENSIC TRIAGE REST API TESTS
    // =========================================================================

    @Test
    @Order(10)
    @DisplayName("API TEST 10: Assign investigator to incident (Admin only, HTTP 200)")
    public void test10_AssignInvestigator_Returns200() throws Exception {
        JsonObject assignReq = new JsonObject();
        assignReq.addProperty("assignedAnalyst", "analyst");

        HttpResponse res = sendPost("/api/incidents/" + testIncidentId + "/assign", assignReq.toString(), adminToken);
        assertEquals(200, res.statusCode);
        JsonObject json = gson.fromJson(res.body, JsonObject.class);
        assertTrue(json.get("success").getAsBoolean());
        JsonObject inc = json.get("incident").getAsJsonObject();
        assertEquals("analyst", inc.get("assignedTo").getAsString());
        assertEquals("INVESTIGATING", inc.get("status").getAsString());
    }

    @Test
    @Order(11)
    @DisplayName("API TEST 11: Add investigation note with valid JSON evidence (Analyst, HTTP 201)")
    public void test11_AddInvestigationNote_Returns201() throws Exception {
        JsonObject noteReq = new JsonObject();
        noteReq.addProperty("notes", "Correlating packet capture with authentication failure logs");
        noteReq.addProperty("evidenceData", "{\"evidenceType\":\"LOGIN_ACTIVITY\",\"sourceIp\":\"198.51.100.88\",\"failedCount\":5}");

        HttpResponse res = sendPost("/api/incidents/" + testIncidentId + "/investigations", noteReq.toString(), analystToken);
        assertEquals(201, res.statusCode);
        JsonObject createdNote = gson.fromJson(res.body, JsonObject.class);
        assertEquals(testIncidentId, createdNote.get("incidentId").getAsInt());
        assertEquals("analyst", createdNote.get("analystUsername").getAsString());
        assertTrue(createdNote.get("notes").getAsString().contains("Correlating packet capture"));
    }

    @Test
    @Order(12)
    @DisplayName("API TEST 12: Add investigation note with malformed JSON evidence rejected (HTTP 400)")
    public void test12_AddInvestigationNoteMalformedJson_Returns400() throws Exception {
        JsonObject badReq = new JsonObject();
        badReq.addProperty("notes", "Testing malformed json payload");
        badReq.addProperty("evidenceData", "{\"evidenceType\": UNTERMINATED_CORRUPT_PAYLOAD");

        HttpResponse res = sendPost("/api/incidents/" + testIncidentId + "/investigations", badReq.toString(), analystToken);
        assertEquals(400, res.statusCode);
        assertTrue(res.body.contains("Malformed JSON evidence payload") || res.body.contains("error"));
    }

    @Test
    @Order(13)
    @DisplayName("API TEST 13: Retrieve investigation notes (HTTP 200)")
    public void test13_GetInvestigationNotes_Returns200() throws Exception {
        HttpResponse res = sendGet("/api/incidents/" + testIncidentId + "/investigations", analystToken);
        assertEquals(200, res.statusCode);
        JsonArray array = gson.fromJson(res.body, JsonArray.class);
        assertTrue(array.size() >= 1);
    }

    @Test
    @Order(14)
    @DisplayName("API TEST 14: Update root cause classification (Analyst, HTTP 200)")
    public void test14_UpdateRootCause_Returns200() throws Exception {
        JsonObject rcReq = new JsonObject();
        rcReq.addProperty("category", "BRUTE_FORCE_ATTACK");
        rcReq.addProperty("explanation", "Distributed credential spray originating from single ASN");

        HttpResponse res = sendPost("/api/incidents/" + testIncidentId + "/root-cause", rcReq.toString(), analystToken);
        assertEquals(200, res.statusCode);
        JsonObject json = gson.fromJson(res.body, JsonObject.class);
        assertTrue(json.get("success").getAsBoolean());
        assertEquals("BRUTE_FORCE_ATTACK", json.get("incident").getAsJsonObject().get("rootCauseCategory").getAsString());
    }

    @Test
    @Order(15)
    @DisplayName("API TEST 15: Retrieve chronological investigation timeline (HTTP 200)")
    public void test15_GetInvestigationTimeline_Returns200() throws Exception {
        HttpResponse res = sendGet("/api/incidents/" + testIncidentId + "/timeline", analystToken);
        assertEquals(200, res.statusCode);
        JsonArray array = gson.fromJson(res.body, JsonArray.class);
        assertTrue(array.size() >= 2, "Timeline must aggregate creation, assignment, notes");
    }

    @Test
    @Order(16)
    @DisplayName("API TEST 16: Retrieve investigation case summary (HTTP 200)")
    public void test16_GetInvestigationSummary_Returns200() throws Exception {
        HttpResponse res = sendGet("/api/incidents/" + testIncidentId + "/investigation-summary", analystToken);
        assertEquals(200, res.statusCode);
        JsonObject summary = gson.fromJson(res.body, JsonObject.class);
        assertEquals(testIncidentId, summary.get("incidentId").getAsInt());
        assertEquals("analyst", summary.get("assignedInvestigator").getAsString());
        assertEquals("BRUTE_FORCE_ATTACK", summary.get("rootCauseCategory").getAsString());
    }

    @Test
    @Order(17)
    @DisplayName("API TEST 17: Resolve incident with technical resolution summary (HTTP 200)")
    public void test17_ResolveIncident_Returns200() throws Exception {
        JsonObject resolveReq = new JsonObject();
        resolveReq.addProperty("resolutionSummary", "Border ACL updated, compromised accounts rotated, no data loss.");

        HttpResponse res = sendPost("/api/incidents/" + testIncidentId + "/resolve", resolveReq.toString(), analystToken);
        assertEquals(200, res.statusCode);
        JsonObject json = gson.fromJson(res.body, JsonObject.class);
        assertTrue(json.get("success").getAsBoolean());

        // Verify status in DB
        Incident resolved = incidentService.getById(testIncidentId);
        assertEquals("RESOLVED", resolved.getStatus());
        assertEquals("Border ACL updated, compromised accounts rotated, no data loss.", resolved.getResolutionSummary());
    }

    @Test
    @Order(18)
    @DisplayName("API TEST 18: Nonexistent incident returns HTTP 404")
    public void test18_NonexistentIncident_Returns404() throws Exception {
        HttpResponse resNotes = sendGet("/api/incidents/999999/investigations", analystToken);
        assertEquals(404, resNotes.statusCode);

        HttpResponse resTimeline = sendGet("/api/incidents/999999/timeline", analystToken);
        assertEquals(404, resTimeline.statusCode);
    }

    @Test
    @Order(19)
    @DisplayName("API TEST 19: Retrieve assignable investigators directory (HTTP 200)")
    public void test19_GetAssignableInvestigators_Returns200() throws Exception {
        HttpResponse res = sendGet("/api/investigators", analystToken);
        assertEquals(200, res.statusCode);
        JsonArray array = gson.fromJson(res.body, JsonArray.class);
        assertTrue(array.size() >= 2);
        for (int i = 0; i < array.size(); i++) {
            JsonObject u = array.get(i).getAsJsonObject();
            String role = u.get("role").getAsString().toUpperCase();
            assertTrue("ADMIN".equals(role) || "ANALYST".equals(role));
            // Ensure passwords and salts are never returned
            assertFalse(u.has("password") && !u.get("password").getAsString().isEmpty());
            assertFalse(u.has("passwordHash") && !u.get("passwordHash").getAsString().isEmpty());
        }
    }

    // =========================================================================
    // HTTP CLIENT HELPERS
    // =========================================================================

    private static class HttpResponse {
        int statusCode;
        String body;
        HttpResponse(int statusCode, String body) {
            this.statusCode = statusCode;
            this.body = body;
        }
    }

    private static HttpResponse sendGet(String path, String token) throws Exception {
        URL url = new URL("http://localhost:" + port + path);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        if (token != null) {
            conn.setRequestProperty("Authorization", "Bearer " + token);
        }
        int code = conn.getResponseCode();
        InputStream is = (code >= 200 && code < 400) ? conn.getInputStream() : conn.getErrorStream();
        String body = is != null ? new String(is.readAllBytes(), StandardCharsets.UTF_8) : "";
        return new HttpResponse(code, body);
    }

    private static HttpResponse sendPost(String path, String jsonBody, String token) throws Exception {
        URL url = new URL("http://localhost:" + port + path);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/json");
        if (token != null) {
            conn.setRequestProperty("Authorization", "Bearer " + token);
        }
        try (OutputStream os = conn.getOutputStream()) {
            os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
        }
        int code = conn.getResponseCode();
        InputStream is = (code >= 200 && code < 400) ? conn.getInputStream() : conn.getErrorStream();
        String body = is != null ? new String(is.readAllBytes(), StandardCharsets.UTF_8) : "";
        return new HttpResponse(code, body);
    }
}
