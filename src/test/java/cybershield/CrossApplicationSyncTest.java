package cybershield;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpServer;
import cybershield.database.DatabaseManager;
import cybershield.model.AccountLockStatus;
import cybershield.model.BlockedIp;
import cybershield.model.Incident;
import cybershield.model.InvestigationNote;
import cybershield.model.InvestigationSummary;
import cybershield.model.ThreatResponse;
import cybershield.server.ApiHandler;
import cybershield.service.IncidentService;
import cybershield.ui.ApiClient;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * CrossApplicationSyncTest — Phase F Verification Suite.
 * Validates cross-channel data synchronization between the Web REST API and
 * the Java Swing Desktop client (via ApiClient & shared persistence layer).
 *
 * Covers:
 * TEST 1: IP Blocking from Web -> Reflected in Swing Desktop
 * TEST 2: IP Unblocking from Desktop -> Reflected in Web REST
 * TEST 3: Investigation Note Added via Web -> Visible in Swing Desktop
 * TEST 4: Investigation Note Added via Desktop -> Visible in Web REST
 * TEST 5: Incident Resolution via Web -> Visible in Swing Desktop
 * TEST 6: Automated Threat Response Synchronization (Alert, Incident, IP Block, Threat Log)
 * TEST 7: Account Security Synchronization (Lockout state & remaining duration)
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class CrossApplicationSyncTest {

    private static HttpServer server;
    private static int port;
    private static String adminToken;
    private static String analystToken;
    private static final Gson gson = new Gson();
    private static ApiClient desktopClient;
    private static IncidentService incidentService;
    private static int sharedIncidentId;

    @BeforeAll
    public static void setUpClass() throws Exception {
        DatabaseManager.initialize();
        incidentService = new IncidentService();
        desktopClient = ApiClient.getInstance();

        // Start embedded test HTTP server on an ephemeral free port
        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/api", new ApiHandler());
        server.start();
        port = server.getAddress().getPort();

        // 1. Authenticate Web Session (Admin)
        JsonObject adminLogin = new JsonObject();
        adminLogin.addProperty("username", "admin");
        adminLogin.addProperty("password", "Admin@123");
        HttpResponse resAdmin = sendPost("/api/auth/login", adminLogin.toString(), null);
        assertEquals(200, resAdmin.statusCode);
        JsonObject adminJson = gson.fromJson(resAdmin.body, JsonObject.class);
        adminToken = adminJson.get("token").getAsString();
        assertNotNull(adminToken);

        // 2. Authenticate Web Session (Analyst)
        JsonObject analystLogin = new JsonObject();
        analystLogin.addProperty("username", "analyst");
        analystLogin.addProperty("password", "Analyst@123");
        HttpResponse resAnalyst = sendPost("/api/auth/login", analystLogin.toString(), null);
        assertEquals(200, resAnalyst.statusCode);
        JsonObject analystJson = gson.fromJson(resAnalyst.body, JsonObject.class);
        analystToken = analystJson.get("token").getAsString();
        assertNotNull(analystToken);

        // 3. Authenticate Desktop Swing Client
        desktopClient.login("admin", "Admin@123");
        assertTrue(desktopClient.isAuthenticated());
        assertTrue(desktopClient.isAdmin());

        // 4. Create a shared test incident for investigation synchronization
        Incident inc = new Incident("Cross-App Sync Verification Incident",
                "Shared case for testing real-time synchronization between Web SOC Console and Desktop GUI",
                "HIGH", "OPEN", "SYSTEM_SYNC_TEST");
        Incident created = incidentService.create(inc, "SYSTEM_SYNC_TEST");
        assertNotNull(created);
        sharedIncidentId = created.getId();
    }

    @AfterAll
    public static void tearDownClass() {
        if (server != null) {
            server.stop(0);
        }
        if (desktopClient != null) {
            desktopClient.logout();
        }
    }

    private static String dynamicBlockIp = "198.51.100." + (int)(10 + (Math.random() * 240));

    // =========================================================================
    // TEST 1: IP BLOCKING (Web -> Swing Desktop)
    // =========================================================================
    @Test
    @Order(1)
    public void test1_webBlocksIp_swingSeesBlocked() throws Exception {
        String testIp = dynamicBlockIp;

        // Step 1: Web SOC Console performs manual block via REST API
        JsonObject blockReq = new JsonObject();
        blockReq.addProperty("ipAddress", testIp);
        blockReq.addProperty("reason", "Web SOC Manual Block Sync Test");
        blockReq.addProperty("durationMinutes", 45);

        HttpResponse res = sendPost("/api/firewall/block", blockReq.toString(), adminToken);
        assertEquals(201, res.statusCode);

        // Step 2: Swing Desktop queries active blocked IPs via ApiClient
        List<BlockedIp> desktopBlocks = desktopClient.getBlockedIps("ACTIVE");
        assertNotNull(desktopBlocks);

        boolean foundInDesktop = false;
        for (BlockedIp b : desktopBlocks) {
            if (testIp.equals(b.getIpAddress()) && "ACTIVE".equalsIgnoreCase(b.getStatus())) {
                foundInDesktop = true;
                assertEquals("Web SOC Manual Block Sync Test", b.getReason());
                assertEquals("admin", b.getBlockedBy());
                break;
            }
        }
        assertTrue(foundInDesktop, "Swing Desktop client must reflect IP blocked via Web SOC Console");
    }

    // =========================================================================
    // TEST 2: IP UNBLOCKING (Swing Desktop -> Web)
    // =========================================================================
    @Test
    @Order(2)
    public void test2_swingUnblocksIp_webSeesUnblocked() throws Exception {
        String testIp = dynamicBlockIp;

        // Step 1: Swing Desktop client lifts the block via ApiClient
        boolean unblocked = desktopClient.unblockIp(testIp);
        assertTrue(unblocked, "Desktop client should successfully unblock active IP");

        // Step 2: Web SOC Console queries active blocked IPs via REST API
        HttpResponse res = sendGet("/api/firewall/blocked-ips?status=ACTIVE", adminToken);
        assertEquals(200, res.statusCode);
        JsonArray array = gson.fromJson(res.body, JsonArray.class);

        boolean stillActiveInWeb = false;
        for (int i = 0; i < array.size(); i++) {
            JsonObject obj = array.get(i).getAsJsonObject();
            if (testIp.equals(obj.get("ipAddress").getAsString())) {
                stillActiveInWeb = true;
                break;
            }
        }
        assertFalse(stillActiveInWeb, "Web REST API must confirm that IP unblocked via Desktop is no longer active");
    }

    // =========================================================================
    // TEST 3: INVESTIGATION NOTE (Web -> Swing Desktop)
    // =========================================================================
    @Test
    @Order(3)
    public void test3_webAddsInvestigationNote_swingSeesNote() throws Exception {
        // Step 1: Web SOC Analyst posts a forensic note with JSON evidence
        JsonObject noteReq = new JsonObject();
        noteReq.addProperty("notes", "Web Analyst identified malicious command injection payload.");
        noteReq.addProperty("evidenceData", "{\"cve\":\"CVE-2026-1144\",\"confidence\":\"HIGH\"}");

        HttpResponse res = sendPost("/api/incidents/" + sharedIncidentId + "/investigations", noteReq.toString(), analystToken);
        assertEquals(201, res.statusCode);

        // Step 2: Swing Desktop loads investigation notes via ApiClient
        List<InvestigationNote> notes = desktopClient.getInvestigationNotes(sharedIncidentId);
        assertNotNull(notes);
        assertFalse(notes.isEmpty());

        boolean noteFoundInDesktop = false;
        for (InvestigationNote n : notes) {
            if (n.getNotes().contains("Web Analyst identified malicious command injection payload")) {
                noteFoundInDesktop = true;
                assertEquals("analyst", n.getAnalystUsername());
                assertNotNull(n.getEvidenceData());
                assertTrue(n.getEvidenceData().contains("CVE-2026-1144"));
                break;
            }
        }
        assertTrue(noteFoundInDesktop, "Swing Desktop must see forensic note added via Web Console");
    }

    // =========================================================================
    // TEST 4: INVESTIGATION NOTE (Swing Desktop -> Web)
    // =========================================================================
    @Test
    @Order(4)
    public void test4_swingAddsInvestigationNote_webSeesNote() throws Exception {
        // Step 1: Swing Desktop Analyst/Admin posts note via ApiClient
        InvestigationNote added = desktopClient.addInvestigationNote(sharedIncidentId,
                "Desktop Engineer verified firewall egress quarantine.",
                "{\"quarantined_vlan\":40,\"switch\":\"CORE-SW-01\"}");
        assertNotNull(added);

        // Step 2: Web SOC Console queries notes via REST API
        HttpResponse res = sendGet("/api/incidents/" + sharedIncidentId + "/investigations", analystToken);
        assertEquals(200, res.statusCode);
        JsonArray array = gson.fromJson(res.body, JsonArray.class);

        boolean noteFoundInWeb = false;
        for (int i = 0; i < array.size(); i++) {
            JsonObject obj = array.get(i).getAsJsonObject();
            if (obj.get("notes").getAsString().contains("Desktop Engineer verified firewall egress quarantine")) {
                noteFoundInWeb = true;
                assertTrue(obj.get("evidenceData").getAsString().contains("CORE-SW-01"));
                break;
            }
        }
        assertTrue(noteFoundInWeb, "Web Console must see forensic note added via Desktop Client");
    }

    // =========================================================================
    // TEST 5: INCIDENT RESOLUTION (Web -> Swing Desktop)
    // =========================================================================
    @Test
    @Order(5)
    public void test5_webResolvesIncident_swingSeesResolved() throws Exception {
        // Step 1: Web Console sets root cause
        JsonObject rcReq = new JsonObject();
        rcReq.addProperty("category", "MALWARE");
        rcReq.addProperty("explanation", "Ransomware canary triggered on staging filesystem.");
        HttpResponse rcRes = sendPost("/api/incidents/" + sharedIncidentId + "/root-cause", rcReq.toString(), analystToken);
        assertEquals(200, rcRes.statusCode);

        // Step 2: Web Console resolves incident
        JsonObject resReq = new JsonObject();
        resReq.addProperty("resolutionSummary", "Threat neutralized, host reimaged, and firewall rule verified.");
        HttpResponse resolveRes = sendPost("/api/incidents/" + sharedIncidentId + "/resolve", resReq.toString(), analystToken);
        assertEquals(200, resolveRes.statusCode);

        // Step 3: Swing Desktop loads case summary via ApiClient
        InvestigationSummary summary = desktopClient.getInvestigationSummary(sharedIncidentId);
        assertNotNull(summary);
        assertEquals("RESOLVED", summary.getStatus(), "Swing Desktop must see incident status as RESOLVED");
        assertEquals("MALWARE", summary.getRootCauseCategory(), "Swing Desktop must see root cause category MALWARE");
        assertTrue(summary.getResolutionSummary().contains("Threat neutralized"), "Swing Desktop must see resolution summary");
    }

    // =========================================================================
    // TEST 6: AUTOMATED THREAT RESPONSE (IDS Trigger -> Both Synchronized)
    // =========================================================================
    @Test
    @Order(6)
    public void test6_automatedThreatResponse_bothFrontendsSynchronized() throws Exception {
        String attackerIp = "198.51.100." + (int)(20 + (Math.random() * 220));

        // Trigger 5 failed logins from attackerIp to activate automated response
        for (int i = 1; i <= 5; i++) {
            JsonObject badLogin = new JsonObject();
            badLogin.addProperty("username", "test_sync_victim");
            badLogin.addProperty("password", "WrongPass" + i);
            badLogin.addProperty("clientIp", attackerIp);
            sendPost("/api/auth/login", badLogin.toString(), null);
        }

        // Web Check: Query threat responses for this IP
        HttpResponse webRes = sendGet("/api/threat-responses?targetIp=" + attackerIp, adminToken);
        assertEquals(200, webRes.statusCode);
        JsonArray webArray = gson.fromJson(webRes.body, JsonArray.class);
        assertTrue(webArray.size() >= 1, "Web must report automated threat response for attacker IP");
        JsonObject webAction = webArray.get(0).getAsJsonObject();
        assertEquals("EXECUTED", webAction.get("status").getAsString());

        // Desktop Check: Query threat responses via ApiClient
        List<ThreatResponse> desktopResponses = desktopClient.getThreatResponses(null, attackerIp, null);
        assertNotNull(desktopResponses);
        assertFalse(desktopResponses.isEmpty(), "Desktop must report automated threat response for attacker IP");
        ThreatResponse desktopAction = desktopResponses.get(0);
        assertEquals("EXECUTED", desktopAction.getStatus());
        assertEquals("AUTO_BLOCK_IP", desktopAction.getActionTaken());

        // Check active firewall block in both
        HttpResponse webBlock = sendGet("/api/firewall/blocked-ips?status=ACTIVE", adminToken);
        assertTrue(webBlock.body.contains(attackerIp), "Web firewall must show attacker IP as active blocked");

        List<BlockedIp> desktopBlocks = desktopClient.getBlockedIps("ACTIVE");
        boolean blockedInDesktop = desktopBlocks.stream().anyMatch(b -> attackerIp.equals(b.getIpAddress()));
        assertTrue(blockedInDesktop, "Desktop firewall must show attacker IP as active blocked");
    }

    // =========================================================================
    // TEST 7: ACCOUNT SECURITY (Lockout -> Both Synchronized)
    // =========================================================================
    @Test
    @Order(7)
    public void test7_accountLockout_bothFrontendsSynchronized() throws Exception {
        String targetUser = "standard_user";

        // Unlock first to start clean
        JsonObject unlockReq = new JsonObject();
        unlockReq.addProperty("username", targetUser);
        sendPost("/api/auth/unlock", unlockReq.toString(), adminToken);

        // Trigger 5 consecutive failed logins for targetUser
        for (int i = 1; i <= 5; i++) {
            JsonObject badAuth = new JsonObject();
            badAuth.addProperty("username", targetUser);
            badAuth.addProperty("password", "BadSecret" + i);
            sendPost("/api/auth/login", badAuth.toString(), null);
        }

        // Web Check: Query locked accounts via REST API
        HttpResponse webRes = sendGet("/api/auth/locked-accounts", adminToken);
        assertEquals(200, webRes.statusCode);
        JsonArray webArray = gson.fromJson(webRes.body, JsonArray.class);
        boolean lockedInWeb = false;
        for (int i = 0; i < webArray.size(); i++) {
            JsonObject acc = webArray.get(i).getAsJsonObject();
            if (targetUser.equals(acc.get("username").getAsString()) && acc.get("locked").getAsBoolean()) {
                lockedInWeb = true;
                assertTrue(acc.get("remainingSeconds").getAsLong() > 0);
                break;
            }
        }
        assertTrue(lockedInWeb, "Web must report target user as locked");

        // Desktop Check: Query locked accounts via ApiClient
        List<AccountLockStatus> desktopAccounts = desktopClient.getLockedAccounts();
        assertNotNull(desktopAccounts);
        boolean lockedInDesktop = false;
        for (AccountLockStatus acc : desktopAccounts) {
            if (targetUser.equals(acc.getUsername()) && acc.isLocked()) {
                lockedInDesktop = true;
                assertTrue(acc.getRemainingSeconds() > 0);
                break;
            }
        }
        assertTrue(lockedInDesktop, "Desktop must report target user as locked");

        // Clean up: unlock target user
        desktopClient.unlockAccount(targetUser);
        assertFalse(desktopClient.getLockedAccounts().stream().anyMatch(a -> targetUser.equals(a.getUsername()) && a.isLocked()));
    }

    // =========================================================================
    // HTTP CLIENT HELPERS
    // =========================================================================
    private static HttpResponse sendGet(String path, String token) throws Exception {
        URL url = new URL("http://localhost:" + port + path);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        if (token != null) {
            conn.setRequestProperty("Authorization", "Bearer " + token);
        }
        return readResponse(conn);
    }

    private static HttpResponse sendPost(String path, String jsonBody, String token) throws Exception {
        URL url = new URL("http://localhost:" + port + path);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        if (token != null) {
            conn.setRequestProperty("Authorization", "Bearer " + token);
        }
        conn.setDoOutput(true);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
        }
        return readResponse(conn);
    }

    private static HttpResponse readResponse(HttpURLConnection conn) throws Exception {
        int code = conn.getResponseCode();
        InputStream is = (code >= 200 && code < 400) ? conn.getInputStream() : conn.getErrorStream();
        StringBuilder sb = new StringBuilder();
        if (is != null) {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line);
                }
            }
        }
        return new HttpResponse(code, sb.toString());
    }

    private static class HttpResponse {
        final int statusCode;
        final String body;

        HttpResponse(int statusCode, String body) {
            this.statusCode = statusCode;
            this.body = body;
        }
    }
}
