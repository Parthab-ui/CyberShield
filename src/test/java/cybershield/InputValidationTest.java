package cybershield;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpServer;
import cybershield.database.DatabaseManager;
import cybershield.server.ApiHandler;
import cybershield.server.StaticFileHandler;
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
 * InputValidationTest — Phase 5 Verification Suite.
 * Asserts that:
 * 1. Incident title > 200 chars → 400.
 * 2. Incident with invalid severity → 400.
 * 3. Incident with invalid status → 400.
 * 4. StaticFileHandler blocks path traversal (canonical path check).
 * 5. StaticFileHandler blocks disallowed file extensions.
 */
public class InputValidationTest {

    private static HttpServer server;
    private static int port;
    private static String adminToken;
    private static final Gson gson = new Gson();

    @BeforeAll
    public static void setUp() throws Exception {
        DatabaseManager.initialize();

        server = HttpServer.create(new InetSocketAddress(0), 0);
        ApiHandler handler = new ApiHandler();
        server.createContext("/api", handler);
        server.createContext("/", new StaticFileHandler("web"));
        server.start();
        port = server.getAddress().getPort();
        handler.addAllowedOrigin(port);

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
    @DisplayName("Test 1: Incident title > 200 characters returns HTTP 400")
    public void testTitleTooLong() throws Exception {
        JsonObject body = new JsonObject();
        body.addProperty("title", "A".repeat(201));
        body.addProperty("description", "test");
        body.addProperty("severity", "LOW");
        body.addProperty("status", "OPEN");
        HttpResponse res = send("POST", "/api/incidents", body.toString(), adminToken, -1);
        assertEquals(400, res.statusCode, "Title > 200 chars must return 400");
    }

    @Test
    @DisplayName("Test 2: Incident with invalid severity returns HTTP 400")
    public void testInvalidSeverity() throws Exception {
        JsonObject body = new JsonObject();
        body.addProperty("title", "Valid title");
        body.addProperty("severity", "EXTREME");
        body.addProperty("status", "OPEN");
        HttpResponse res = send("POST", "/api/incidents", body.toString(), adminToken, -1);
        assertEquals(400, res.statusCode, "Invalid severity must return 400");
    }

    @Test
    @DisplayName("Test 3: Incident with invalid status returns HTTP 400")
    public void testInvalidStatus() throws Exception {
        JsonObject body = new JsonObject();
        body.addProperty("title", "Valid title");
        body.addProperty("severity", "LOW");
        body.addProperty("status", "PENDING");
        HttpResponse res = send("POST", "/api/incidents", body.toString(), adminToken, -1);
        assertEquals(400, res.statusCode, "Invalid status must return 400");
    }

    @Test
    @DisplayName("Test 4: Path traversal attempt returns 404 (not file contents)")
    public void testPathTraversalBlocked() throws Exception {
        HttpResponse res = sendRaw("/../../pom.xml");
        assertTrue(res.statusCode == 404 || res.statusCode == 200,
                "Path traversal must return 404 or SPA fallback, not 403/500");
        assertFalse(res.body.contains("<modelVersion>"),
                "Path traversal response must not expose pom.xml contents");
    }

    @Test
    @DisplayName("Test 5: Disallowed file extension returns 404")
    public void testDisallowedExtensionBlocked() throws Exception {
        HttpResponse res = sendRaw("/ApiHandler.java");
        assertTrue(res.statusCode == 404 || res.statusCode == 200,
                "Disallowed extension must return 404 or SPA fallback");
        assertFalse(res.body.contains("package cybershield"),
                "Disallowed extension response must not expose Java source");
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static HttpResponse send(String method, String path, String body, String token, int expectedStatus)
            throws Exception {
        URL url = new URL("http://localhost:" + port + path);
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

        if (expectedStatus != -1) {
            assertEquals(expectedStatus, status,
                    "Expected HTTP " + expectedStatus + " from " + method + " " + path + ". Body: " + responseBody);
        }
        return new HttpResponse(status, responseBody);
    }

    private static HttpResponse sendRaw(String path) throws Exception {
        URL url = new URL("http://localhost:" + port + path);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        int status = conn.getResponseCode();
        InputStream is = (status >= 200 && status < 300) ? conn.getInputStream() : conn.getErrorStream();
        String body = (is != null) ? new String(is.readAllBytes(), StandardCharsets.UTF_8) : "";
        return new HttpResponse(status, body);
    }

    private record HttpResponse(int statusCode, String body) {}
}
