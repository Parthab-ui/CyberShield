package cybershield;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpServer;
import cybershield.database.DatabaseManager;
import cybershield.server.ApiHandler;
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
 * DataHygieneTest — Phase 6 Verification Suite.
 * Asserts that sensitive credential fields (passwordHash, salt, password)
 * are NEVER included in API responses for login, /me, or /investigators endpoints.
 */
public class DataHygieneTest {

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
    @DisplayName("Test 1: Login response does not contain passwordHash, salt, or password fields")
    public void testLoginResponseNoCredentials() throws Exception {
        JsonObject login = new JsonObject();
        login.addProperty("username", "admin");
        login.addProperty("password", "Admin@123");
        HttpResponse res = send("POST", "/api/auth/login", login.toString(), null, 200);
        assertSensitiveFieldsAbsent(res.body, "POST /api/auth/login");
    }

    @Test
    @DisplayName("Test 2: GET /api/auth/me response does not contain sensitive credential fields")
    public void testMeResponseNoCredentials() throws Exception {
        HttpResponse res = send("GET", "/api/auth/me", null, adminToken, 200);
        assertSensitiveFieldsAbsent(res.body, "GET /api/auth/me");
    }

    @Test
    @DisplayName("Test 3: GET /api/investigators response does not contain sensitive credential fields")
    public void testInvestigatorsResponseNoCredentials() throws Exception {
        HttpResponse res = send("GET", "/api/investigators", null, adminToken, 200);
        assertSensitiveFieldsAbsent(res.body, "GET /api/investigators");
    }

    private void assertSensitiveFieldsAbsent(String body, String endpoint) {
        String lower = body.toLowerCase();
        assertFalse(lower.contains("passwordhash"),
                endpoint + " response must not contain 'passwordHash'");
        assertFalse(lower.contains("password_hash"),
                endpoint + " response must not contain 'password_hash'");
        assertFalse(lower.contains("\"salt\""),
                endpoint + " response must not contain 'salt' field");
        assertFalse(lower.matches(".*\"password\"\\s*:.*"),
                endpoint + " response must not contain raw 'password' field");
    }

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

    private record HttpResponse(int statusCode, String body) {}
}
