package cybershield;

import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpServer;
import cybershield.database.DatabaseManager;
import cybershield.model.User;
import cybershield.security.SessionManager;
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
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * SessionManagerTest — Validates session security rules:
 * - 32-byte URL-safe Base64 token format
 * - 30-minute idle expiration
 * - 8-hour absolute expiration
 * - Rejection of ?token= query parameters
 * - Invalidation on logout and account unlock
 */
public class SessionManagerTest {

    private static HttpServer server;
    private static int port;

    @BeforeAll
    public static void setUp() throws Exception {
        DatabaseManager.initialize();
        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/api", new ApiHandler());
        server.start();
        port = server.getAddress().getPort();
    }

    @AfterAll
    public static void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("Test 1: Token format is cryptographically secure 32-byte URL-safe Base64")
    public void testTokenFormat() {
        User testUser = new User(101, "tokentest", "hash", "salt", "ANALYST", "now");
        String token = SessionManager.createSession(testUser);

        assertNotNull(token);
        // Base64URL without padding for 32 bytes produces exactly 43 characters
        assertEquals(43, token.length(), "32 bytes base64url unpadded should be 43 characters");
        // Verify valid Base64URL characters
        assertDoesNotThrow(() -> Base64.getUrlDecoder().decode(token));

        User retrieved = SessionManager.validateSession(token);
        assertNotNull(retrieved);
        assertEquals("tokentest", retrieved.getUsername());
    }

    @Test
    @DisplayName("Test 2: Idle timeout (30 minutes) expires inactive sessions")
    public void testIdleExpiry() {
        User testUser = new User(102, "idletest", "hash", "salt", "ANALYST", "now");
        Instant now = Instant.now();
        // Created 1 hour ago, last accessed 31 minutes ago (> 30 min idle limit)
        Instant created = now.minus(Duration.ofMinutes(60));
        Instant lastAccessed = now.minus(Duration.ofMinutes(31));

        String token = SessionManager.createSessionForTesting(testUser, created, lastAccessed);

        // Validation against current instant 'now' must fail due to idle timeout
        User validated = SessionManager.validateSession(token, now);
        assertNull(validated, "Session must expire after 30 minutes of inactivity");
    }

    @Test
    @DisplayName("Test 3: Absolute lifetime (8 hours) expires sessions even if active")
    public void testAbsoluteExpiry() {
        User testUser = new User(103, "absolutetest", "hash", "salt", "ADMIN", "now");
        Instant now = Instant.now();
        // Created 8 hours and 5 minutes ago, but accessed 5 minutes ago (idle ok, absolute exceeded)
        Instant created = now.minus(Duration.ofHours(8).plusMinutes(5));
        Instant lastAccessed = now.minus(Duration.ofMinutes(5));

        String token = SessionManager.createSessionForTesting(testUser, created, lastAccessed);

        // Validation against 'now' must fail due to absolute 8h lifetime
        User validated = SessionManager.validateSession(token, now);
        assertNull(validated, "Session must expire after 8 hours absolute lifetime regardless of activity");
    }

    @Test
    @DisplayName("Test 4: Query parameter ?token= is strictly rejected, only Authorization: Bearer is accepted")
    public void testQueryTokenRejected() throws Exception {
        User testUser = new User(104, "querytest", "hash", "salt", "ADMIN", "now");
        String token = SessionManager.createSession(testUser);

        // 1. Attempt using query parameter: /api/auth/me?token=...
        URL queryUrl = new URL("http://localhost:" + port + "/api/auth/me?token=" + token);
        HttpURLConnection connQuery = (HttpURLConnection) queryUrl.openConnection();
        connQuery.setRequestMethod("GET");
        assertEquals(401, connQuery.getResponseCode(), "Query parameter token must be rejected with HTTP 401");

        // 2. Attempt using Authorization header: Authorization: Bearer ...
        URL headerUrl = new URL("http://localhost:" + port + "/api/auth/me");
        HttpURLConnection connHeader = (HttpURLConnection) headerUrl.openConnection();
        connHeader.setRequestMethod("GET");
        connHeader.setRequestProperty("Authorization", "Bearer " + token);
        assertEquals(200, connHeader.getResponseCode(), "Authorization: Bearer header must succeed with HTTP 200");
    }

    @Test
    @DisplayName("Test 5: Explicit logout invalidates active session")
    public void testLogoutInvalidates() {
        User testUser = new User(105, "logouttest", "hash", "salt", "ANALYST", "now");
        String token = SessionManager.createSession(testUser);

        assertNotNull(SessionManager.validateSession(token));

        SessionManager.invalidateSession(token);
        assertNull(SessionManager.validateSession(token), "Session must be null after logout invalidation");
    }

    @Test
    @DisplayName("Test 6: Invalidate all sessions of a user on account unlock")
    public void testInvalidateSessionsForUser() {
        User user1 = new User(106, "multiuser", "hash", "salt", "ANALYST", "now");
        User user2 = new User(107, "otheruser", "hash", "salt", "ANALYST", "now");

        String token1 = SessionManager.createSession(user1);
        String token2 = SessionManager.createSession(user1); // second device
        String tokenOther = SessionManager.createSession(user2);

        int invalidated = SessionManager.invalidateSessionsForUser("multiuser");
        assertEquals(2, invalidated, "Both sessions for multiuser must be invalidated");

        assertNull(SessionManager.validateSession(token1));
        assertNull(SessionManager.validateSession(token2));
        assertNotNull(SessionManager.validateSession(tokenOther), "Other user's session must remain valid");
    }
}
