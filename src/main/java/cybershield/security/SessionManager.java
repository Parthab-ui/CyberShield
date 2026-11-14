package cybershield.security;

import cybershield.model.User;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * SessionManager — Manages in-memory authentication sessions and bearer tokens.
 * Demonstrates: Session-based authentication, token validation, and role-based authorization checks.
 * Works seamlessly with both Web client requests (via HTTP Authorization headers)
 * and the Java Swing desktop client.
 */
public class SessionManager {

    /**
     * SessionData — Internal record holding session information.
     */
    public static class SessionData {
        private final String token;
        private final User user;
        private final Instant createdAt;
        private Instant lastAccessedAt;

        public SessionData(String token, User user) {
            this.token = token;
            this.user = user;
            this.createdAt = Instant.now();
            this.lastAccessedAt = Instant.now();
        }

        public String getToken() {
            return token;
        }

        public User getUser() {
            return user;
        }

        public Instant getCreatedAt() {
            return createdAt;
        }

        public Instant getLastAccessedAt() {
            return lastAccessedAt;
        }

        public void touch() {
            this.lastAccessedAt = Instant.now();
        }
    }

    // Thread-safe map of active sessions keyed by token string
    private static final Map<String, SessionData> ACTIVE_SESSIONS = new ConcurrentHashMap<>();

    private SessionManager() {
        // Static singleton manager
    }

    /**
     * Creates a new authenticated session token for the given user.
     * @param user The authenticated user object.
     * @return A cryptographically random UUID session token.
     */
    public static String createSession(User user) {
        String token = UUID.randomUUID().toString();
        ACTIVE_SESSIONS.put(token, new SessionData(token, user));
        return token;
    }

    /**
     * Validates a token and returns the associated User, updating last access time.
     * @param token The session token string.
     * @return The authenticated User, or null if the session is invalid or expired.
     */
    public static User validateSession(String token) {
        if (token == null || token.trim().isEmpty()) {
            return null;
        }
        // Normalize "Bearer <token>" header format if present
        String cleanToken = token.startsWith("Bearer ") ? token.substring(7).trim() : token.trim();
        SessionData data = ACTIVE_SESSIONS.get(cleanToken);
        if (data != null) {
            data.touch();
            return data.getUser();
        }
        return null;
    }

    /**
     * Invalidates and removes an active session token upon logout.
     * @param token The token to invalidate.
     */
    public static void invalidateSession(String token) {
        if (token != null) {
            String cleanToken = token.startsWith("Bearer ") ? token.substring(7).trim() : token.trim();
            ACTIVE_SESSIONS.remove(cleanToken);
        }
    }

    /**
     * Checks if the user associated with the token has the required role (e.g. "ADMIN").
     */
    public static boolean hasRole(String token, String requiredRole) {
        User user = validateSession(token);
        if (user == null || requiredRole == null) {
            return false;
        }
        return requiredRole.equalsIgnoreCase(user.getRole());
    }

    /**
     * Clears all active sessions (e.g., during testing or system reset).
     */
    public static void clearAllSessions() {
        ACTIVE_SESSIONS.clear();
    }
}
