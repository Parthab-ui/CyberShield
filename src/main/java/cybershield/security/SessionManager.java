package cybershield.security;

import cybershield.model.User;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * SessionManager — Manages in-memory authentication sessions and bearer tokens.
 * Features:
 * - Cryptographically secure 32-byte URL-safe Base64 session tokens (SecureRandom)
 * - 30-minute idle session timeout
 * - 8-hour maximum absolute session lifetime
 * - Periodic background cleanup of expired sessions
 * - Targeted session invalidation on logout and administrative account unlock
 */
public class SessionManager {

    public static final Duration IDLE_TIMEOUT = Duration.ofMinutes(30);
    public static final Duration ABSOLUTE_LIFETIME = Duration.ofHours(8);

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final Map<String, SessionData> ACTIVE_SESSIONS = new ConcurrentHashMap<>();

    // Background daemon executor for periodic expired session cleanup
    private static final ScheduledExecutorService CLEANUP_EXECUTOR;

    static {
        CLEANUP_EXECUTOR = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "SessionManager-Cleanup");
            t.setDaemon(true);
            return t;
        });
        CLEANUP_EXECUTOR.scheduleAtFixedRate(() -> purgeExpiredSessions(Instant.now()), 10, 10, TimeUnit.MINUTES);
    }

    /**
     * SessionData — Internal record holding session information, timestamps, and expiry logic.
     */
    public static class SessionData {
        private final String token;
        private final User user;
        private final Instant createdAt;
        private Instant lastAccessedAt;

        public SessionData(String token, User user) {
            this(token, user, Instant.now());
        }

        public SessionData(String token, User user, Instant createdAt) {
            this.token = token;
            this.user = user;
            this.createdAt = createdAt;
            this.lastAccessedAt = createdAt;
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

        public void touch(Instant now) {
            this.lastAccessedAt = now;
        }

        /**
         * Checks whether the session has expired due to idle timeout or absolute lifetime.
         */
        public boolean isExpired(Instant now) {
            boolean idleExpired = now.isAfter(lastAccessedAt.plus(IDLE_TIMEOUT));
            boolean absoluteExpired = now.isAfter(createdAt.plus(ABSOLUTE_LIFETIME));
            return idleExpired || absoluteExpired;
        }
    }

    private SessionManager() {
        // Prevent direct instantiation
    }

    /**
     * Creates a new authenticated session token for the given user.
     * Generates a 32-byte cryptographically secure URL-safe Base64 token.
     *
     * @param user The authenticated user object.
     * @return The 32-byte random URL-safe Base64 token string.
     */
    public static String createSession(User user) {
        byte[] tokenBytes = new byte[32];
        SECURE_RANDOM.nextBytes(tokenBytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
        ACTIVE_SESSIONS.put(token, new SessionData(token, user));
        return token;
    }

    /**
     * Testing hook: allows creating a session with explicit timestamps.
     */
    public static String createSessionForTesting(User user, Instant createdAt, Instant lastAccessedAt) {
        byte[] tokenBytes = new byte[32];
        SECURE_RANDOM.nextBytes(tokenBytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
        SessionData data = new SessionData(token, user, createdAt);
        data.touch(lastAccessedAt);
        ACTIVE_SESSIONS.put(token, data);
        return token;
    }

    /**
     * Validates a token, ensures it has not expired, and updates its last accessed time.
     *
     * @param token The bearer session token.
     * @return The authenticated User, or null if expired or not found.
     */
    public static User validateSession(String token) {
        return validateSession(token, Instant.now());
    }

    /**
     * Validates session against a specified time instant (supports testing).
     */
    public static User validateSession(String token, Instant now) {
        if (token == null || token.trim().isEmpty()) {
            return null;
        }
        String cleanToken = token.startsWith("Bearer ") ? token.substring(7).trim() : token.trim();
        SessionData data = ACTIVE_SESSIONS.get(cleanToken);
        if (data == null) {
            return null;
        }

        // Check idle and absolute expiration
        if (data.isExpired(now)) {
            ACTIVE_SESSIONS.remove(cleanToken);
            return null;
        }

        data.touch(now);
        return data.getUser();
    }

    /**
     * Invalidates and removes an active session token upon logout.
     *
     * @param token The token to invalidate.
     */
    public static void invalidateSession(String token) {
        if (token != null) {
            String cleanToken = token.startsWith("Bearer ") ? token.substring(7).trim() : token.trim();
            ACTIVE_SESSIONS.remove(cleanToken);
        }
    }

    /**
     * Invalidates all active sessions belonging to the given username.
     * Invoked when an administrator unlocks or resets a user account.
     *
     * @param username The username whose sessions must be revoked.
     * @return The number of revoked sessions.
     */
    public static int invalidateSessionsForUser(String username) {
        if (username == null || username.trim().isEmpty()) {
            return 0;
        }
        String cleanUser = username.trim();
        int count = 0;
        for (Map.Entry<String, SessionData> entry : ACTIVE_SESSIONS.entrySet()) {
            User u = entry.getValue().getUser();
            if (u != null && cleanUser.equalsIgnoreCase(u.getUsername())) {
                if (ACTIVE_SESSIONS.remove(entry.getKey()) != null) {
                    count++;
                }
            }
        }
        return count;
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
     * Purges all expired sessions from memory.
     *
     * @return The number of purged sessions.
     */
    public static int purgeExpiredSessions() {
        return purgeExpiredSessions(Instant.now());
    }

    /**
     * Purges expired sessions based on the provided reference time instant.
     */
    public static int purgeExpiredSessions(Instant now) {
        int count = 0;
        for (Map.Entry<String, SessionData> entry : ACTIVE_SESSIONS.entrySet()) {
            if (entry.getValue().isExpired(now)) {
                if (ACTIVE_SESSIONS.remove(entry.getKey()) != null) {
                    count++;
                }
            }
        }
        return count;
    }

    /**
     * Returns the count of currently active sessions.
     */
    public static int getActiveSessionCount() {
        return ACTIVE_SESSIONS.size();
    }

    /**
     * Clears all active sessions (e.g., during testing or system reset).
     */
    public static void clearAllSessions() {
        ACTIVE_SESSIONS.clear();
    }
}
