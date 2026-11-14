package cybershield.service;

import cybershield.database.DatabaseManager;
import cybershield.model.User;
import cybershield.security.PasswordUtils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * UserService — Handles user credential verification, lookups, and authentication auditing.
 * Demonstrates: Secure authentication with salted SHA-256 verification, parameterized queries,
 * integration with AccessEvent, ActivityLog, and automated IntrusionDetectionService.
 */
public class UserService {

    private final AccessEventService accessEventService;
    private final ActivityLogService activityLogService;
    private final IntrusionDetectionService intrusionDetectionService;
    private final AccountLockoutService accountLockoutService;

    public UserService() {
        this.accessEventService = new AccessEventService();
        this.activityLogService = new ActivityLogService();
        this.intrusionDetectionService = new IntrusionDetectionService();
        this.accountLockoutService = new AccountLockoutService(this.activityLogService);
    }

    public UserService(AccessEventService accessEventService,
                       ActivityLogService activityLogService,
                       IntrusionDetectionService intrusionDetectionService) {
        this(accessEventService, activityLogService, intrusionDetectionService, new AccountLockoutService(activityLogService));
    }

    public UserService(AccessEventService accessEventService,
                       ActivityLogService activityLogService,
                       IntrusionDetectionService intrusionDetectionService,
                       AccountLockoutService accountLockoutService) {
        this.accessEventService = accessEventService;
        this.activityLogService = activityLogService;
        this.intrusionDetectionService = intrusionDetectionService;
        this.accountLockoutService = accountLockoutService;
    }

    public IntrusionDetectionService getIntrusionDetectionService() {
        return intrusionDetectionService;
    }

    public AccountLockoutService getAccountLockoutService() {
        return accountLockoutService;
    }

    /**
     * Backward-compatible authentication method defaulting client IP to local loopback.
     */
    public User authenticate(String username, String password, String source) {
        return authenticate(username, password, "127.0.0.1", source);
    }

    /**
     * Authenticates a user against stored salted hashes in SQLite.
     * Records telemetry in AccessEvent and ActivityLog.
     * On failure, invokes IntrusionDetectionService to monitor and detect brute-force attacks.
     *
     * @param username The entered username.
     * @param password The entered plaintext password (NEVER logged or stored).
     * @param clientIp The remote IP address of the client connection.
     * @param source The origin channel of the request ("WEB" or "DESKTOP").
     * @return The authenticated User object, or null if credentials are invalid.
     */
    public User authenticate(String username, String password, String clientIp, String source) {
        String cleanIp = (clientIp != null && !clientIp.trim().isEmpty()) ? clientIp.trim() : "127.0.0.1";
        if ("0:0:0:0:0:0:0:1".equals(cleanIp) || "::1".equals(cleanIp)) {
            cleanIp = "127.0.0.1";
        }
        String cleanSource = (source != null && !source.trim().isEmpty()) ? source.trim() : "CLIENT";
        String originLabel = cleanIp + " (" + cleanSource + ")";

        if (username == null || password == null || username.trim().isEmpty()) {
            String targetUser = username == null ? "UNKNOWN" : username.trim();
            accessEventService.recordEvent(targetUser, originLabel, "LOGIN_ATTEMPT_EMPTY", "FAILED");
            intrusionDetectionService.recordFailedLogin(cleanIp, targetUser);
            return null;
        }

        String trimmedUser = username.trim();

        // 1. Account Lock Check: evaluate before password verification
        if (accountLockoutService.isAccountLocked(trimmedUser)) {
            accessEventService.recordEvent(trimmedUser, originLabel, "LOGIN_FAILED_LOCKED", "FAILED");
            // Locked accounts reject authentication immediately. Do not increment failure counter (Rule TEST 4).
            return null;
        }

        String sql = "SELECT id, username, password_hash, salt, role, created_at, is_locked, locked_until, failed_attempt_count FROM users WHERE username = ?";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, trimmedUser);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    int id = rs.getInt("id");
                    String uname = rs.getString("username");
                    String storedHash = rs.getString("password_hash");
                    String salt = rs.getString("salt");
                    String role = rs.getString("role");
                    String createdAt = rs.getString("created_at");

                    // Verify using constant-time cryptographic check
                    boolean passwordMatches = PasswordUtils.verifyPassword(password, salt, storedHash);
                    if (passwordMatches) {
                        // Successful login resets consecutive failed attempts counter
                        accountLockoutService.resetFailedAttempts(uname);

                        User user = new User(id, uname, storedHash, salt, role, createdAt, 0, 0L, 0);
                        // Record success audit trail
                        accessEventService.recordEvent(uname, originLabel, "LOGIN_SUCCESS", "SUCCESS");
                        activityLogService.log(uname, "USER_LOGIN", "User logged in from " + originLabel);
                        return user;
                    }
                }
            }
        } catch (SQLException e) {
            System.err.println("[UserService] Database error during authentication: " + e.getMessage());
        }

        // Authentication failed: record in AccountLockoutService (increments counter & locks on 5th attempt)
        accountLockoutService.recordFailedAttempt(trimmedUser);

        // Log security event for unauthorized access tracking
        accessEventService.recordEvent(trimmedUser, originLabel, "LOGIN_FAILED", "FAILED");

        // Forward to IntrusionDetectionService for brute-force sliding-window tracking
        // Note: Password is NEVER passed or logged
        intrusionDetectionService.recordFailedLogin(cleanIp, trimmedUser);

        return null;
    }

    /**
     * Finds a user by their unique username.
     */
    public User findByUsername(String username) {
        if (username == null) return null;
        String sql = "SELECT id, username, password_hash, salt, role, created_at, is_locked, locked_until, failed_attempt_count FROM users WHERE username = ?";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, username.trim());
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return new User(
                        rs.getInt("id"),
                        rs.getString("username"),
                        rs.getString("password_hash"),
                        rs.getString("salt"),
                        rs.getString("role"),
                        rs.getString("created_at"),
                        rs.getInt("is_locked"),
                        rs.getLong("locked_until"),
                        rs.getInt("failed_attempt_count")
                    );
                }
            }
        } catch (SQLException e) {
            System.err.println("[UserService] Error finding user: " + e.getMessage());
        }
        return null;
    }

    /**
     * Alias for findByUsername to support standard naming conventions.
     */
    public User getUserByUsername(String username) {
        return findByUsername(username);
    }

    /**
     * Retrieves all active users authorized to act as investigators (roles: ADMIN and ANALYST).
     * Returns sanitized user objects with blanked passwords and salts for security.
     */
    public java.util.List<User> getAssignableInvestigators() {
        java.util.List<User> list = new java.util.ArrayList<>();
        String sql = "SELECT id, username, role, created_at FROM users WHERE UPPER(role) IN ('ADMIN', 'ANALYST') ORDER BY role ASC, username ASC";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {
            while (rs.next()) {
                list.add(new User(
                    rs.getInt("id"),
                    rs.getString("username"),
                    "", // scrubbed password hash
                    "", // scrubbed salt
                    rs.getString("role"),
                    rs.getString("created_at"),
                    0, 0L, 0
                ));
            }
        } catch (SQLException e) {
            System.err.println("[UserService] Error fetching assignable investigators: " + e.getMessage());
        }
        return list;
    }
}
