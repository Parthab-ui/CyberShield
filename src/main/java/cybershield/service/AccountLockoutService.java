package cybershield.service;

import cybershield.database.DatabaseManager;
import cybershield.model.AccountLockStatus;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * AccountLockoutService — Core Credential Security & Account Lockout Engine for Review 3.
 * Enforces temporary account locking after repeated consecutive failed authentication attempts,
 * protecting against password guessing and credential stuffing attacks.
 *
 * Security Policies:
 * - MAX_FAILED_ATTEMPTS = 5 consecutive failures per existing user account.
 * - DEFAULT_LOCK_DURATION_MS = 15 minutes (900,000 ms).
 * - Independent of IP-based Intrusion Detection sliding windows.
 * - Automatic lazy lock expiration on status checks and login evaluations.
 * - Thread-safe and transaction-managed SQLite updates.
 */
public class AccountLockoutService {

    public static final int MAX_FAILED_ATTEMPTS = 5;
    public static final long DEFAULT_LOCK_DURATION_MS = 15 * 60 * 1000L; // 15 minutes

    private final ActivityLogService activityLogService;

    public AccountLockoutService() {
        this(new ActivityLogService());
    }

    public AccountLockoutService(ActivityLogService activityLogService) {
        this.activityLogService = activityLogService;
    }

    /**
     * Records a failed authentication attempt against a user account.
     * Increments the consecutive failure counter. If threshold is reached (5 attempts),
     * locks the account for 15 minutes and records an audit log.
     *
     * @param username The target username.
     * @return Updated AccountLockStatus, or safe default if user does not exist.
     */
    public synchronized AccountLockStatus recordFailedAttempt(String username) {
        if (username == null || username.trim().isEmpty()) {
            return new AccountLockStatus("", false, 0, 0L, 0L);
        }
        String cleanUser = username.trim();

        String selectSql = "SELECT is_locked, locked_until, failed_attempt_count FROM users WHERE username = ?";
        try (Connection conn = DatabaseManager.getConnection()) {
            int currentIsLocked = 0;
            long currentLockedUntil = 0L;
            int currentAttempts = 0;
            boolean userFound = false;

            try (PreparedStatement pstmt = conn.prepareStatement(selectSql)) {
                pstmt.setString(1, cleanUser);
                try (ResultSet rs = pstmt.executeQuery()) {
                    if (rs.next()) {
                        userFound = true;
                        currentIsLocked = rs.getInt("is_locked");
                        currentLockedUntil = rs.getLong("locked_until");
                        currentAttempts = rs.getInt("failed_attempt_count");
                    }
                }
            }

            // Unknown usernames: handle safely without database errors or fake account creation
            if (!userFound) {
                return new AccountLockStatus(cleanUser, false, 0, 0L, 0L);
            }

            long now = System.currentTimeMillis();

            // Check if account is currently locked
            if (currentIsLocked == 1) {
                if (currentLockedUntil > 0 && now >= currentLockedUntil) {
                    // Lock has expired: auto-unlock and reset state
                    autoUnlockAccount(conn, cleanUser);
                    currentIsLocked = 0;
                    currentLockedUntil = 0L;
                    currentAttempts = 0;
                } else {
                    // Still actively locked: reject without incrementing the counter (Rule TEST 4)
                    long remainingSec = currentLockedUntil > 0 ? Math.max(0, (currentLockedUntil - now) / 1000) : 0;
                    return new AccountLockStatus(cleanUser, true, currentAttempts, currentLockedUntil, remainingSec);
                }
            }

            int newAttempts = currentAttempts + 1;
            if (newAttempts >= MAX_FAILED_ATTEMPTS) {
                // Threshold reached: lock account for 15 minutes
                long lockExpiresAt = now + DEFAULT_LOCK_DURATION_MS;
                String lockSql = "UPDATE users SET failed_attempt_count = ?, is_locked = 1, locked_until = ? WHERE username = ?";
                try (PreparedStatement updateStmt = conn.prepareStatement(lockSql)) {
                    updateStmt.setInt(1, newAttempts);
                    updateStmt.setLong(2, lockExpiresAt);
                    updateStmt.setString(3, cleanUser);
                    updateStmt.executeUpdate();
                }

                activityLogService.log(cleanUser, "ACCOUNT_LOCKED",
                        "Account temporarily locked due to " + newAttempts + " consecutive failed login attempts. Lock duration: 15 minutes.");

                long remainingSec = DEFAULT_LOCK_DURATION_MS / 1000;
                return new AccountLockStatus(cleanUser, true, newAttempts, lockExpiresAt, remainingSec);
            } else {
                // Increment counter only
                String incSql = "UPDATE users SET failed_attempt_count = ? WHERE username = ?";
                try (PreparedStatement updateStmt = conn.prepareStatement(incSql)) {
                    updateStmt.setInt(1, newAttempts);
                    updateStmt.setString(2, cleanUser);
                    updateStmt.executeUpdate();
                }
                return new AccountLockStatus(cleanUser, false, newAttempts, 0L, 0L);
            }
        } catch (SQLException e) {
            System.err.println("[AccountLockoutService] Database error recording failed attempt: " + e.getMessage());
            return new AccountLockStatus(cleanUser, false, 0, 0L, 0L);
        }
    }

    /**
     * Checks if a user account is actively locked.
     * If a temporary lock has expired, automatically transitions the account back to unlocked
     * and resets the failure counter (lazy expiration).
     *
     * @param username The username to check.
     * @return true if the account is currently locked, false otherwise.
     */
    public synchronized boolean isAccountLocked(String username) {
        if (username == null || username.trim().isEmpty()) {
            return false;
        }
        String cleanUser = username.trim();

        String sql = "SELECT is_locked, locked_until FROM users WHERE username = ?";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, cleanUser);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    int isLocked = rs.getInt("is_locked");
                    long lockedUntil = rs.getLong("locked_until");

                    if (isLocked == 1) {
                        long now = System.currentTimeMillis();
                        if (lockedUntil > 0 && now >= lockedUntil) {
                            // Temporary lock expired: perform automatic unlock
                            autoUnlockAccount(conn, cleanUser);
                            return false;
                        }
                        return true;
                    }
                }
            }
        } catch (SQLException e) {
            System.err.println("[AccountLockoutService] Database error checking account lock: " + e.getMessage());
        }
        return false;
    }

    /**
     * Resets the consecutive failed attempt counter to 0 upon successful authentication.
     * Preserves security audit logs and historical failed login records in failed_logins.
     *
     * @param username The username that successfully authenticated.
     */
    public synchronized void resetFailedAttempts(String username) {
        if (username == null || username.trim().isEmpty()) {
            return;
        }
        String cleanUser = username.trim();
        String sql = "UPDATE users SET failed_attempt_count = 0 WHERE username = ? AND is_locked = 0";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, cleanUser);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[AccountLockoutService] Database error resetting failed attempts: " + e.getMessage());
        }
    }

    /**
     * Manually unlocks an account by an authorized administrator.
     * Clears is_locked, resets locked_until and failed_attempt_count, and records an audit log.
     *
     * @param username The account to unlock.
     * @param unlockedBy The administrator performing the unlock.
     * @return true if user account was found and unlocked, false otherwise.
     */
    public synchronized boolean unlockAccount(String username, String unlockedBy) {
        if (username == null || username.trim().isEmpty()) {
            return false;
        }
        String cleanUser = username.trim();
        String operator = (unlockedBy != null && !unlockedBy.trim().isEmpty()) ? unlockedBy.trim() : "ADMIN";

        String sql = "UPDATE users SET is_locked = 0, locked_until = 0, failed_attempt_count = 0 WHERE username = ?";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, cleanUser);
            int rows = pstmt.executeUpdate();
            if (rows > 0) {
                activityLogService.log(operator, "ACCOUNT_UNLOCKED",
                        "Account manually unlocked for user: " + cleanUser);
                return true;
            }
        } catch (SQLException e) {
            System.err.println("[AccountLockoutService] Database error unlocking account: " + e.getMessage());
        }
        return false;
    }

    /**
     * Retrieves the current security and lockout state for an account without exposing
     * password hashes, salts, or sensitive user details.
     *
     * @param username The username to inspect.
     * @return AccountLockStatus details.
     */
    public synchronized AccountLockStatus getAccountLockStatus(String username) {
        if (username == null || username.trim().isEmpty()) {
            return new AccountLockStatus("", false, 0, 0L, 0L);
        }
        String cleanUser = username.trim();

        String sql = "SELECT is_locked, locked_until, failed_attempt_count FROM users WHERE username = ?";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, cleanUser);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    int isLocked = rs.getInt("is_locked");
                    long lockedUntil = rs.getLong("locked_until");
                    int attempts = rs.getInt("failed_attempt_count");

                    long now = System.currentTimeMillis();
                    if (isLocked == 1) {
                        if (lockedUntil > 0 && now >= lockedUntil) {
                            // Lock expired: auto-unlock and return unlocked status
                            autoUnlockAccount(conn, cleanUser);
                            return new AccountLockStatus(cleanUser, false, 0, 0L, 0L);
                        }
                        long remainingSec = lockedUntil > 0 ? Math.max(0, (lockedUntil - now) / 1000) : 0;
                        return new AccountLockStatus(cleanUser, true, attempts, lockedUntil, remainingSec);
                    }
                    return new AccountLockStatus(cleanUser, false, attempts, 0L, 0L);
                }
            }
        } catch (SQLException e) {
            System.err.println("[AccountLockoutService] Database error getting lock status: " + e.getMessage());
        }
        return new AccountLockStatus(cleanUser, false, 0, 0L, 0L);
    }

    /**
     * Helper to perform atomic lazy unlocking within an existing connection.
     */
    private void autoUnlockAccount(Connection conn, String username) throws SQLException {
        String unlockSql = "UPDATE users SET is_locked = 0, locked_until = 0, failed_attempt_count = 0 WHERE username = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(unlockSql)) {
            pstmt.setString(1, username);
            pstmt.executeUpdate();
        }
        activityLogService.log(username, "ACCOUNT_UNLOCKED",
                "Temporary account lock expired. Account automatically restored to active status.");
    }

    /**
     * Testing utility: directly sets locked_until timestamp to simulate time travel without sleeping.
     */
    public synchronized void setLockUntilForTesting(String username, long lockedUntil) {
        String sql = "UPDATE users SET is_locked = 1, locked_until = ? WHERE username = ?";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setLong(1, lockedUntil);
            pstmt.setString(2, username);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[AccountLockoutService] Error setting lock timestamp: " + e.getMessage());
        }
    }

    /**
     * Testing utility: directly sets failed_attempt_count to simulate partial attempts.
     */
    public synchronized void setFailedAttemptsForTesting(String username, int count) {
        String sql = "UPDATE users SET failed_attempt_count = ? WHERE username = ?";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, count);
            pstmt.setString(2, username);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[AccountLockoutService] Error setting failed attempts: " + e.getMessage());
        }
    }

    /**
     * Retrieves all accounts with their current lockout and security states.
     * Enforces lazy auto-unlocking of expired locks.
     */
    public synchronized List<AccountLockStatus> getAllLockedAccounts() {
        List<AccountLockStatus> list = new ArrayList<>();
        String sql = "SELECT username FROM users ORDER BY is_locked DESC, failed_attempt_count DESC, username ASC";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {
            while (rs.next()) {
                String uname = rs.getString("username");
                AccountLockStatus status = getAccountLockStatus(uname);
                list.add(status);
            }
        } catch (SQLException e) {
            System.err.println("[AccountLockoutService] Database error querying locked accounts: " + e.getMessage());
        }
        return list;
    }
}
