package cybershield.model;

/**
 * AccountLockStatus — Represents the lockout and credential security status of a user account.
 * Encapsulates lockout state, consecutive failed attempts, expiration timestamps, and remaining time.
 * Prevents exposing password hashes, salts, or internal user identifiers.
 */
public class AccountLockStatus {

    private String username;
    private boolean locked;
    private int failedAttemptCount;
    private long lockedUntil;      // Epoch milliseconds
    private long remainingSeconds;  // Remaining lock duration in seconds (0 if unlocked)

    public AccountLockStatus() {
    }

    public AccountLockStatus(String username, boolean locked, int failedAttemptCount, long lockedUntil, long remainingSeconds) {
        this.username = username;
        this.locked = locked;
        this.failedAttemptCount = failedAttemptCount;
        this.lockedUntil = lockedUntil;
        this.remainingSeconds = remainingSeconds;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public boolean isLocked() {
        return locked;
    }

    public void setLocked(boolean locked) {
        this.locked = locked;
    }

    public int getFailedAttemptCount() {
        return failedAttemptCount;
    }

    public void setFailedAttemptCount(int failedAttemptCount) {
        this.failedAttemptCount = failedAttemptCount;
    }

    public long getLockedUntil() {
        return lockedUntil;
    }

    public void setLockedUntil(long lockedUntil) {
        this.lockedUntil = lockedUntil;
    }

    public long getRemainingSeconds() {
        return remainingSeconds;
    }

    public void setRemainingSeconds(long remainingSeconds) {
        this.remainingSeconds = remainingSeconds;
    }

    @Override
    public String toString() {
        return "AccountLockStatus{" +
                "username='" + username + '\'' +
                ", locked=" + locked +
                ", failedAttemptCount=" + failedAttemptCount +
                ", lockedUntil=" + lockedUntil +
                ", remainingSeconds=" + remainingSeconds +
                '}';
    }
}
