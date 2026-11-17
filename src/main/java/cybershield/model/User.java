package cybershield.model;

/**
 * User — Represents an authenticated user in the CyberShield system.
 * Demonstrates: Encapsulation with private attributes, public getters and setters.
 * Used for authentication, role-based access control (ADMIN vs ANALYST),
 * and Review 3 account lockout security state.
 *
 * SECURITY: Credential fields (passwordHash, salt) are sensitive internal data
 * and must never be exposed or serialized in public or client API responses.
 */
public class User {
    private int id;
    private String username;
    private String passwordHash;
    private String salt;
    private String role; // "ADMIN" or "ANALYST"
    private String createdAt;

    // Review 3 Account Lockout Properties
    private int isLocked;              // 0 = Unlocked, 1 = Locked
    private long lockedUntil;          // Epoch millis until which account cannot authenticate (0 = not temporarily locked)
    private int failedAttemptCount;    // Consecutive failed authentication attempts

    // Default constructor required for JSON serialization
    public User() {
    }

    // Parameterized constructor for creating a new user instance (Review 1 & 2 backward compatibility)
    public User(int id, String username, String passwordHash, String salt, String role, String createdAt) {
        this(id, username, passwordHash, salt, role, createdAt, 0, 0L, 0);
    }

    // Full parameterized constructor including Review 3 account lockout properties
    public User(int id, String username, String passwordHash, String salt, String role, String createdAt,
                int isLocked, long lockedUntil, int failedAttemptCount) {
        this.id = id;
        this.username = username;
        this.passwordHash = passwordHash;
        this.salt = salt;
        this.role = role;
        this.createdAt = createdAt;
        this.isLocked = isLocked;
        this.lockedUntil = lockedUntil;
        this.failedAttemptCount = failedAttemptCount;
    }

    // Constructor without id (for creating new users before database insertion)
    public User(String username, String passwordHash, String salt, String role) {
        this(-1, username, passwordHash, salt, role, null, 0, 0L, 0);
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(String createdAt) {
        this.createdAt = createdAt;
    }

    public int getIsLocked() {
        return isLocked;
    }

    public void setIsLocked(int isLocked) {
        this.isLocked = isLocked;
    }

    public long getLockedUntil() {
        return lockedUntil;
    }

    public void setLockedUntil(long lockedUntil) {
        this.lockedUntil = lockedUntil;
    }

    public int getFailedAttemptCount() {
        return failedAttemptCount;
    }

    public void setFailedAttemptCount(int failedAttemptCount) {
        this.failedAttemptCount = failedAttemptCount;
    }

    public boolean isAdmin() {
        return "ADMIN".equalsIgnoreCase(role);
    }

    public boolean isAnalyst() {
        return "ANALYST".equalsIgnoreCase(role);
    }

    /**
     * Checks if the account is currently locked (either permanently or during active temporary lockout window).
     * Automatically considers temporary locks expired if currentEpochMillis >= lockedUntil.
     */
    public boolean isAccountLocked(long currentEpochMillis) {
        if (isLocked == 1) {
            if (lockedUntil > 0 && currentEpochMillis >= lockedUntil) {
                return false; // Expired
            }
            return true;
        }
        return false;
    }

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", role='" + role + '\'' +
                ", isLocked=" + isLocked +
                ", lockedUntil=" + lockedUntil +
                ", failedAttemptCount=" + failedAttemptCount +
                '}';
    }
}
