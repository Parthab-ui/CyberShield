package cybershield.model;

/**
 * BlockedIp — Represents an application-level firewall block on a client IP address.
 * Demonstrates: Domain modeling for defensive network isolation, temporary expiration tracking,
 * and administrator audit trail for manual unblock actions.
 *
 * Status values:
 * - ACTIVE: Currently blocked from authenticating or accessing endpoints.
 * - EXPIRED: Block duration has lapsed automatically.
 * - UNBLOCKED: Administrator manually revoked the block.
 */
public class BlockedIp {

    private int id;
    private String ipAddress;
    private String reason;
    private long blockedAt;
    private Long expiresAt;      // Epoch millis, null indicates permanent block
    private String blockedBy;    // "IDS_ENGINE" or administrator username
    private String status;       // "ACTIVE", "EXPIRED", "UNBLOCKED"
    private Long unblockedAt;    // Epoch millis when unblocked
    private String unblockedBy;  // Username of administrator who unblocked

    /** Default constructor required for Google Gson serialization */
    public BlockedIp() {
    }

    /** Full parameterized constructor */
    public BlockedIp(int id, String ipAddress, String reason, long blockedAt, Long expiresAt,
                     String blockedBy, String status, Long unblockedAt, String unblockedBy) {
        this.id = id;
        this.ipAddress = ipAddress;
        this.reason = reason;
        this.blockedAt = blockedAt;
        this.expiresAt = expiresAt;
        this.blockedBy = blockedBy;
        this.status = (status != null && !status.trim().isEmpty()) ? status.trim().toUpperCase() : "ACTIVE";
        this.unblockedAt = unblockedAt;
        this.unblockedBy = unblockedBy;
    }

    /** Constructor for creating new block entries before database insertion */
    public BlockedIp(String ipAddress, String reason, long blockedAt, Long expiresAt, String blockedBy) {
        this(-1, ipAddress, reason, blockedAt, expiresAt, blockedBy, "ACTIVE", null, null);
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public long getBlockedAt() {
        return blockedAt;
    }

    public void setBlockedAt(long blockedAt) {
        this.blockedAt = blockedAt;
    }

    public Long getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Long expiresAt) {
        this.expiresAt = expiresAt;
    }

    public String getBlockedBy() {
        return blockedBy;
    }

    public void setBlockedBy(String blockedBy) {
        this.blockedBy = blockedBy;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = (status != null && !status.trim().isEmpty()) ? status.trim().toUpperCase() : "ACTIVE";
    }

    public Long getUnblockedAt() {
        return unblockedAt;
    }

    public void setUnblockedAt(Long unblockedAt) {
        this.unblockedAt = unblockedAt;
    }

    public String getUnblockedBy() {
        return unblockedBy;
    }

    public void setUnblockedBy(String unblockedBy) {
        this.unblockedBy = unblockedBy;
    }

    /** Checks whether this block record is currently in ACTIVE status */
    public boolean isActive() {
        return "ACTIVE".equalsIgnoreCase(status);
    }

    /** Checks whether this temporary block has expired relative to the given timestamp */
    public boolean isExpired(long currentTimeMillis) {
        return expiresAt != null && expiresAt > 0 && currentTimeMillis >= expiresAt;
    }

    @Override
    public String toString() {
        return "BlockedIp{" +
                "id=" + id +
                ", ipAddress='" + ipAddress + '\'' +
                ", reason='" + reason + '\'' +
                ", blockedAt=" + blockedAt +
                ", expiresAt=" + expiresAt +
                ", blockedBy='" + blockedBy + '\'' +
                ", status='" + status + '\'' +
                '}';
    }
}

