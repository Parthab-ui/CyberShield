package cybershield.model;

import java.sql.Timestamp;

/**
 * BlockedIP — Represents an IP address that has been blocked by the system.
 * Demonstrates ENCAPSULATION: all fields are private, accessed through getters/setters.
 */
public class BlockedIP {

    private int id;
    private String ipAddress;
    private String reason;
    private Timestamp blockedAt;

    // Default constructor
    public BlockedIP() { }

    // Constructor with all fields
    public BlockedIP(int id, String ipAddress, String reason, Timestamp blockedAt) {
        this.id = id;
        this.ipAddress = ipAddress;
        this.reason = reason;
        this.blockedAt = blockedAt;
    }

    // Constructor without id (for inserting new blocked IPs)
    public BlockedIP(String ipAddress, String reason) {
        this.ipAddress = ipAddress;
        this.reason = reason;
    }

    // -------- Getters and Setters (Encapsulation) --------

    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }

    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }

    public Timestamp getBlockedAt() { return blockedAt; }
    public void setBlockedAt(Timestamp blockedAt) { this.blockedAt = blockedAt; }

    /** Returns a readable string representation of this blocked IP. */
    @Override
    public String toString() {
        return "BlockedIP{id=" + id + ", ip='" + ipAddress + "', reason='" + reason + "'}";
    }
}
