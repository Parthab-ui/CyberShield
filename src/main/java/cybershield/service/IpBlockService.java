package cybershield.service;

import cybershield.database.DatabaseManager;
import cybershield.model.BlockedIp;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * IpBlockService — Application-level IP blocking and whitelist engine for CyberShield.
 *
 * Responsibilities:
 * 1. Validating incoming IPv4 and IPv6 network addresses without external DNS lookups.
 * 2. Protecting loopback and critical administrative addresses via IP whitelisting.
 * 3. Enforcing persistent application-level IP blocking with configurable expiration durations.
 * 4. Preventing duplicate active blocks for the same IP.
 * 5. Automatically transitioning expired active blocks to EXPIRED status.
 * 6. Managing manual administrator unblock actions with full historical traceability.
 * 7. Providing thread-safe operations backed by SQLite transactions.
 */
public class IpBlockService {

    public static final long DEFAULT_BLOCK_DURATION_MINUTES = 15;
    public static final long DEFAULT_BLOCK_DURATION_MILLIS = DEFAULT_BLOCK_DURATION_MINUTES * 60 * 1000L;

    // Strict IPv4 validation pattern (4 octets, 0-255 each, no leading garbage)
    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$"
    );

    // Standard RFC-compliant IPv6 validation pattern (supports :: compaction)
    private static final Pattern IPV6_PATTERN = Pattern.compile(
            "^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|" +
            "^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|" +
            "^(?:[0-9a-fA-F]{1,4}:){1,7}:$|" +
            "^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|" +
            "^(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}$|" +
            "^(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}$|" +
            "^(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}$|" +
            "^(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}$|" +
            "^[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}$|" +
            "^:(?::[0-9a-fA-F]{1,4}){1,7}$|^::$"
    );

    // Configurable whitelist set (thread-safe)
    private final Set<String> whitelistedIps = ConcurrentHashMap.newKeySet();

    public IpBlockService() {
        // Initialize default trusted loopback addresses
        whitelistedIps.add("127.0.0.1");
        whitelistedIps.add("::1");
        whitelistedIps.add("0:0:0:0:0:0:0:1");
        whitelistedIps.add("localhost");
    }

    // =========================================================================
    // WHITELIST MANAGEMENT
    // =========================================================================

    /**
     * Checks if the given IP address is whitelisted against blocking.
     */
    public boolean isWhitelisted(String ipAddress) {
        if (ipAddress == null || ipAddress.trim().isEmpty()) {
            return false;
        }
        String clean = normalizeIp(ipAddress);
        return whitelistedIps.contains(clean) || whitelistedIps.contains(ipAddress.trim().toLowerCase());
    }

    /**
     * Adds an IP address to the in-memory trusted whitelist.
     */
    public void addWhitelistedIp(String ipAddress) {
        if (ipAddress == null || ipAddress.trim().isEmpty()) {
            throw new IllegalArgumentException("Cannot whitelist null or empty IP address.");
        }
        String clean = normalizeIp(ipAddress);
        if (!isValidIp(clean) && !"localhost".equalsIgnoreCase(clean)) {
            throw new IllegalArgumentException("Cannot whitelist invalid IP format: " + ipAddress);
        }
        whitelistedIps.add(clean);
    }

    /**
     * Removes an IP address from the trusted whitelist.
     */
    public boolean removeWhitelistedIp(String ipAddress) {
        if (ipAddress == null) return false;
        String clean = normalizeIp(ipAddress);
        return whitelistedIps.remove(clean);
    }

    /**
     * Returns an unmodifiable snapshot of currently whitelisted IP addresses.
     */
    public Set<String> getWhitelistedIps() {
        return Set.copyOf(whitelistedIps);
    }

    // =========================================================================
    // VALIDATION & NORMALIZATION
    // =========================================================================

    /**
     * Validates an IP string against IPv4 and IPv6 rules without performing network DNS lookups.
     */
    public boolean isValidIp(String ipAddress) {
        if (ipAddress == null) return false;
        String trimmed = ipAddress.trim();
        if (trimmed.isEmpty()) return false;

        // Allow localhost loopback aliases
        if ("localhost".equalsIgnoreCase(trimmed) || "127.0.0.1".equals(trimmed) || "::1".equals(trimmed)) {
            return true;
        }

        // Match against pure regex (no DNS)
        return IPV4_PATTERN.matcher(trimmed).matches() || IPV6_PATTERN.matcher(trimmed).matches();
    }

    /**
     * Normalizes loopback representations and trims whitespace.
     */
    public String normalizeIp(String ipAddress) {
        if (ipAddress == null) return "";
        String clean = ipAddress.trim();
        if ("0:0:0:0:0:0:0:1".equals(clean)) {
            return "::1";
        }
        return clean;
    }

    // =========================================================================
    // CORE BLOCKING OPERATIONS
    // =========================================================================

    /**
     * Blocks an IP address with the default 15-minute duration.
     */
    public BlockedIp blockIp(String ipAddress, String reason, String blockedBy) {
        return blockIp(ipAddress, reason, DEFAULT_BLOCK_DURATION_MINUTES, blockedBy, System.currentTimeMillis());
    }

    /**
     * Blocks an IP address with a custom duration in minutes.
     */
    public BlockedIp blockIp(String ipAddress, String reason, long durationMinutes, String blockedBy) {
        return blockIp(ipAddress, reason, durationMinutes, blockedBy, System.currentTimeMillis());
    }

    /**
     * Core block method with explicit epoch timestamp for deterministic testing.
     *
     * @param ipAddress Target IP address.
     * @param reason Security justification for the block.
     * @param durationMinutes Duration in minutes (duration <= 0 indicates permanent block).
     * @param blockedBy Username or service that initiated the block (e.g. "IDS_ENGINE", "admin").
     * @param currentEpochMillis System epoch timestamp in milliseconds.
     * @return The created or existing active BlockedIp record.
     * @throws IllegalArgumentException If IP is malformed or protected by whitelist.
     */
    public synchronized BlockedIp blockIp(String ipAddress, String reason, long durationMinutes,
                                         String blockedBy, long currentEpochMillis) {
        if (ipAddress == null || ipAddress.trim().isEmpty() || !isValidIp(ipAddress)) {
            throw new IllegalArgumentException("Cannot block invalid or malformed IP address: " + ipAddress);
        }

        String cleanIp = normalizeIp(ipAddress);

        if (isWhitelisted(cleanIp)) {
            throw new IllegalArgumentException("Cannot block protected/whitelisted IP address: " + cleanIp);
        }

        // Check whether an active block already exists in SQLite
        BlockedIp existingActive = getActiveBlock(cleanIp, currentEpochMillis);
        if (existingActive != null) {
            System.out.println("[IpBlockService] IP " + cleanIp + " already has an active block (ID #" +
                    existingActive.getId() + "). Duplicate active block prevented.");
            return existingActive;
        }

        // Calculate timestamps
        long blockedAt = currentEpochMillis;
        Long expiresAt = durationMinutes > 0 ? (blockedAt + (durationMinutes * 60 * 1000L)) : null;
        String actor = (blockedBy != null && !blockedBy.trim().isEmpty()) ? blockedBy.trim() : "SYSTEM";
        String blockReason = (reason != null && !reason.trim().isEmpty()) ? reason.trim() : "Automated security rule block";

        String sql = "INSERT INTO blocked_ips (ip_address, reason, blocked_at, expires_at, blocked_by, status, unblocked_at, unblocked_by) " +
                     "VALUES (?, ?, ?, ?, ?, 'ACTIVE', NULL, NULL)";

        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {

            pstmt.setString(1, cleanIp);
            pstmt.setString(2, blockReason);
            pstmt.setLong(3, blockedAt);
            if (expiresAt != null) {
                pstmt.setLong(4, expiresAt);
            } else {
                pstmt.setNull(4, Types.INTEGER);
            }
            pstmt.setString(5, actor);

            pstmt.executeUpdate();

            int generatedId = -1;
            try (ResultSet rs = pstmt.getGeneratedKeys()) {
                if (rs.next()) {
                    generatedId = rs.getInt(1);
                }
            }

            BlockedIp created = new BlockedIp(generatedId, cleanIp, blockReason, blockedAt, expiresAt, actor, "ACTIVE", null, null);
            System.out.println("[IpBlockService] Successfully blocked IP " + cleanIp + " for " + durationMinutes +
                    " minutes (ID #" + generatedId + ", Actor: " + actor + ")");
            return created;

        } catch (SQLException e) {
            System.err.println("[IpBlockService] Database error recording blocked IP: " + e.getMessage());
            throw new RuntimeException("Failed to persist IP block record to database", e);
        }
    }

    /**
     * Checks if an IP is actively blocked at the current system time.
     */
    public boolean isBlocked(String ipAddress) {
        return isBlocked(ipAddress, System.currentTimeMillis());
    }

    /**
     * Checks if an IP is actively blocked at a specific epoch timestamp.
     * Automatically transitions expired blocks to EXPIRED in SQLite.
     */
    public boolean isBlocked(String ipAddress, long currentEpochMillis) {
        if (ipAddress == null || ipAddress.trim().isEmpty() || !isValidIp(ipAddress)) {
            return false;
        }

        String cleanIp = normalizeIp(ipAddress);
        if (isWhitelisted(cleanIp)) {
            return false;
        }

        BlockedIp activeBlock = getActiveBlock(cleanIp, currentEpochMillis);
        return activeBlock != null;
    }

    /**
     * Retrieves the active BlockedIp record if one exists and is currently non-expired.
     */
    public BlockedIp getActiveBlock(String ipAddress) {
        return getActiveBlock(ipAddress, System.currentTimeMillis());
    }

    /**
     * Retrieves the active BlockedIp record for an IP at the given epoch time.
     * If an active record has expired, updates it to EXPIRED in SQLite and returns null.
     */
    public BlockedIp getActiveBlock(String ipAddress, long currentEpochMillis) {
        if (ipAddress == null || ipAddress.trim().isEmpty()) {
            return null;
        }

        String cleanIp = normalizeIp(ipAddress);
        String sql = "SELECT id, ip_address, reason, blocked_at, expires_at, blocked_by, status, unblocked_at, unblocked_by " +
                     "FROM blocked_ips WHERE ip_address = ? AND status = 'ACTIVE' ORDER BY id DESC LIMIT 1";

        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, cleanIp);

            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    BlockedIp block = mapRowToBlockedIp(rs);

                    // Check if the temporary block has expired
                    if (block.getExpiresAt() != null && currentEpochMillis >= block.getExpiresAt()) {
                        markBlockExpired(block.getId());
                        System.out.println("[IpBlockService] Block on IP " + cleanIp + " (ID #" + block.getId() +
                                ") has expired. Status updated to EXPIRED.");
                        return null; // Expired, access allowed
                    }

                    return block; // Block is still active
                }
            }
        } catch (SQLException e) {
            System.err.println("[IpBlockService] Error checking active block for IP " + cleanIp + ": " + e.getMessage());
        }

        return null;
    }

    /**
     * Unblocks an actively blocked IP address, updating status to UNBLOCKED.
     */
    public boolean unblockIp(String ipAddress, String unblockedBy) {
        return unblockIp(ipAddress, unblockedBy, System.currentTimeMillis());
    }

    /**
     * Unblocks an actively blocked IP address at an explicit timestamp.
     * Preserves the historical database record.
     */
    public synchronized boolean unblockIp(String ipAddress, String unblockedBy, long currentEpochMillis) {
        if (ipAddress == null || ipAddress.trim().isEmpty()) {
            return false;
        }

        String cleanIp = normalizeIp(ipAddress);
        String actor = (unblockedBy != null && !unblockedBy.trim().isEmpty()) ? unblockedBy.trim() : "ADMIN";

        String findSql = "SELECT id FROM blocked_ips WHERE ip_address = ? AND status = 'ACTIVE' ORDER BY id DESC LIMIT 1";
        String updateSql = "UPDATE blocked_ips SET status = 'UNBLOCKED', unblocked_at = ?, unblocked_by = ? WHERE id = ?";

        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement findStmt = conn.prepareStatement(findSql)) {

            findStmt.setString(1, cleanIp);
            try (ResultSet rs = findStmt.executeQuery()) {
                if (rs.next()) {
                    int blockId = rs.getInt("id");

                    try (PreparedStatement updateStmt = conn.prepareStatement(updateSql)) {
                        updateStmt.setLong(1, currentEpochMillis);
                        updateStmt.setString(2, actor);
                        updateStmt.setInt(3, blockId);

                        int affected = updateStmt.executeUpdate();
                        if (affected > 0) {
                            System.out.println("[IpBlockService] Successfully unblocked IP " + cleanIp +
                                    " (ID #" + blockId + ", Unblocked by: " + actor + ")");
                            return true;
                        }
                    }
                }
            }
        } catch (SQLException e) {
            System.err.println("[IpBlockService] Error unblocking IP " + cleanIp + ": " + e.getMessage());
        }

        return false;
    }

    /**
     * Scans for all active blocks whose expiration timestamp has passed and marks them EXPIRED.
     * Returns the count of expired blocks updated.
     */
    public int expireOutdatedBlocks() {
        return expireOutdatedBlocks(System.currentTimeMillis());
    }

    /**
     * Scans for all active blocks where expires_at <= currentEpochMillis and marks them EXPIRED.
     */
    public synchronized int expireOutdatedBlocks(long currentEpochMillis) {
        String sql = "UPDATE blocked_ips SET status = 'EXPIRED' WHERE status = 'ACTIVE' AND expires_at IS NOT NULL AND expires_at <= ?";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setLong(1, currentEpochMillis);
            int affected = pstmt.executeUpdate();
            if (affected > 0) {
                System.out.println("[IpBlockService] Automatically expired " + affected + " outdated IP block records.");
            }
            return affected;

        } catch (SQLException e) {
            System.err.println("[IpBlockService] Error expiring outdated blocks: " + e.getMessage());
        }
        return 0;
    }

    /**
     * Convenience method to retrieve blocked IPs by status filter.
     */
    public List<BlockedIp> getAllBlockedIps(String statusFilter) {
        return getBlockedIps(statusFilter, !"ACTIVE".equalsIgnoreCase(statusFilter));
    }

    /**
     * Retrieves blocked IP records with optional status filtering.
     *
     * @param statusFilter Filter e.g. "ACTIVE", "EXPIRED", "UNBLOCKED", or "ALL".
     * @param includeHistory If false, strictly returns ACTIVE records only.
     */
    public List<BlockedIp> getBlockedIps(String statusFilter, boolean includeHistory) {
        List<BlockedIp> list = new ArrayList<>();
        StringBuilder sql = new StringBuilder("SELECT id, ip_address, reason, blocked_at, expires_at, blocked_by, status, unblocked_at, unblocked_by FROM blocked_ips ");

        List<Object> params = new ArrayList<>();

        if (!includeHistory) {
            sql.append("WHERE status = 'ACTIVE' ");
        } else if (statusFilter != null && !statusFilter.trim().isEmpty() && !"ALL".equalsIgnoreCase(statusFilter.trim())) {
            sql.append("WHERE status = ? ");
            params.add(statusFilter.trim().toUpperCase());
        }

        sql.append("ORDER BY id DESC");

        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql.toString())) {

            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }

            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    list.add(mapRowToBlockedIp(rs));
                }
            }
        } catch (SQLException e) {
            System.err.println("[IpBlockService] Error querying blocked IPs: " + e.getMessage());
        }

        return list;
    }

    /**
     * Clears all blocked IP records from SQLite. Strictly for automated unit test resets.
     */
    public void clearBlockHistory() {
        try (Connection conn = DatabaseManager.getConnection();
             Statement stmt = conn.createStatement()) {
            stmt.executeUpdate("DELETE FROM blocked_ips");
        } catch (SQLException e) {
            System.err.println("[IpBlockService] Error clearing block history: " + e.getMessage());
        }
    }

    // =========================================================================
    // HELPER MAPPERS
    // =========================================================================

    private BlockedIp mapRowToBlockedIp(ResultSet rs) throws SQLException {
        int id = rs.getInt("id");
        String ip = rs.getString("ip_address");
        String reason = rs.getString("reason");
        long blockedAt = rs.getLong("blocked_at");

        long expVal = rs.getLong("expires_at");
        Long expiresAt = rs.wasNull() ? null : expVal;

        String blockedBy = rs.getString("blocked_by");
        String status = rs.getString("status");

        long unbVal = rs.getLong("unblocked_at");
        Long unblockedAt = rs.wasNull() ? null : unbVal;

        String unblockedBy = rs.getString("unblocked_by");

        return new BlockedIp(id, ip, reason, blockedAt, expiresAt, blockedBy, status, unblockedAt, unblockedBy);
    }

    private void markBlockExpired(int blockId) {
        String sql = "UPDATE blocked_ips SET status = 'EXPIRED' WHERE id = ?";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, blockId);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[IpBlockService] Error marking block expired: " + e.getMessage());
        }
    }
}

