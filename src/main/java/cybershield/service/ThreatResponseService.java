package cybershield.service;

import cybershield.database.DatabaseManager;
import cybershield.model.BlockedIp;
import cybershield.model.SecurityAlert;
import cybershield.model.ThreatResponse;
import cybershield.model.ThreatResponseStats;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * ThreatResponseService — Coordinates and audits automated defensive countermeasures in CyberShield.
 *
 * Responsibilities:
 * 1. Automatically enforces IP mitigations via IpBlockService (default 15 minutes).
 * 2. Checks loopback and trusted IP whitelist to prevent self-denial of service.
 * 3. Prevents duplicate active blocks and duplicate mitigation records for the same incident/target.
 * 4. Records structured mitigation telemetry in the 'threat_responses' table and 'activity_log'.
 * 5. Provides forensic history queries and aggregated defense statistics for dashboards and compliance.
 */
public class ThreatResponseService {

    public static final long DEFAULT_AUTO_BLOCK_DURATION_MINUTES = 15;

    private final IpBlockService ipBlockService;
    private final IncidentService incidentService;
    private final ActivityLogService activityLogService;

    public ThreatResponseService() {
        this(new IpBlockService(), new IncidentService(), new ActivityLogService());
    }

    public ThreatResponseService(IpBlockService ipBlockService,
                                 IncidentService incidentService,
                                 ActivityLogService activityLogService) {
        this.ipBlockService = (ipBlockService != null) ? ipBlockService : new IpBlockService();
        this.incidentService = (incidentService != null) ? incidentService : new IncidentService();
        this.activityLogService = (activityLogService != null) ? activityLogService : new ActivityLogService();
    }

    public IpBlockService getIpBlockService() {
        return ipBlockService;
    }

    public IncidentService getIncidentService() {
        return incidentService;
    }

    public ActivityLogService getActivityLogService() {
        return activityLogService;
    }

    /**
     * Executes an automated brute-force response: validates the source IP, checks whitelist,
     * applies a 15-minute block via IpBlockService, and records the defense action in SQLite.
     *
     * @param sourceIp The attacker IP address.
     * @param threatType The detected threat classification (e.g. "BRUTE_FORCE_ATTACK").
     * @param alert Associated SecurityAlert (optional).
     * @param incidentId Associated automatically generated incident ID in SQLite.
     * @return The persisted ThreatResponse record reflecting the outcome.
     */
    public synchronized ThreatResponse executeBruteForceResponse(
            String sourceIp, String threatType, SecurityAlert alert, Integer incidentId) {
        return executeBruteForceResponse(sourceIp, threatType, alert, incidentId, System.currentTimeMillis());
    }

    /**
     * Parameterized execution method allowing explicit epoch timestamps for deterministic testing.
     */
    public synchronized ThreatResponse executeBruteForceResponse(
            String sourceIp, String threatType, SecurityAlert alert, Integer incidentId, long epochMillis) {

        long now = epochMillis > 0 ? epochMillis : System.currentTimeMillis();
        String effectiveThreat = (threatType != null && !threatType.trim().isEmpty()) ? threatType.trim() : "BRUTE_FORCE_ATTACK";
        String cleanIp = sourceIp != null ? sourceIp.trim() : "";

        // 1. Validate IP address structure
        if (cleanIp.isEmpty() || !ipBlockService.isValidIp(cleanIp)) {
            ThreatResponse failed = new ThreatResponse(
                    incidentId, effectiveThreat, "AUTO_BLOCK_IP", cleanIp, "FAILED", now,
                    "Automated IP block failed: Invalid IP address format: '" + sourceIp + "'"
            );
            return recordResponse(failed);
        }

        // 2. Check Whitelist: do not block loopback or trusted addresses
        if (ipBlockService.isWhitelisted(cleanIp)) {
            ThreatResponse skipped = new ThreatResponse(
                    incidentId, effectiveThreat, "AUTO_BLOCK_IP", cleanIp, "SKIPPED_WHITELIST", now,
                    "Automated IP block skipped: Target IP " + cleanIp + " is whitelisted (loopback/trusted host)."
            );
            activityLogService.log("SYSTEM_AUTO_RESPONSE", "THREAT_RESPONSE_SKIPPED",
                    "Skipped automated block for whitelisted IP: " + cleanIp + " (Incident #" + incidentId + ")");
            return recordResponse(skipped);
        }

        // 3. Idempotency Check: check if a response was already recorded for this incident and action
        if (incidentId != null && incidentId > 0) {
            ThreatResponse existing = findExistingResponse(incidentId, cleanIp, "AUTO_BLOCK_IP");
            if (existing != null) {
                return existing;
            }
        }

        // 4. Check if IP is already actively blocked in the system
        if (ipBlockService.isBlocked(cleanIp)) {
            ThreatResponse alreadyActive = new ThreatResponse(
                    incidentId, effectiveThreat, "AUTO_BLOCK_IP", cleanIp, "ALREADY_ACTIVE", now,
                    "Target IP " + cleanIp + " is already actively blocked. Duplicate active block prevented."
            );
            return recordResponse(alreadyActive);
        }

        // 5. Execute Automatic IP Block via IpBlockService
        try {
            BlockedIp block = ipBlockService.blockIp(
                    cleanIp,
                    "Automated brute-force attack mitigation",
                    DEFAULT_AUTO_BLOCK_DURATION_MINUTES,
                    "SYSTEM_AUTO_RESPONSE",
                    now
            );

            if (block != null && "ACTIVE".equalsIgnoreCase(block.getStatus())) {
                ThreatResponse executed = new ThreatResponse(
                        incidentId, effectiveThreat, "AUTO_BLOCK_IP", cleanIp, "EXECUTED", now,
                        "Automated 15-minute IP block successfully applied following detection threshold."
                );
                executed.setCompletedAt(now);
                ThreatResponse recorded = recordResponse(executed);

                activityLogService.log(
                        "SYSTEM_AUTO_RESPONSE",
                        "THREAT_RESPONSE_EXECUTED",
                        "Automatically blocked malicious IP " + cleanIp + " for 15 minutes linked to Incident #" + incidentId
                );

                System.out.println("[ThreatResponse] AUTOMATED DEFENSE: Blocked IP " + cleanIp +
                        " for 15 minutes linked to Incident #" + incidentId);
                return recorded;
            } else {
                ThreatResponse failed = new ThreatResponse(
                        incidentId, effectiveThreat, "AUTO_BLOCK_IP", cleanIp, "FAILED", now,
                        "IpBlockService did not return an active block record for IP " + cleanIp
                );
                return recordResponse(failed);
            }
        } catch (Exception e) {
            System.err.println("[ThreatResponse] Error executing block on " + cleanIp + ": " + e.getMessage());
            ThreatResponse failed = new ThreatResponse(
                    incidentId, effectiveThreat, "AUTO_BLOCK_IP", cleanIp, "FAILED", now,
                    "Internal error during auto-block: " + e.getMessage()
            );
            return recordResponse(failed);
        }
    }

    /**
     * Persists a threat mitigation response record to the 'threat_responses' table.
     *
     * @param response The ThreatResponse object to persist.
     * @return The hydrated ThreatResponse with database-generated ID.
     */
    public synchronized ThreatResponse recordResponse(ThreatResponse response) {
        if (response == null) return null;

        String sql = "INSERT INTO threat_responses (incident_id, threat_type, action_taken, target_identifier, status, executed_at, completed_at, details) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {

            if (response.getIncidentId() != null && response.getIncidentId() > 0 && incidentExists(conn, response.getIncidentId())) {
                pstmt.setInt(1, response.getIncidentId());
            } else {
                pstmt.setNull(1, java.sql.Types.INTEGER);
            }
            pstmt.setString(2, response.getThreatType());
            pstmt.setString(3, response.getActionTaken());
            pstmt.setString(4, response.getTargetIdentifier());
            pstmt.setString(5, response.getStatus());
            pstmt.setLong(6, response.getExecutedAt());
            if (response.getCompletedAt() != null) {
                pstmt.setLong(7, response.getCompletedAt());
            } else {
                pstmt.setNull(7, java.sql.Types.INTEGER);
            }
            pstmt.setString(8, response.getDetails());

            pstmt.executeUpdate();
            try (ResultSet rs = pstmt.getGeneratedKeys()) {
                if (rs.next()) {
                    response.setId(rs.getInt(1));
                }
            }
        } catch (SQLException e) {
            System.err.println("[ThreatResponse] Error persisting threat response: " + e.getMessage());
        }
        return response;
    }

    /**
     * Retrieves historical threat response actions filtered by incident ID, target IP, and status.
     *
     * @param incidentId Optional filter for incident ID.
     * @param targetIp Optional filter for target IP.
     * @param statusFilter Optional filter for status ("EXECUTED", "ALREADY_ACTIVE", "FAILED", "SKIPPED_WHITELIST", or "ALL").
     * @return List of matching ThreatResponse records ordered newest first.
     */
    public synchronized List<ThreatResponse> getResponseHistory(Integer incidentId, String targetIp, String statusFilter) {
        List<ThreatResponse> results = new ArrayList<>();
        StringBuilder sql = new StringBuilder(
                "SELECT id, incident_id, threat_type, action_taken, target_identifier, status, executed_at, completed_at, details " +
                "FROM threat_responses WHERE 1=1"
        );
        List<Object> params = new ArrayList<>();

        if (incidentId != null && incidentId > 0) {
            sql.append(" AND incident_id = ?");
            params.add(incidentId);
        }
        if (targetIp != null && !targetIp.trim().isEmpty()) {
            sql.append(" AND target_identifier = ?");
            params.add(targetIp.trim());
        }
        if (statusFilter != null && !statusFilter.trim().isEmpty() && !"ALL".equalsIgnoreCase(statusFilter)) {
            sql.append(" AND UPPER(status) = ?");
            params.add(statusFilter.trim().toUpperCase());
        }
        sql.append(" ORDER BY executed_at DESC");

        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql.toString())) {

            for (int i = 0; i < params.size(); i++) {
                Object p = params.get(i);
                if (p instanceof Integer) {
                    pstmt.setInt(i + 1, (Integer) p);
                } else if (p instanceof String) {
                    pstmt.setString(i + 1, (String) p);
                }
            }

            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    results.add(mapResultSetToResponse(rs));
                }
            }
        } catch (SQLException e) {
            System.err.println("[ThreatResponse] Error querying response history: " + e.getMessage());
        }
        return results;
    }

    /**
     * Compiles aggregated statistics regarding threat responses across the system.
     *
     * @return ThreatResponseStats object.
     */
    public synchronized ThreatResponseStats getResponseStatistics() {
        int total = 0;
        int successful = 0;
        int failed = 0;
        int skipped = 0;
        int alreadyActive = 0;

        String sql = "SELECT status, COUNT(*) AS cnt FROM threat_responses GROUP BY status";
        try (Connection conn = DatabaseManager.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                String st = rs.getString("status");
                int count = rs.getInt("cnt");
                total += count;

                if ("EXECUTED".equalsIgnoreCase(st)) {
                    successful += count;
                } else if ("FAILED".equalsIgnoreCase(st)) {
                    failed += count;
                } else if (st != null && st.toUpperCase().startsWith("SKIPPED")) {
                    skipped += count;
                } else if ("ALREADY_ACTIVE".equalsIgnoreCase(st)) {
                    alreadyActive += count;
                }
            }
        } catch (SQLException e) {
            System.err.println("[ThreatResponse] Error calculating statistics: " + e.getMessage());
        }

        int activeBlockedIps = ipBlockService.getAllBlockedIps("ACTIVE").size();

        return new ThreatResponseStats(total, successful, failed, skipped, alreadyActive, activeBlockedIps);
    }

    /**
     * Testing utility: Clears all threat response history for clean test isolation.
     */
    public synchronized void clearResponseHistory() {
        try (Connection conn = DatabaseManager.getConnection();
             Statement stmt = conn.createStatement()) {
            stmt.executeUpdate("DELETE FROM threat_responses");
        } catch (SQLException e) {
            System.err.println("[ThreatResponse] Error clearing history: " + e.getMessage());
        }
    }

    private ThreatResponse findExistingResponse(int incidentId, String targetIp, String actionTaken) {
        String sql = "SELECT id, incident_id, threat_type, action_taken, target_identifier, status, executed_at, completed_at, details " +
                "FROM threat_responses WHERE incident_id = ? AND target_identifier = ? AND action_taken = ? LIMIT 1";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, incidentId);
            pstmt.setString(2, targetIp);
            pstmt.setString(3, actionTaken);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return mapResultSetToResponse(rs);
                }
            }
        } catch (SQLException e) {
            System.err.println("[ThreatResponse] Error checking existing response: " + e.getMessage());
        }
        return null;
    }

    private boolean incidentExists(Connection conn, int incidentId) {
        String sql = "SELECT id FROM incidents WHERE id = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, incidentId);
            try (ResultSet rs = pstmt.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            return false;
        }
    }

    private ThreatResponse mapResultSetToResponse(ResultSet rs) throws SQLException {
        int id = rs.getInt("id");
        int incId = rs.getInt("incident_id");
        Integer incidentId = rs.wasNull() ? null : incId;
        String threatType = rs.getString("threat_type");
        String actionTaken = rs.getString("action_taken");
        String targetIdentifier = rs.getString("target_identifier");
        String status = rs.getString("status");
        long executedAt = rs.getLong("executed_at");
        long compAt = rs.getLong("completed_at");
        Long completedAt = rs.wasNull() ? null : compAt;
        String details = rs.getString("details");

        return new ThreatResponse(id, incidentId, threatType, actionTaken, targetIdentifier, status, executedAt, completedAt, details);
    }
}
