package cybershield.service;

import cybershield.database.DatabaseManager;
import cybershield.model.Incident;
import cybershield.model.IntrusionDetectionConfig;
import cybershield.model.SecurityAlert;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * IntrusionDetectionService — Rule-based automated intrusion detection engine for CyberShield.
 *
 * Core Responsibilities:
 * 1. Monitoring failed login events persistently in SQLite.
 * 2. Maintaining and evaluating failed attempt history per source IP within a sliding time window.
 * 3. Enforcing Rule: MAX_FAILED_ATTEMPTS (5) within TIME_WINDOW_MINUTES (2) -> Suspected Brute Force.
 * 4. Automatically generating HIGH severity incidents via IncidentService.
 * 5. Enforcing ALERT_COOLDOWN_MINUTES (10) to suppress duplicate incident spam.
 * 6. Audit logging all automated detections in ActivityLogService.
 * 7. Supplying real-time detection telemetry to Web and Swing dashboards.
 *
 * Designed using clean OOP principles suitable for 2nd-Year B.Tech CSE evaluation.
 */
public class IntrusionDetectionService {

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final IncidentService incidentService;
    private final ActivityLogService activityLogService;
    private final AccessEventService accessEventService;
    private final ThreatResponseService threatResponseService;
    private IntrusionDetectionConfig config;

    public IntrusionDetectionService() {
        this(new IncidentService(), new ActivityLogService(), new AccessEventService(), new IntrusionDetectionConfig());
    }

    public IntrusionDetectionService(IncidentService incidentService,
                                     ActivityLogService activityLogService,
                                     AccessEventService accessEventService,
                                     IntrusionDetectionConfig config) {
        this(incidentService, activityLogService, accessEventService, config,
             new ThreatResponseService(new IpBlockService(), incidentService, activityLogService));
    }

    public IntrusionDetectionService(IncidentService incidentService,
                                     ActivityLogService activityLogService,
                                     AccessEventService accessEventService,
                                     IntrusionDetectionConfig config,
                                     ThreatResponseService threatResponseService) {
        this.incidentService = incidentService;
        this.activityLogService = activityLogService;
        this.accessEventService = accessEventService;
        this.config = config != null ? config : new IntrusionDetectionConfig();
        this.threatResponseService = threatResponseService;
    }

    public ThreatResponseService getThreatResponseService() {
        return threatResponseService;
    }

    public IntrusionDetectionConfig getConfig() {
        return config;
    }

    public void setConfig(IntrusionDetectionConfig config) {
        if (config == null) throw new IllegalArgumentException("Config cannot be null");
        this.config = config;
    }

    /**
     * Records a failed login attempt with the current system time and evaluates detection rules.
     * Note: Passwords are NEVER accepted or stored here.
     *
     * @param sourceIp The remote connection IP address.
     * @param username The attempted username.
     * @return A SecurityAlert if an automated incident was triggered; null otherwise.
     */
    public SecurityAlert recordFailedLogin(String sourceIp, String username) {
        return recordFailedLogin(sourceIp, username, System.currentTimeMillis());
    }

    /**
     * Records a failed login attempt with an explicit epoch timestamp.
     * Enables deterministic testing of sliding time windows and cooldowns.
     *
     * @param sourceIp The remote IP address.
     * @param username The attempted username.
     * @param timestampMillis Epoch timestamp in milliseconds.
     * @return A SecurityAlert if a new intrusion was detected and incident created; null otherwise.
     */
    public synchronized SecurityAlert recordFailedLogin(String sourceIp, String username, long timestampMillis) {
        String cleanIp = sanitizeIp(sourceIp);
        String cleanUser = (username != null && !username.trim().isEmpty()) ? username.trim() : "unknown";
        String timeStr = formatEpoch(timestampMillis);

        // Step 1: Persist failed login attempt to SQLite table
        String insertSql = "INSERT INTO failed_logins (ip_address, username, attempted_at, timestamp_epoch) VALUES (?, ?, ?, ?)";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(insertSql)) {

            pstmt.setString(1, cleanIp);
            pstmt.setString(2, cleanUser);
            pstmt.setString(3, timeStr);
            pstmt.setLong(4, timestampMillis);
            pstmt.executeUpdate();

        } catch (SQLException e) {
            System.err.println("[IDS] Error recording failed login in database: " + e.getMessage());
        }

        // Step 2: Evaluate detection rules for this IP
        return evaluateDetectionRule(cleanIp, timestampMillis);
    }

    /**
     * Evaluates whether the specified IP has exceeded the brute-force threshold within
     * the configured sliding time window, and generates an automated incident if eligible.
     */
    public synchronized SecurityAlert evaluateDetectionRule(String sourceIp, long currentEpochMillis) {
        String cleanIp = sanitizeIp(sourceIp);
        long windowStartEpoch = currentEpochMillis - config.getTimeWindowMillis();

        // 1. Count failed attempts from this IP within the sliding time window
        int attemptCount = countRecentFailures(cleanIp, windowStartEpoch);

        // 2. Threshold Check: If count < MAX_FAILED_ATTEMPTS, no threat alert yet
        if (attemptCount < config.getMaxFailedAttempts()) {
            return null;
        }

        // 3. Cooldown Check: Verify if an alert was already triggered recently for this IP
        long cooldownStartEpoch = currentEpochMillis - config.getAlertCooldownMillis();
        if (isInCooldown(cleanIp, cooldownStartEpoch)) {
            System.out.println("[IDS] Alert threshold reached for IP " + cleanIp +
                    " (" + attemptCount + " failures), but IP is within " +
                    config.getAlertCooldownMinutes() + "-minute cooldown. Duplicate incident suppressed.");
            return null;
        }

        // 4. Threshold reached and not in cooldown -> Trigger Automated Incident Generation
        return triggerBruteForceIncident(cleanIp, attemptCount, currentEpochMillis);
    }

    /**
     * Automatically creates a HIGH severity incident in SQLite, logs the alert,
     * and records the action in the activity audit history.
     */
    private SecurityAlert triggerBruteForceIncident(String sourceIp, int failedAttempts, long epochMillis) {
        String timestamp = formatEpoch(epochMillis);

        String incidentTitle = "Brute Force Login Attack Detected";
        String description = String.format(
                "Multiple failed login attempts were detected from the same source IP address within a short time period. " +
                "The activity has been classified as suspicious and automatically flagged by the intrusion detection engine.\n\n" +
                "Forensic Detection Details:\n" +
                "• Source IP Address: %s\n" +
                "• Failed Login Attempts: %d\n" +
                "• Detection Timestamp: %s\n" +
                "• Detection Rule Triggered: Threshold of %d failed attempts within %d minutes reached.\n" +
                "• Incident Classification: Automated Rule-Based IDS Alert",
                sourceIp, failedAttempts, timestamp, config.getMaxFailedAttempts(), config.getTimeWindowMinutes()
        );

        // Create incident via existing IncidentService
        Incident incident = new Incident(incidentTitle, description, "HIGH", "OPEN", "IDS_ENGINE");
        Incident created = incidentService.create(incident, "IDS_ENGINE");

        int incidentId = created != null ? created.getId() : -1;

        // Persist to security_alerts table
        SecurityAlert alert = new SecurityAlert(
                "BRUTE_FORCE_ATTACK",
                sourceIp,
                failedAttempts,
                "HIGH",
                "OPEN",
                incidentId,
                description,
                timestamp,
                epochMillis
        );

        String insertAlertSql = "INSERT INTO security_alerts " +
                "(alert_type, source_ip, failed_attempts, severity, status, incident_id, details, created_at, created_at_epoch) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(insertAlertSql, Statement.RETURN_GENERATED_KEYS)) {

            pstmt.setString(1, alert.getAlertType());
            pstmt.setString(2, alert.getSourceIp());
            pstmt.setInt(3, alert.getFailedAttempts());
            pstmt.setString(4, alert.getSeverity());
            pstmt.setString(5, alert.getStatus());
            pstmt.setInt(6, alert.getIncidentId());
            pstmt.setString(7, alert.getDetails());
            pstmt.setString(8, alert.getCreatedAt());
            pstmt.setLong(9, alert.getCreatedAtEpoch());

            pstmt.executeUpdate();
            try (ResultSet rs = pstmt.getGeneratedKeys()) {
                if (rs.next()) {
                    alert.setId(rs.getInt(1));
                }
            }

        } catch (SQLException e) {
            System.err.println("[IDS] Failed to persist security alert: " + e.getMessage());
        }

        // Record automated detection in audit activity log
        activityLogService.log(
                "IDS_ENGINE",
                "INTRUSION_ALERT",
                "Detected brute-force attack from IP " + sourceIp + " (" + failedAttempts + " failures). Generated Incident #" + incidentId
        );

        System.out.println("[IDS ALERT] *** BRUTE FORCE ATTACK DETECTED *** Source IP: " + sourceIp +
                " | Failures: " + failedAttempts + " | Created Incident #" + incidentId);

        // Review 3 Phase 4: Automated Threat Response Execution
        if (threatResponseService != null) {
            try {
                threatResponseService.executeBruteForceResponse(
                        sourceIp, "BRUTE_FORCE_ATTACK", alert, incidentId, epochMillis
                );
            } catch (Exception e) {
                System.err.println("[IDS] Error executing automated threat response: " + e.getMessage());
            }
        }

        return alert;
    }

    /**
     * Counts failed login attempts from a given IP starting from windowStartEpoch.
     */
    public int countRecentFailures(String sourceIp, long windowStartEpoch) {
        String sql = "SELECT COUNT(*) FROM failed_logins WHERE ip_address = ? AND timestamp_epoch >= ?";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, sourceIp);
            pstmt.setLong(2, windowStartEpoch);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt(1);
                }
            }
        } catch (SQLException e) {
            System.err.println("[IDS] Error counting recent failures: " + e.getMessage());
        }
        return 0;
    }

    /**
     * Checks if a security alert was already generated for this IP since cooldownStartEpoch.
     */
    public boolean isInCooldown(String sourceIp, long cooldownStartEpoch) {
        String sql = "SELECT COUNT(*) FROM security_alerts WHERE source_ip = ? AND created_at_epoch >= ?";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, sourceIp);
            pstmt.setLong(2, cooldownStartEpoch);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt(1) > 0;
                }
            }
        } catch (SQLException e) {
            System.err.println("[IDS] Error checking cooldown: " + e.getMessage());
        }
        return false;
    }

    /**
     * Retrieves the latest active security alert for the dashboard.
     */
    public SecurityAlert getLatestAlert() {
        String sql = "SELECT id, alert_type, source_ip, failed_attempts, severity, status, incident_id, details, created_at, created_at_epoch " +
                "FROM security_alerts ORDER BY id DESC LIMIT 1";

        try (Connection conn = DatabaseManager.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            if (rs.next()) {
                return mapResultSetToAlert(rs);
            }
        } catch (SQLException e) {
            System.err.println("[IDS] Error fetching latest alert: " + e.getMessage());
        }
        return null;
    }

    /**
     * Retrieves recent security alerts ordered newest first.
     */
    public List<SecurityAlert> getRecentAlerts(int limit) {
        List<SecurityAlert> list = new ArrayList<>();
        int effectiveLimit = limit > 0 ? limit : 50;
        String sql = "SELECT id, alert_type, source_ip, failed_attempts, severity, status, incident_id, details, created_at, created_at_epoch " +
                "FROM security_alerts ORDER BY id DESC LIMIT ?";

        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, effectiveLimit);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    list.add(mapResultSetToAlert(rs));
                }
            }
        } catch (SQLException e) {
            System.err.println("[IDS] Error fetching recent alerts: " + e.getMessage());
        }
        return list;
    }

    /**
     * Returns total detected threats count from security_alerts table.
     */
    public int getTotalDetectedThreats() {
        String sql = "SELECT COUNT(*) FROM security_alerts";
        try (Connection conn = DatabaseManager.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            if (rs.next()) return rs.getInt(1);
        } catch (SQLException e) {
            System.err.println("[IDS] Error getting total threats: " + e.getMessage());
        }
        return 0;
    }

    /**
     * Returns active (OPEN or INVESTIGATING) security alerts count.
     */
    public int getActiveAlertsCount() {
        String sql = "SELECT COUNT(*) FROM security_alerts WHERE UPPER(status) IN ('OPEN', 'INVESTIGATING')";
        try (Connection conn = DatabaseManager.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            if (rs.next()) return rs.getInt(1);
        } catch (SQLException e) {
            System.err.println("[IDS] Error getting active alerts: " + e.getMessage());
        }
        return 0;
    }

    /**
     * Returns the number of automatically generated incidents created by IDS_ENGINE.
     */
    public int getAutoIncidentsCount() {
        String sql = "SELECT COUNT(*) FROM incidents WHERE created_by = 'IDS_ENGINE'";
        try (Connection conn = DatabaseManager.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            if (rs.next()) return rs.getInt(1);
        } catch (SQLException e) {
            System.err.println("[IDS] Error getting auto-incident count: " + e.getMessage());
        }
        return 0;
    }

    /**
     * Clears failed login and alert history (strictly for automated unit test resets).
     */
    public void clearDetectionHistory() {
        try (Connection conn = DatabaseManager.getConnection();
             Statement stmt = conn.createStatement()) {

            stmt.executeUpdate("DELETE FROM failed_logins");
            stmt.executeUpdate("DELETE FROM security_alerts");
        } catch (SQLException e) {
            System.err.println("[IDS] Error clearing detection history: " + e.getMessage());
        }
        if (threatResponseService != null) {
            threatResponseService.clearResponseHistory();
        }
    }

    private SecurityAlert mapResultSetToAlert(ResultSet rs) throws SQLException {
        return new SecurityAlert(
                rs.getInt("id"),
                rs.getString("alert_type"),
                rs.getString("source_ip"),
                rs.getInt("failed_attempts"),
                rs.getString("severity"),
                rs.getString("status"),
                rs.getInt("incident_id"),
                rs.getString("details"),
                rs.getString("created_at"),
                rs.getLong("created_at_epoch")
        );
    }

    private String sanitizeIp(String ip) {
        if (ip == null || ip.trim().isEmpty()) {
            return "127.0.0.1";
        }
        String clean = ip.trim();
        // Normalize IPv6 loopback
        if ("0:0:0:0:0:0:0:1".equals(clean) || "::1".equals(clean)) {
            return "127.0.0.1";
        }
        return clean;
    }

    private String formatEpoch(long epochMillis) {
        return LocalDateTime.ofInstant(Instant.ofEpochMilli(epochMillis), ZoneId.systemDefault()).format(FORMATTER);
    }
}

