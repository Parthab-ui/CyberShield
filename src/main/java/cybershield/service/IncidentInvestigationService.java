package cybershield.service;

import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import cybershield.database.DatabaseManager;
import cybershield.model.Incident;
import cybershield.model.InvestigationNote;
import cybershield.model.InvestigationSummary;
import cybershield.model.InvestigationTimelineItem;
import cybershield.model.ThreatResponse;
import cybershield.model.User;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

/**
 * IncidentInvestigationService — Coordinates multi-analyst incident triage,
 * structured forensic evidence recording, investigator ownership, and resolution auditing.
 *
 * Demonstrates:
 * 1. Collaborative SOC workflow and multi-note forensic dossiers.
 * 2. Structured JSON evidence validation and size bounding.
 * 3. Role-based assignment verification (ADMIN or ANALYST only).
 * 4. Unified chronological investigation timeline synthesis across incidents, notes, threat responses, and activity logs.
 * 5. Incident lifecycle state transitions (OPEN -> INVESTIGATING -> RESOLVED -> CLOSED).
 */
public class IncidentInvestigationService {

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final int MAX_EVIDENCE_PAYLOAD_BYTES = 65536; // 64 KB limit

    public static final Set<String> SUGGESTED_ROOT_CAUSES = Set.of(
            "BRUTE_FORCE_ATTACK",
            "CREDENTIAL_STUFFING",
            "UNAUTHORIZED_ACCESS",
            "SUSPICIOUS_LOGIN_ACTIVITY",
            "OTHER"
    );

    private final IncidentService incidentService;
    private final UserService userService;
    private final ActivityLogService activityLogService;
    private final ThreatResponseService threatResponseService;

    public IncidentInvestigationService() {
        this(new IncidentService(), new UserService(), new ActivityLogService(), new ThreatResponseService());
    }

    public IncidentInvestigationService(IncidentService incidentService,
                                      UserService userService,
                                      ActivityLogService activityLogService,
                                      ThreatResponseService threatResponseService) {
        this.incidentService = (incidentService != null) ? incidentService : new IncidentService();
        this.userService = (userService != null) ? userService : new UserService();
        this.activityLogService = (activityLogService != null) ? activityLogService : new ActivityLogService();
        this.threatResponseService = (threatResponseService != null) ? threatResponseService : new ThreatResponseService();
    }

    public IncidentService getIncidentService() {
        return incidentService;
    }

    public UserService getUserService() {
        return userService;
    }

    public ActivityLogService getActivityLogService() {
        return activityLogService;
    }

    public ThreatResponseService getThreatResponseService() {
        return threatResponseService;
    }

    /**
     * Adds an analyst investigation note and optional forensic evidence to an existing incident.
     * Enforces role validation, JSON syntax verification on structured payloads, and updates incident lifecycle.
     *
     * @param incidentId Target incident ID.
     * @param analystUsername Authorizing investigator.
     * @param notes Technical narrative.
     * @param evidenceData Optional structured JSON or descriptive evidence.
     * @return The persisted InvestigationNote record.
     */
    public synchronized InvestigationNote addInvestigationNote(int incidentId, String analystUsername, String notes, String evidenceData) {
        // 1. Verify incident existence
        Incident incident = incidentService.getById(incidentId);
        if (incident == null) {
            throw new IllegalArgumentException("Incident #" + incidentId + " does not exist.");
        }

        // 2. Validate analyst identity & role
        if (analystUsername == null || analystUsername.trim().isEmpty()) {
            throw new IllegalArgumentException("Analyst username cannot be empty.");
        }
        User analyst = userService.getUserByUsername(analystUsername.trim());
        if (analyst == null) {
            throw new IllegalArgumentException("User '" + analystUsername + "' does not exist.");
        }
        if (!"ANALYST".equalsIgnoreCase(analyst.getRole()) && !"ADMIN".equalsIgnoreCase(analyst.getRole())) {
            throw new IllegalArgumentException("User '" + analystUsername + "' with role '" + analyst.getRole() +
                    "' is not authorized to conduct investigations (must be ANALYST or ADMIN).");
        }

        // 3. Validate investigation notes
        if (notes == null || notes.trim().isEmpty()) {
            throw new IllegalArgumentException("Investigation notes cannot be empty.");
        }

        // 4. Validate evidence payload
        String cleanEvidence = null;
        if (evidenceData != null && !evidenceData.trim().isEmpty()) {
            String trimmed = evidenceData.trim();
            if (trimmed.length() > MAX_EVIDENCE_PAYLOAD_BYTES) {
                throw new IllegalArgumentException("Evidence data exceeds maximum allowed size (" + MAX_EVIDENCE_PAYLOAD_BYTES + " bytes).");
            }
            if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
                try {
                    JsonParser.parseString(trimmed);
                } catch (JsonSyntaxException e) {
                    throw new IllegalArgumentException("Malformed JSON evidence payload: " + e.getMessage());
                }
            }
            cleanEvidence = trimmed;
        }

        long now = System.currentTimeMillis();
        String sql = "INSERT INTO incident_investigations (incident_id, analyst_username, notes, evidence_data, created_at) " +
                "VALUES (?, ?, ?, ?, ?)";
        int generatedId = -1;

        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {

            pstmt.setInt(1, incidentId);
            pstmt.setString(2, analyst.getUsername());
            pstmt.setString(3, notes.trim());
            pstmt.setString(4, cleanEvidence);
            pstmt.setLong(5, now);

            int affected = pstmt.executeUpdate();
            if (affected > 0) {
                try (ResultSet rs = pstmt.getGeneratedKeys()) {
                    if (rs.next()) {
                        generatedId = rs.getInt(1);
                    }
                }
            }
        } catch (SQLException e) {
            System.err.println("[IncidentInvestigationService] Error saving investigation note: " + e.getMessage());
            return null;
        }

        // 5. Automatic lifecycle transition: OPEN -> INVESTIGATING
        if ("OPEN".equalsIgnoreCase(incident.getStatus())) {
            incident.setStatus("INVESTIGATING");
            incidentService.update(incidentId, incident, analyst.getUsername());
            activityLogService.log(analyst.getUsername(), "INVESTIGATION_STARTED",
                    "Investigation automatically initiated on incident #" + incidentId);
        }

        // 6. Audit logging
        String shortNote = notes.trim().length() > 60 ? notes.trim().substring(0, 57) + "..." : notes.trim();
        activityLogService.log(analyst.getUsername(), "INVESTIGATION_NOTE_ADDED",
                "Added note to incident #" + incidentId + ": " + shortNote);

        if (cleanEvidence != null) {
            activityLogService.log(analyst.getUsername(), "INVESTIGATION_EVIDENCE_ADDED",
                    "Attached forensic evidence to incident #" + incidentId);
        }

        return new InvestigationNote(generatedId, incidentId, analyst.getUsername(), notes.trim(), cleanEvidence, now);
    }

    /**
     * Retrieves all investigation notes associated with an incident ordered chronologically.
     *
     * @param incidentId Target incident ID.
     * @return List of InvestigationNote items.
     */
    public synchronized List<InvestigationNote> getInvestigationNotes(int incidentId) {
        List<InvestigationNote> notes = new ArrayList<>();
        String sql = "SELECT id, incident_id, analyst_username, notes, evidence_data, created_at " +
                "FROM incident_investigations WHERE incident_id = ? ORDER BY created_at ASC, id ASC";

        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, incidentId);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    notes.add(new InvestigationNote(
                            rs.getInt("id"),
                            rs.getInt("incident_id"),
                            rs.getString("analyst_username"),
                            rs.getString("notes"),
                            rs.getString("evidence_data"),
                            rs.getLong("created_at")
                    ));
                }
            }
        } catch (SQLException e) {
            System.err.println("[IncidentInvestigationService] Error retrieving notes: " + e.getMessage());
        }
        return notes;
    }

    /**
     * Synthesizes a unified forensic investigation timeline by aggregating:
     * 1. Incident creation milestone.
     * 2. Analyst forensic notes and attached evidence.
     * 3. Automated/manual threat response defense actions.
     * 4. Correlated audit activity logs (assignments, root cause updates, resolutions).
     *
     * @param incidentId Target incident ID.
     * @return Chronologically sorted List of InvestigationTimelineItem.
     */
    public synchronized List<InvestigationTimelineItem> getInvestigationTimeline(int incidentId) {
        List<InvestigationTimelineItem> timeline = new ArrayList<>();

        // 1. Incident Creation Milestone
        Incident incident = incidentService.getById(incidentId);
        if (incident != null) {
            long creationTime = parseTimestampToEpoch(incident.getCreatedAt());
            timeline.add(new InvestigationTimelineItem(
                    creationTime,
                    "INCIDENT_CREATED",
                    incident.getCreatedBy() != null ? incident.getCreatedBy() : "system",
                    "Incident created: " + incident.getTitle() + " [" + incident.getSeverity() + "]",
                    incident.getDescription()
            ));
        }

        // 2. Investigation Notes & Evidence
        List<InvestigationNote> notes = getInvestigationNotes(incidentId);
        for (InvestigationNote note : notes) {
            timeline.add(new InvestigationTimelineItem(
                    note.getCreatedAt(),
                    "INVESTIGATION_NOTE_ADDED",
                    note.getAnalystUsername(),
                    note.getNotes(),
                    note.getEvidenceData()
            ));
        }

        // 3. Automated / Manual Threat Responses
        List<ThreatResponse> responses = threatResponseService.getResponseHistory(incidentId, null, "ALL");
        for (ThreatResponse tr : responses) {
            timeline.add(new InvestigationTimelineItem(
                    tr.getExecutedAt(),
                    "THREAT_RESPONSE_" + tr.getStatus(),
                    "DEFENSE_ENGINE",
                    tr.getActionTaken() + " on " + tr.getTargetIdentifier() + " (" + tr.getStatus() + ")",
                    tr.getDetails()
            ));
        }

        // 4. Correlated Activity Logs
        String sqlLogs = "SELECT id, username, action, details, created_at FROM activity_log " +
                "WHERE (details LIKE ? OR details LIKE ? OR details LIKE ?) " +
                "AND action IN ('INVESTIGATOR_ASSIGNED', 'INVESTIGATION_STARTED', 'ROOT_CAUSE_UPDATED', 'INCIDENT_RESOLVED', 'INCIDENT_CLOSED') " +
                "ORDER BY id ASC";

        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sqlLogs)) {

            pstmt.setString(1, "%#" + incidentId + "%");
            pstmt.setString(2, "%incident " + incidentId + "%");
            pstmt.setString(3, "%Incident #" + incidentId + "%");

            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    long logEpoch = parseTimestampToEpoch(rs.getString("created_at"));
                    timeline.add(new InvestigationTimelineItem(
                            logEpoch,
                            rs.getString("action"),
                            rs.getString("username"),
                            rs.getString("details"),
                            null
                    ));
                }
            }
        } catch (SQLException e) {
            System.err.println("[IncidentInvestigationService] Error querying timeline activity logs: " + e.getMessage());
        }

        // Sort chronologically ascending
        timeline.sort(Comparator.comparingLong(InvestigationTimelineItem::getTimestamp));
        return timeline;
    }

    /**
     * Assigns an authorized analyst or admin as the lead investigator on an incident.
     * Transitions incident status to INVESTIGATING if currently OPEN.
     *
     * @param incidentId Target incident ID.
     * @param assignedAnalyst Username of the assigned investigator.
     * @param assignedBy Username of the authorizing manager or system.
     * @return Updated Incident object.
     */
    public synchronized Incident assignInvestigator(int incidentId, String assignedAnalyst, String assignedBy) {
        Incident incident = incidentService.getById(incidentId);
        if (incident == null) {
            throw new IllegalArgumentException("Incident #" + incidentId + " does not exist.");
        }
        if (assignedAnalyst == null || assignedAnalyst.trim().isEmpty()) {
            throw new IllegalArgumentException("Assigned analyst username cannot be empty.");
        }

        User user = userService.getUserByUsername(assignedAnalyst.trim());
        if (user == null) {
            throw new IllegalArgumentException("User '" + assignedAnalyst + "' does not exist.");
        }
        if (!"ANALYST".equalsIgnoreCase(user.getRole()) && !"ADMIN".equalsIgnoreCase(user.getRole())) {
            throw new IllegalArgumentException("User '" + assignedAnalyst + "' has role '" + user.getRole() +
                    "' and cannot be assigned as an investigator (role must be ANALYST or ADMIN).");
        }

        incident.setAssignedTo(user.getUsername());
        boolean wasOpen = "OPEN".equalsIgnoreCase(incident.getStatus());
        if (wasOpen) {
            incident.setStatus("INVESTIGATING");
        }

        String actor = (assignedBy != null && !assignedBy.trim().isEmpty()) ? assignedBy.trim() : "system";
        incidentService.update(incidentId, incident, actor);

        activityLogService.log(actor, "INVESTIGATOR_ASSIGNED",
                "Assigned investigator " + user.getUsername() + " to incident #" + incidentId);
        if (wasOpen) {
            activityLogService.log(actor, "INVESTIGATION_STARTED",
                    "Investigation initiated on incident #" + incidentId + " assigned to " + user.getUsername());
        }

        return incidentService.getById(incidentId);
    }

    /**
     * Updates the suspected root cause classification of an incident.
     *
     * @param incidentId Target incident ID.
     * @param category Root cause category (e.g. BRUTE_FORCE_ATTACK, CREDENTIAL_STUFFING).
     * @param explanation Descriptive rationale or forensic findings.
     * @param updatedBy Authorizing investigator username.
     * @return Updated Incident object.
     */
    public synchronized Incident updateRootCause(int incidentId, String category, String explanation, String updatedBy) {
        Incident incident = incidentService.getById(incidentId);
        if (incident == null) {
            throw new IllegalArgumentException("Incident #" + incidentId + " does not exist.");
        }
        if (category == null || category.trim().isEmpty()) {
            throw new IllegalArgumentException("Root cause category cannot be empty.");
        }

        String normCategory = category.trim().toUpperCase();
        incident.setRootCauseCategory(normCategory);

        String actor = (updatedBy != null && !updatedBy.trim().isEmpty()) ? updatedBy.trim() : "analyst";
        incidentService.update(incidentId, incident, actor);

        String details = "Updated root cause category to " + normCategory + " for incident #" + incidentId;
        if (explanation != null && !explanation.trim().isEmpty()) {
            details += " (" + explanation.trim() + ")";
        }
        activityLogService.log(actor, "ROOT_CAUSE_UPDATED", details);

        return incidentService.getById(incidentId);
    }

    /**
     * Resolves an incident with a technical resolution summary.
     */
    public synchronized boolean resolveIncident(int incidentId, String resolutionSummary, String resolvedBy) {
        return incidentService.resolveIncident(incidentId, resolutionSummary, resolvedBy);
    }

    /**
     * Produces a comprehensive case brief summarizing investigation metrics for dashboard triage.
     *
     * @param incidentId Target incident ID.
     * @return InvestigationSummary DTO.
     */
    public synchronized InvestigationSummary getInvestigationSummary(int incidentId) {
        Incident incident = incidentService.getById(incidentId);
        if (incident == null) {
            return null;
        }

        int totalNotes = 0;
        long latestTimestamp = 0;
        String sqlNotes = "SELECT COUNT(*), MAX(created_at) FROM incident_investigations WHERE incident_id = ?";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sqlNotes)) {
            pstmt.setInt(1, incidentId);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    totalNotes = rs.getInt(1);
                    latestTimestamp = rs.getLong(2);
                }
            }
        } catch (SQLException e) {
            System.err.println("[IncidentInvestigationService] Error querying summary notes: " + e.getMessage());
        }

        int totalThreatResponses = 0;
        String sqlResponses = "SELECT COUNT(*) FROM threat_responses WHERE incident_id = ?";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sqlResponses)) {
            pstmt.setInt(1, incidentId);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    totalThreatResponses = rs.getInt(1);
                }
            }
        } catch (SQLException e) {
            System.err.println("[IncidentInvestigationService] Error querying summary threat responses: " + e.getMessage());
        }

        return new InvestigationSummary(
                incident.getId(),
                incident.getTitle(),
                incident.getSeverity(),
                incident.getStatus(),
                incident.getAssignedTo(),
                incident.getRootCauseCategory(),
                totalNotes,
                totalThreatResponses,
                incident.getCreatedAt(),
                latestTimestamp,
                incident.getResolutionSummary()
        );
    }

    /**
     * Purges investigation records — for isolated test resets.
     */
    public synchronized void clearInvestigationHistory() {
        try (Connection conn = DatabaseManager.getConnection();
             Statement stmt = conn.createStatement()) {
            stmt.execute("DELETE FROM incident_investigations;");
        } catch (SQLException e) {
            System.err.println("[IncidentInvestigationService] Error clearing investigation history: " + e.getMessage());
        }
    }

    private long parseTimestampToEpoch(String timestampStr) {
        if (timestampStr == null || timestampStr.trim().isEmpty()) {
            return System.currentTimeMillis();
        }
        try {
            return LocalDateTime.parse(timestampStr.trim(), FORMATTER)
                    .atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
        } catch (Exception e) {
            return System.currentTimeMillis();
        }
    }
}
