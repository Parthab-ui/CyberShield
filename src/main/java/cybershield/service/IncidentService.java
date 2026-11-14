package cybershield.service;

import cybershield.database.DatabaseManager;
import cybershield.model.Incident;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * IncidentService — Handles business logic and CRUD operations for security incidents.
 * Demonstrates: PreparedStatements, SQL filtering, transaction logging via ActivityLogService,
 * comprehensive input validation, and Review 3 Phase 5 forensic investigation lifecycle support.
 */
public class IncidentService {

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final Set<String> VALID_STATUSES = Set.of("OPEN", "INVESTIGATING", "RESOLVED", "CLOSED");
    private static final Set<String> VALID_SEVERITIES = Set.of("LOW", "MEDIUM", "HIGH", "CRITICAL");

    private final ActivityLogService activityLogService;

    public IncidentService() {
        this(new ActivityLogService());
    }

    public IncidentService(ActivityLogService activityLogService) {
        this.activityLogService = (activityLogService != null) ? activityLogService : new ActivityLogService();
    }

    public ActivityLogService getActivityLogService() {
        return activityLogService;
    }

    public static boolean isValidStatus(String status) {
        return status != null && VALID_STATUSES.contains(status.trim().toUpperCase());
    }

    public static boolean isValidSeverity(String severity) {
        return severity != null && VALID_SEVERITIES.contains(severity.trim().toUpperCase());
    }

    /**
     * Retrieves all incidents without filters.
     */
    public List<Incident> getAll() {
        return getAll(null, null, null);
    }

    /**
     * Retrieves all incidents matching optional search query, severity, and status filters.
     *
     * @param query Text search targeting title or description (optional).
     * @param severity Severity filter e.g. "CRITICAL", "HIGH" or "ALL" (optional).
     * @param status Status filter e.g. "OPEN", "INVESTIGATING", "RESOLVED", "CLOSED" or "ALL" (optional).
     */
    public List<Incident> getAll(String query, String severity, String status) {
        List<Incident> incidents = new ArrayList<>();
        StringBuilder sql = new StringBuilder(
                "SELECT id, title, description, severity, status, created_by, created_at, updated_at, " +
                "assigned_to, root_cause_category, resolution_summary FROM incidents WHERE 1=1 "
        );
        List<Object> params = new ArrayList<>();

        if (query != null && !query.trim().isEmpty()) {
            sql.append("AND (LOWER(title) LIKE ? OR LOWER(description) LIKE ?) ");
            String wild = "%" + query.trim().toLowerCase() + "%";
            params.add(wild);
            params.add(wild);
        }

        if (severity != null && !severity.trim().isEmpty() && !"ALL".equalsIgnoreCase(severity.trim())) {
            sql.append("AND UPPER(severity) = ? ");
            params.add(severity.trim().toUpperCase());
        }

        if (status != null && !status.trim().isEmpty() && !"ALL".equalsIgnoreCase(status.trim())) {
            sql.append("AND UPPER(status) = ? ");
            params.add(status.trim().toUpperCase());
        }

        sql.append("ORDER BY id DESC");

        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql.toString())) {

            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }

            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    incidents.add(mapResultSetToIncident(rs));
                }
            }
        } catch (SQLException e) {
            System.err.println("[IncidentService] Error retrieving incidents: " + e.getMessage());
        }
        return incidents;
    }

    /**
     * Retrieves a single incident by its unique ID.
     */
    public Incident getById(int id) {
        String sql = "SELECT id, title, description, severity, status, created_by, created_at, updated_at, " +
                "assigned_to, root_cause_category, resolution_summary FROM incidents WHERE id = ?";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, id);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return mapResultSetToIncident(rs);
                }
            }
        } catch (SQLException e) {
            System.err.println("[IncidentService] Error finding incident by id: " + e.getMessage());
        }
        return null;
    }

    /**
     * Creates a new incident record in SQLite with input validation and audit logging.
     */
    public Incident create(Incident incident, String username) {
        if (incident == null || incident.getTitle() == null || incident.getTitle().trim().isEmpty()) {
            throw new IllegalArgumentException("Incident title is required.");
        }

        String now = LocalDateTime.now().format(FORMATTER);
        String sql = "INSERT INTO incidents (title, description, severity, status, created_by, created_at, updated_at, " +
                "assigned_to, root_cause_category, resolution_summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        String author = (username != null && !username.trim().isEmpty()) ? username.trim() : "system";
        String severity = normalizeSeverity(incident.getSeverity());
        String status = normalizeStatus(incident.getStatus());
        String desc = incident.getDescription() != null ? incident.getDescription().trim() : "";
        String assignedTo = incident.getAssignedTo();
        String rootCause = incident.getRootCauseCategory();
        String resolution = incident.getResolutionSummary();

        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {

            pstmt.setString(1, incident.getTitle().trim());
            pstmt.setString(2, desc);
            pstmt.setString(3, severity);
            pstmt.setString(4, status);
            pstmt.setString(5, author);
            pstmt.setString(6, now);
            pstmt.setString(7, now);
            pstmt.setString(8, assignedTo);
            pstmt.setString(9, rootCause);
            pstmt.setString(10, resolution);

            int affected = pstmt.executeUpdate();
            if (affected > 0) {
                try (ResultSet generatedKeys = pstmt.getGeneratedKeys()) {
                    if (generatedKeys.next()) {
                        int newId = generatedKeys.getInt(1);
                        incident.setId(newId);
                        incident.setCreatedAt(now);
                        incident.setUpdatedAt(now);
                        incident.setCreatedBy(author);
                        incident.setSeverity(severity);
                        incident.setStatus(status);

                        // Audit log
                        activityLogService.log(author, "INCIDENT_CREATED", "Created incident #" + newId + ": " + incident.getTitle());
                        return incident;
                    }
                }
            }
        } catch (SQLException e) {
            System.err.println("[IncidentService] Error creating incident: " + e.getMessage());
        }
        return null;
    }

    /**
     * Updates an existing incident record in SQLite.
     * Enforces strict status validation (rejects invalid statuses like IN_PROGRESS).
     */
    public boolean update(int id, Incident updated, String username) {
        if (updated == null || updated.getTitle() == null || updated.getTitle().trim().isEmpty()) {
            throw new IllegalArgumentException("Incident title cannot be empty.");
        }

        String now = LocalDateTime.now().format(FORMATTER);
        String severity = normalizeSeverity(updated.getSeverity());
        String status = normalizeStatus(updated.getStatus());
        String desc = updated.getDescription() != null ? updated.getDescription().trim() : "";
        String actor = (username != null && !username.trim().isEmpty()) ? username.trim() : "user";

        String sql = "UPDATE incidents SET title = ?, description = ?, severity = ?, status = ?, updated_at = ?, " +
                "assigned_to = ?, root_cause_category = ?, resolution_summary = ? WHERE id = ?";

        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, updated.getTitle().trim());
            pstmt.setString(2, desc);
            pstmt.setString(3, severity);
            pstmt.setString(4, status);
            pstmt.setString(5, now);
            pstmt.setString(6, updated.getAssignedTo());
            pstmt.setString(7, updated.getRootCauseCategory());
            pstmt.setString(8, updated.getResolutionSummary());
            pstmt.setInt(9, id);

            int affected = pstmt.executeUpdate();
            if (affected > 0) {
                activityLogService.log(actor, "INCIDENT_UPDATED", "Updated incident #" + id + " to [" + severity + "/" + status + "]");
                if ("CLOSED".equalsIgnoreCase(status)) {
                    activityLogService.log(actor, "INCIDENT_CLOSED", "Closed incident #" + id + " (" + updated.getTitle() + ")");
                }
                return true;
            }
        } catch (SQLException e) {
            System.err.println("[IncidentService] Error updating incident: " + e.getMessage());
        }
        return false;
    }

    /**
     * Resolves an incident with a documented technical resolution summary.
     * Transitions status to RESOLVED, updates timestamp, and writes an audit log.
     *
     * @param incidentId Target incident ID.
     * @param resolutionSummary Technical resolution narrative.
     * @param resolvedBy Authorizing analyst or admin.
     * @return true if successfully updated, false otherwise.
     */
    public boolean resolveIncident(int incidentId, String resolutionSummary, String resolvedBy) {
        if (resolutionSummary == null || resolutionSummary.trim().isEmpty()) {
            throw new IllegalArgumentException("Resolution summary cannot be empty.");
        }
        Incident existing = getById(incidentId);
        if (existing == null) {
            return false;
        }

        String now = LocalDateTime.now().format(FORMATTER);
        String actor = (resolvedBy != null && !resolvedBy.trim().isEmpty()) ? resolvedBy.trim() : "analyst";
        String sql = "UPDATE incidents SET status = 'RESOLVED', resolution_summary = ?, updated_at = ? WHERE id = ?";

        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, resolutionSummary.trim());
            pstmt.setString(2, now);
            pstmt.setInt(3, incidentId);

            int affected = pstmt.executeUpdate();
            if (affected > 0) {
                activityLogService.log(actor, "INCIDENT_RESOLVED",
                        "Resolved incident #" + incidentId + ": " + resolutionSummary.trim());
                return true;
            }
        } catch (SQLException e) {
            System.err.println("[IncidentService] Error resolving incident: " + e.getMessage());
        }
        return false;
    }

    /**
     * Deletes an incident record from SQLite by ID.
     */
    public boolean delete(int id, String username) {
        Incident existing = getById(id);
        if (existing == null) {
            return false;
        }

        try (Connection conn = DatabaseManager.getConnection()) {
            // Explicit cascade cleanup for database integrity
            try (PreparedStatement cleanInv = conn.prepareStatement("DELETE FROM incident_investigations WHERE incident_id = ?")) {
                cleanInv.setInt(1, id);
                cleanInv.executeUpdate();
            }
            try (PreparedStatement cleanTr = conn.prepareStatement("UPDATE threat_responses SET incident_id = NULL WHERE incident_id = ?")) {
                cleanTr.setInt(1, id);
                cleanTr.executeUpdate();
            }

            try (PreparedStatement pstmt = conn.prepareStatement("DELETE FROM incidents WHERE id = ?")) {
                pstmt.setInt(1, id);
                int affected = pstmt.executeUpdate();
                if (affected > 0) {
                    String actor = (username != null) ? username : "admin";
                    activityLogService.log(actor, "INCIDENT_DELETED", "Deleted incident #" + id + " (" + existing.getTitle() + ")");
                    return true;
                }
            }
        } catch (SQLException e) {
            System.err.println("[IncidentService] Error deleting incident: " + e.getMessage());
        }
        return false;
    }

    private String normalizeSeverity(String severity) {
        if (severity == null || severity.trim().isEmpty()) return "MEDIUM";
        String s = severity.trim().toUpperCase();
        if (VALID_SEVERITIES.contains(s)) {
            return s;
        }
        throw new IllegalArgumentException("Invalid incident severity: " + severity + ". Allowed: LOW, MEDIUM, HIGH, CRITICAL");
    }

    private String normalizeStatus(String status) {
        if (status == null || status.trim().isEmpty()) return "OPEN";
        String s = status.trim().toUpperCase();
        if (VALID_STATUSES.contains(s)) {
            return s;
        }
        throw new IllegalArgumentException("Invalid incident status: " + status + ". Allowed: OPEN, INVESTIGATING, RESOLVED, CLOSED");
    }

    private Incident mapResultSetToIncident(ResultSet rs) throws SQLException {
        return new Incident(
                rs.getInt("id"),
                rs.getString("title"),
                rs.getString("description"),
                rs.getString("severity"),
                rs.getString("status"),
                rs.getString("created_by"),
                rs.getString("created_at"),
                rs.getString("updated_at"),
                rs.getString("assigned_to"),
                rs.getString("root_cause_category"),
                rs.getString("resolution_summary")
        );
    }
}
