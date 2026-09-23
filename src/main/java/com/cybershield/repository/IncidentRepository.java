package com.cybershield.repository;

import com.cybershield.exception.DatabaseOperationException;
import com.cybershield.model.Incident;
import com.cybershield.model.ResponseAction;
import com.cybershield.model.Threat;
import com.cybershield.model.enums.IncidentStatus;
import com.cybershield.model.enums.Severity;
import com.cybershield.util.DateTimeUtils;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * Repository for managing Incident entities and their composed collections in SQLite.
 * Demonstrates Composition and relational joins/hydration.
 */
public class IncidentRepository {

    private final DatabaseManager databaseManager;
    private final ThreatRepository threatRepository;
    private final ResponseActionRepository actionRepository;

    public IncidentRepository() {
        this.databaseManager = DatabaseManager.getInstance();
        this.threatRepository = new ThreatRepository(databaseManager);
        this.actionRepository = new ResponseActionRepository(databaseManager);
    }

    public IncidentRepository(DatabaseManager databaseManager, ThreatRepository threatRepository, ResponseActionRepository actionRepository) {
        this.databaseManager = databaseManager;
        this.threatRepository = threatRepository;
        this.actionRepository = actionRepository;
    }

    public Incident save(Incident incident) throws DatabaseOperationException {
        String sql = """
            INSERT INTO incidents (incident_id, title, description, severity, status, threat_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """;
        try (Connection conn = databaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {

            pstmt.setString(1, incident.getIncidentId());
            pstmt.setString(2, incident.getTitle());
            pstmt.setString(3, incident.getDescription());
            pstmt.setString(4, incident.getSeverity().name());
            pstmt.setString(5, incident.getStatus().name());
            pstmt.setString(6, incident.getAssociatedThreat() != null ? incident.getAssociatedThreat().getThreatId() : null);
            pstmt.setString(7, DateTimeUtils.format(incident.getCreatedAt()));
            pstmt.setString(8, DateTimeUtils.format(incident.getUpdatedAt()));

            int affected = pstmt.executeUpdate();
            if (affected > 0) {
                try (ResultSet keys = pstmt.getGeneratedKeys()) {
                    if (keys.next()) {
                        incident.setId(keys.getInt(1));
                    }
                }
            }
            return incident;
        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to save incident: " + incident.getIncidentId(), e);
        }
    }

    public void update(Incident incident) throws DatabaseOperationException {
        String sql = """
            UPDATE incidents
            SET title = ?, description = ?, severity = ?, status = ?, updated_at = ?
            WHERE incident_id = ?;
        """;
        try (Connection conn = databaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, incident.getTitle());
            pstmt.setString(2, incident.getDescription());
            pstmt.setString(3, incident.getSeverity().name());
            pstmt.setString(4, incident.getStatus().name());
            pstmt.setString(5, DateTimeUtils.format(incident.getUpdatedAt()));
            pstmt.setString(6, incident.getIncidentId());

            pstmt.executeUpdate();
        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to update incident: " + incident.getIncidentId(), e);
        }
    }

    public Incident findById(String incidentId) throws DatabaseOperationException {
        String sql = "SELECT * FROM incidents WHERE incident_id = ?";
        try (Connection conn = databaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, incidentId);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return hydrateIncident(rs);
                }
            }
            return null;
        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to find incident by ID: " + incidentId, e);
        }
    }

    public List<Incident> findAll() throws DatabaseOperationException {
        List<Incident> list = new ArrayList<>();
        String sql = "SELECT * FROM incidents ORDER BY id DESC";
        try (Connection conn = databaseManager.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                list.add(hydrateIncident(rs));
            }
            return list;
        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to list all incidents", e);
        }
    }

    public int count() throws DatabaseOperationException {
        String sql = "SELECT COUNT(*) FROM incidents";
        try (Connection conn = databaseManager.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            if (rs.next()) {
                return rs.getInt(1);
            }
            return 0;
        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to count incidents", e);
        }
    }

    public int countByStatus(IncidentStatus status) throws DatabaseOperationException {
        String sql = "SELECT COUNT(*) FROM incidents WHERE status = ?";
        try (Connection conn = databaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, status.name());
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt(1);
                }
            }
            return 0;
        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to count incidents by status: " + status, e);
        }
    }

    private Incident hydrateIncident(ResultSet rs) throws SQLException, DatabaseOperationException {
        Incident incident = new Incident();
        incident.setId(rs.getInt("id"));
        incident.setIncidentId(rs.getString("incident_id"));
        incident.setTitle(rs.getString("title"));
        incident.setDescription(rs.getString("description"));
        incident.setSeverity(Severity.fromString(rs.getString("severity")));
        incident.setStatus(IncidentStatus.fromString(rs.getString("status")));
        incident.setCreatedAt(DateTimeUtils.parse(rs.getString("created_at")));
        incident.setUpdatedAt(DateTimeUtils.parse(rs.getString("updated_at")));

        String threatId = rs.getString("threat_id");
        if (threatId != null && !threatId.isEmpty()) {
            Threat threat = threatRepository.findById(threatId);
            incident.setAssociatedThreat(threat);
        }

        // Hydrate composed list of actions
        List<ResponseAction> actions = actionRepository.findByIncidentId(incident.getIncidentId());
        for (ResponseAction action : actions) {
            incident.addResponseAction(action);
        }

        return incident;
    }
}
