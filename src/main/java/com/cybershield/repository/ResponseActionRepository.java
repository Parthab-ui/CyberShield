package com.cybershield.repository;

import com.cybershield.exception.DatabaseOperationException;
import com.cybershield.model.ResponseAction;
import com.cybershield.model.enums.ResponseActionType;
import com.cybershield.util.DateTimeUtils;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Repository for storing and retrieving simulated incident response actions.
 */
public class ResponseActionRepository {

    private final DatabaseManager databaseManager;

    public ResponseActionRepository() {
        this.databaseManager = DatabaseManager.getInstance();
    }

    public ResponseActionRepository(DatabaseManager databaseManager) {
        this.databaseManager = databaseManager;
    }

    public ResponseAction save(ResponseAction action) throws DatabaseOperationException {
        String sql = """
            INSERT INTO response_actions (action_id, incident_id, action_type, target, executed_by, status, details, executed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """;
        try (Connection conn = databaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {

            pstmt.setString(1, action.getActionId());
            pstmt.setString(2, action.getIncidentId());
            pstmt.setString(3, action.getActionType().name());
            pstmt.setString(4, action.getTarget());
            pstmt.setString(5, action.getExecutedBy());
            pstmt.setString(6, action.getStatus());
            pstmt.setString(7, action.getDetails());
            pstmt.setString(8, DateTimeUtils.format(action.getExecutedAt()));

            int affected = pstmt.executeUpdate();
            if (affected > 0) {
                try (ResultSet keys = pstmt.getGeneratedKeys()) {
                    if (keys.next()) {
                        action.setId(keys.getInt(1));
                    }
                }
            }
            return action;
        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to save response action: " + action.getActionId(), e);
        }
    }

    public List<ResponseAction> findByIncidentId(String incidentId) throws DatabaseOperationException {
        List<ResponseAction> list = new ArrayList<>();
        String sql = "SELECT * FROM response_actions WHERE incident_id = ? ORDER BY id ASC";
        try (Connection conn = databaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, incidentId);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    list.add(mapRow(rs));
                }
            }
            return list;
        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to query actions for incident: " + incidentId, e);
        }
    }

    public List<ResponseAction> findAll(int limit) throws DatabaseOperationException {
        List<ResponseAction> list = new ArrayList<>();
        String sql = "SELECT * FROM response_actions ORDER BY id DESC LIMIT ?";
        try (Connection conn = databaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, limit > 0 ? limit : 200);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    list.add(mapRow(rs));
                }
            }
            return list;
        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to list all response actions", e);
        }
    }

    public int count() throws DatabaseOperationException {
        String sql = "SELECT COUNT(*) FROM response_actions";
        try (Connection conn = databaseManager.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            if (rs.next()) {
                return rs.getInt(1);
            }
            return 0;
        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to count response actions", e);
        }
    }

    public Map<ResponseActionType, Integer> getCountsByType() throws DatabaseOperationException {
        Map<ResponseActionType, Integer> counts = new HashMap<>();
        String sql = "SELECT action_type, COUNT(*) FROM response_actions GROUP BY action_type";
        try (Connection conn = databaseManager.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                ResponseActionType type = ResponseActionType.fromString(rs.getString(1));
                counts.put(type, rs.getInt(2));
            }
            return counts;
        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to aggregate action counts by type", e);
        }
    }

    private ResponseAction mapRow(ResultSet rs) throws SQLException {
        ResponseAction a = new ResponseAction();
        a.setId(rs.getInt("id"));
        a.setActionId(rs.getString("action_id"));
        a.setIncidentId(rs.getString("incident_id"));
        a.setActionType(ResponseActionType.fromString(rs.getString("action_type")));
        a.setTarget(rs.getString("target"));
        a.setExecutedBy(rs.getString("executed_by"));
        a.setStatus(rs.getString("status"));
        a.setDetails(rs.getString("details"));
        a.setExecutedAt(DateTimeUtils.parse(rs.getString("executed_at")));
        return a;
    }
}
