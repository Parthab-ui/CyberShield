package com.cybershield.repository;

import com.cybershield.exception.DatabaseOperationException;
import com.cybershield.model.SecurityEvent;
import com.cybershield.model.enums.EventType;
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
 * Repository for managing raw security telemetry events in SQLite.
 * Demonstrates batch database transactions and parameterized SQL querying.
 */
public class SecurityEventRepository {

    private final DatabaseManager databaseManager;

    public SecurityEventRepository() {
        this.databaseManager = DatabaseManager.getInstance();
    }

    public SecurityEventRepository(DatabaseManager databaseManager) {
        this.databaseManager = databaseManager;
    }

    public SecurityEvent save(SecurityEvent event) throws DatabaseOperationException {
        String sql = """
            INSERT INTO security_events (event_id, timestamp, event_type, source_ip, username, description, raw_payload, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """;
        try (Connection conn = databaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {

            pstmt.setString(1, event.getEventId());
            pstmt.setString(2, DateTimeUtils.format(event.getTimestamp()));
            pstmt.setString(3, event.getEventType().name());
            pstmt.setString(4, event.getSourceIp());
            pstmt.setString(5, event.getUsername());
            pstmt.setString(6, event.getDescription());
            pstmt.setString(7, event.getRawPayload());
            pstmt.setString(8, event.getSeverity().name());

            int affected = pstmt.executeUpdate();
            if (affected > 0) {
                try (ResultSet keys = pstmt.getGeneratedKeys()) {
                    if (keys.next()) {
                        event.setId(keys.getInt(1));
                    }
                }
            }
            return event;
        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to save security event: " + event.getEventId(), e);
        }
    }

    public void saveAll(List<SecurityEvent> events) throws DatabaseOperationException {
        if (events == null || events.isEmpty()) return;

        String sql = """
            INSERT INTO security_events (event_id, timestamp, event_type, source_ip, username, description, raw_payload, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """;
        try (Connection conn = databaseManager.getConnection()) {
            conn.setAutoCommit(false);
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                for (SecurityEvent event : events) {
                    pstmt.setString(1, event.getEventId());
                    pstmt.setString(2, DateTimeUtils.format(event.getTimestamp()));
                    pstmt.setString(3, event.getEventType().name());
                    pstmt.setString(4, event.getSourceIp());
                    pstmt.setString(5, event.getUsername());
                    pstmt.setString(6, event.getDescription());
                    pstmt.setString(7, event.getRawPayload());
                    pstmt.setString(8, event.getSeverity().name());
                    pstmt.addBatch();
                }
                pstmt.executeBatch();
                conn.commit();
            } catch (SQLException ex) {
                conn.rollback();
                throw ex;
            }
        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to save batch security events: " + e.getMessage(), e);
        }
    }

    public List<SecurityEvent> findAll(int limit) throws DatabaseOperationException {
        List<SecurityEvent> list = new ArrayList<>();
        String sql = "SELECT id, event_id, timestamp, event_type, source_ip, username, description, raw_payload, severity " +
                     "FROM security_events ORDER BY id DESC LIMIT ?";
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
            throw new DatabaseOperationException("Failed to fetch security events", e);
        }
    }

    public List<SecurityEvent> search(String keyword) throws DatabaseOperationException {
        List<SecurityEvent> list = new ArrayList<>();
        String sql = """
            SELECT id, event_id, timestamp, event_type, source_ip, username, description, raw_payload, severity
            FROM security_events
            WHERE source_ip LIKE ? OR username LIKE ? OR description LIKE ? OR event_type LIKE ?
            ORDER BY id DESC LIMIT 100;
        """;
        try (Connection conn = databaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            String pattern = "%" + (keyword != null ? keyword.trim() : "") + "%";
            pstmt.setString(1, pattern);
            pstmt.setString(2, pattern);
            pstmt.setString(3, pattern);
            pstmt.setString(4, pattern);

            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    list.add(mapRow(rs));
                }
            }
            return list;
        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to search security events: " + keyword, e);
        }
    }

    public int count() throws DatabaseOperationException {
        String sql = "SELECT COUNT(*) FROM security_events";
        try (Connection conn = databaseManager.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            if (rs.next()) {
                return rs.getInt(1);
            }
            return 0;
        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to count security events", e);
        }
    }

    private SecurityEvent mapRow(ResultSet rs) throws SQLException {
        SecurityEvent event = new SecurityEvent();
        event.setId(rs.getInt("id"));
        event.setEventId(rs.getString("event_id"));
        event.setTimestamp(DateTimeUtils.parse(rs.getString("timestamp")));
        event.setEventType(EventType.fromString(rs.getString("event_type")));
        event.setSourceIp(rs.getString("source_ip"));
        event.setUsername(rs.getString("username"));
        event.setDescription(rs.getString("description"));
        event.setRawPayload(rs.getString("raw_payload"));
        event.setSeverity(Severity.fromString(rs.getString("severity")));
        return event;
    }
}
