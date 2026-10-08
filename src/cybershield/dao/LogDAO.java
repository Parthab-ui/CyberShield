package cybershield.dao;

import cybershield.model.LogEntry;
import cybershield.util.DBConnection;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

/**
 * LogDAO — Handles all database operations for the logs table.
 * Implements GenericDAO, demonstrating POLYMORPHISM (same interface, log-specific SQL).
 */
public class LogDAO implements GenericDAO<LogEntry> {

    /** Inserts a new log entry into the database. */
    @Override
    public void add(LogEntry log) {
        String sql = "INSERT INTO logs (user_id, action) VALUES (?, ?)";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, log.getUserId());
            ps.setString(2, log.getAction());
            ps.executeUpdate();
            System.out.println("Log added: " + log.getAction());

        } catch (SQLException e) {
            System.out.println("Error adding log: " + e.getMessage());
        }
    }

    /** Updates an existing log entry. */
    @Override
    public void update(LogEntry log) {
        String sql = "UPDATE logs SET user_id=?, action=? WHERE id=?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, log.getUserId());
            ps.setString(2, log.getAction());
            ps.setInt(3, log.getId());
            ps.executeUpdate();
            System.out.println("Log updated: id=" + log.getId());

        } catch (SQLException e) {
            System.out.println("Error updating log: " + e.getMessage());
        }
    }

    /** Deletes a log entry by its id. */
    @Override
    public void delete(int id) {
        String sql = "DELETE FROM logs WHERE id = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, id);
            ps.executeUpdate();
            System.out.println("Log deleted: id=" + id);

        } catch (SQLException e) {
            System.out.println("Error deleting log: " + e.getMessage());
        }
    }

    /** Returns a single log entry by id, or null if not found. */
    @Override
    public LogEntry getById(int id) {
        String sql = "SELECT * FROM logs WHERE id = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return extractLogEntry(rs);
                }
            }

        } catch (SQLException e) {
            System.out.println("Error fetching log: " + e.getMessage());
        }
        return null;
    }

    /** Returns all log entries from the database. */
    @Override
    public List<LogEntry> getAll() {
        List<LogEntry> logs = new ArrayList<>();
        String sql = "SELECT * FROM logs ORDER BY log_time DESC";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {

            while (rs.next()) {
                logs.add(extractLogEntry(rs));
            }

        } catch (SQLException e) {
            System.out.println("Error fetching logs: " + e.getMessage());
        }
        return logs;
    }

    /** Helper method — builds a LogEntry object from the current row of a ResultSet. */
    private LogEntry extractLogEntry(ResultSet rs) throws SQLException {
        return new LogEntry(
            rs.getInt("id"),
            rs.getInt("user_id"),
            rs.getString("action"),
            rs.getTimestamp("log_time")
        );
    }

    /**
     * Retrieves audit log records recorded between two timestamps.
     */
    public List<LogEntry> getLogsBetween(Timestamp start, Timestamp end) {
        List<LogEntry> logs = new ArrayList<>();
        String sql = "SELECT * FROM logs WHERE log_time BETWEEN ? AND ? ORDER BY log_time DESC";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setTimestamp(1, start);
            ps.setTimestamp(2, end);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    logs.add(extractLogEntry(rs));
                }
            }

        } catch (SQLException e) {
            System.out.println("Error fetching logs between dates: " + e.getMessage());
        }
        return logs;
    }

    /**
     * Retrieves audit log records from the past N days.
     */
    public List<LogEntry> getRecentLogs(int days) {
        List<LogEntry> logs = new ArrayList<>();
        String sql = "SELECT * FROM logs WHERE log_time >= ? ORDER BY log_time DESC";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            long cutoffMillis = System.currentTimeMillis() - (days * 86400000L);
            ps.setTimestamp(1, new Timestamp(cutoffMillis));
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    logs.add(extractLogEntry(rs));
                }
            }

        } catch (SQLException e) {
            System.out.println("Error fetching recent logs: " + e.getMessage());
        }
        return logs;
    }
}
