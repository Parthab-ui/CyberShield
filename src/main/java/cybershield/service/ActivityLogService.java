package cybershield.service;

import cybershield.database.DatabaseManager;
import cybershield.model.ActivityLog;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * ActivityLogService — Records system audit events and tracks user interactions.
 * Demonstrates: Non-repudiation, activity history persistence, and audit query capabilities.
 */
public class ActivityLogService {

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /**
     * Records a user action into the persistent activity log.
     */
    public boolean log(String username, String action, String details) {
        String now = LocalDateTime.now().format(FORMATTER);
        String sql = "INSERT INTO activity_log (username, action, details, created_at) VALUES (?, ?, ?, ?)";

        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, username != null ? username : "system");
            pstmt.setString(2, action != null ? action : "ACTION");
            pstmt.setString(3, details != null ? details : "");
            pstmt.setString(4, now);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            System.err.println("[ActivityLogService] Failed to record activity: " + e.getMessage());
            return false;
        }
    }

    /**
     * Retrieves recent activity records ordered newest first.
     */
    public List<ActivityLog> getAll(int limit) {
        List<ActivityLog> list = new ArrayList<>();
        int effectiveLimit = limit > 0 ? limit : 100;
        String sql = "SELECT id, username, action, details, created_at FROM activity_log ORDER BY id DESC LIMIT ?";

        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, effectiveLimit);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    list.add(new ActivityLog(
                        rs.getInt("id"),
                        rs.getString("username"),
                        rs.getString("action"),
                        rs.getString("details"),
                        rs.getString("created_at")
                    ));
                }
            }
        } catch (SQLException e) {
            System.err.println("[ActivityLogService] Error fetching activity: " + e.getMessage());
        }
        return list;
    }
}
