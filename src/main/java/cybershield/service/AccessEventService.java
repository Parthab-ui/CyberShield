package cybershield.service;

import cybershield.database.DatabaseManager;
import cybershield.model.AccessEvent;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * AccessEventService — Manages security access logs and unauthorized access intrusion monitoring.
 * Demonstrates: Audit logging, threat simulation, and data retrieval for SOC review.
 */
public class AccessEventService {

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final Random RANDOM = new Random();

    /**
     * Records a new access event into the database.
     */
    public boolean recordEvent(String username, String source, String eventType, String result) {
        String now = LocalDateTime.now().format(FORMATTER);
        String sql = "INSERT INTO access_events (attempted_username, source, event_type, result, created_at) VALUES (?, ?, ?, ?, ?)";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, username != null ? username : "anonymous");
            pstmt.setString(2, source != null ? source : "UNKNOWN");
            pstmt.setString(3, eventType != null ? eventType : "SECURITY_EVENT");
            pstmt.setString(4, result != null ? result : "FAILED");
            pstmt.setString(5, now);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            System.err.println("[AccessEventService] Failed to record event: " + e.getMessage());
            return false;
        }
    }

    /**
     * Retrieves the most recent access events ordered newest first.
     */
    public List<AccessEvent> getAll(int limit) {
        List<AccessEvent> list = new ArrayList<>();
        int effectiveLimit = limit > 0 ? limit : 100;
        String sql = "SELECT id, attempted_username, source, event_type, result, created_at FROM access_events ORDER BY id DESC LIMIT ?";

        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, effectiveLimit);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    list.add(new AccessEvent(
                        rs.getInt("id"),
                        rs.getString("attempted_username"),
                        rs.getString("source"),
                        rs.getString("event_type"),
                        rs.getString("result"),
                        rs.getString("created_at")
                    ));
                }
            }
        } catch (SQLException e) {
            System.err.println("[AccessEventService] Error fetching events: " + e.getMessage());
        }
        return list;
    }

    /**
     * Generates a simulated unauthorized access or intrusion detection event.
     * Useful during viva evaluations to demonstrate dynamic threat logging and dashboard responsiveness.
     */
    public AccessEvent simulateThreat(String origin) {
        String[] usernames = {"admin_test", "oracle_svc", "guest99", "api_tester", "scanner_bot", "eval_user"};
        String[] types = {"SQL_INJECTION_SIM", "BRUTE_FORCE_BURST", "PATH_TRAVERSAL_SIM", "PORT_SCAN_PROBE", "ANOMALOUS_TOKEN"};
        String[] results = {"BLOCKED", "FAILED", "BLOCKED"};

        String selectedUser = usernames[RANDOM.nextInt(usernames.length)];
        String selectedType = types[RANDOM.nextInt(types.length)];
        String selectedResult = results[RANDOM.nextInt(results.length)];
        String sourceIp = "192.168.1." + (100 + RANDOM.nextInt(150)) + " (" + origin + ")";

        recordEvent(selectedUser, sourceIp, selectedType, selectedResult);

        return new AccessEvent(selectedUser, sourceIp, selectedType, selectedResult);
    }
}
