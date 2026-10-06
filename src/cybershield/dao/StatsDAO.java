package cybershield.dao;

import cybershield.util.DBConnection;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * StatsDAO — Provides read-only count queries for the Dashboard.
 * All SQL lives here; no SQL is placed in GUI classes.
 * Each method runs one COUNT query and returns the result as an integer.
 */
public class StatsDAO {

    /** Returns the total number of threats in the database. */
    public int countThreats() {
        return runCountQuery("SELECT COUNT(*) FROM threats");
    }

    /** Returns the number of threats that have a specific severity (e.g. "CRITICAL"). */
    public int countThreatsBySeverity(String severity) {
        String sql = "SELECT COUNT(*) FROM threats WHERE severity = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, severity);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt(1);
                }
            }

        } catch (SQLException e) {
            System.out.println("Error counting threats by severity: " + e.getMessage());
        }
        return 0;
    }

    /** Returns the number of incidents whose status is OPEN or IN_PROGRESS. */
    public int countOpenIncidents() {
        return runCountQuery(
            "SELECT COUNT(*) FROM incidents WHERE status IN ('OPEN', 'IN_PROGRESS')"
        );
    }

    /** Returns the total number of blocked IP addresses. */
    public int countBlockedIPs() {
        return runCountQuery("SELECT COUNT(*) FROM blocked_ips");
    }

    /** Returns the number of threats with status RESOLVED. */
    public int countResolvedThreats() {
        return runCountQuery("SELECT COUNT(*) FROM threats WHERE status = 'RESOLVED'");
    }

    /** Returns the number of incidents with status CLOSED. */
    public int countClosedIncidents() {
        return runCountQuery("SELECT COUNT(*) FROM incidents WHERE status = 'CLOSED'");
    }

    /** Returns the total number of incidents regardless of status. */
    public int countTotalIncidents() {
        return runCountQuery("SELECT COUNT(*) FROM incidents");
    }

    /**
     * Returns a Map where each key is a severity label and each value is the count.
     * The map is ordered: LOW -> MEDIUM -> HIGH -> CRITICAL.
     * Used by ThreatGraphPanel to draw the bar chart.
     */
    public Map<String, Integer> countThreatsBySeverityMap() {
        // LinkedHashMap preserves insertion order so the bars always appear in this order
        Map<String, Integer> map = new LinkedHashMap<>();
        map.put("LOW",      countThreatsBySeverity("LOW"));
        map.put("MEDIUM",   countThreatsBySeverity("MEDIUM"));
        map.put("HIGH",     countThreatsBySeverity("HIGH"));
        map.put("CRITICAL", countThreatsBySeverity("CRITICAL"));
        return map;
    }

    /**
     * Helper method — runs a simple COUNT query that takes no parameters.
     * Returns 0 on any error.
     */
    private int runCountQuery(String sql) {
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {

            if (rs.next()) {
                return rs.getInt(1);
            }

        } catch (SQLException e) {
            System.out.println("Stats query failed: " + e.getMessage());
        }
        return 0;
    }
}
