package cybershield.dao;

import cybershield.model.Threat;
import cybershield.util.DBConnection;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * ThreatDAO — Handles all database operations for the threats table.
 * Implements GenericDAO, demonstrating POLYMORPHISM (same interface, threat-specific SQL).
 */
public class ThreatDAO implements GenericDAO<Threat> {

    /** Inserts a new threat into the database. */
    @Override
    public void add(Threat threat) {
        String sql = "INSERT INTO threats (threat_type, source_ip, target_system, severity, status) "
                   + "VALUES (?, ?, ?, ?, ?)";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, threat.getThreatType());
            ps.setString(2, threat.getSourceIp());
            ps.setString(3, threat.getTargetSystem());
            ps.setString(4, threat.getSeverity());
            ps.setString(5, threat.getStatus());
            ps.executeUpdate();
            System.out.println("Threat added: " + threat.getThreatType());

        } catch (SQLException e) {
            System.out.println("Error adding threat: " + e.getMessage());
        }
    }

    /** Updates an existing threat in the database. */
    @Override
    public void update(Threat threat) {
        String sql = "UPDATE threats SET threat_type=?, source_ip=?, target_system=?, "
                   + "severity=?, status=? WHERE id=?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, threat.getThreatType());
            ps.setString(2, threat.getSourceIp());
            ps.setString(3, threat.getTargetSystem());
            ps.setString(4, threat.getSeverity());
            ps.setString(5, threat.getStatus());
            ps.setInt(6, threat.getId());
            ps.executeUpdate();
            System.out.println("Threat updated: id=" + threat.getId());

        } catch (SQLException e) {
            System.out.println("Error updating threat: " + e.getMessage());
        }
    }

    /** Deletes a threat by its id. */
    @Override
    public void delete(int id) {
        String sql = "DELETE FROM threats WHERE id = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, id);
            ps.executeUpdate();
            System.out.println("Threat deleted: id=" + id);

        } catch (SQLException e) {
            System.out.println("Error deleting threat: " + e.getMessage());
        }
    }

    /** Returns a single threat by id, or null if not found. */
    @Override
    public Threat getById(int id) {
        String sql = "SELECT * FROM threats WHERE id = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return extractThreat(rs);
                }
            }

        } catch (SQLException e) {
            System.out.println("Error fetching threat: " + e.getMessage());
        }
        return null;
    }

    /** Returns all threats from the database. */
    @Override
    public List<Threat> getAll() {
        List<Threat> threats = new ArrayList<>();
        String sql = "SELECT * FROM threats ORDER BY detected_at DESC";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {

            while (rs.next()) {
                threats.add(extractThreat(rs));
            }

        } catch (SQLException e) {
            System.out.println("Error fetching threats: " + e.getMessage());
        }
        return threats;
    }

    /** Helper method — builds a Threat object from the current row of a ResultSet. */
    private Threat extractThreat(ResultSet rs) throws SQLException {
        return new Threat(
            rs.getInt("id"),
            rs.getString("threat_type"),
            rs.getString("source_ip"),
            rs.getString("target_system"),
            rs.getString("severity"),
            rs.getString("status"),
            rs.getTimestamp("detected_at")
        );
    }

    /**
     * Updates only the status column of a threat (DETECTED, INVESTIGATING, RESOLVED).
     * Used by table context menu and details action buttons.
     */
    public void updateStatus(int id, String newStatus) {
        String sql = "UPDATE threats SET status = ? WHERE id = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, newStatus);
            ps.setInt(2, id);
            ps.executeUpdate();
            System.out.println("Threat status updated: id=" + id + " -> " + newStatus);

        } catch (SQLException e) {
            System.out.println("Error updating threat status: " + e.getMessage());
        }
    }

    /**
     * Returns all threats matching a specific status.
     */
    public List<Threat> getByStatus(String status) {
        List<Threat> list = new ArrayList<>();
        String sql = "SELECT * FROM threats WHERE status = ? ORDER BY detected_at DESC";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, status);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    list.add(extractThreat(rs));
                }
            }

        } catch (SQLException e) {
            System.out.println("Error fetching threats by status: " + e.getMessage());
        }
        return list;
    }

    /**
     * Searches threats across threat type, source IP, or target system.
     */
    public List<Threat> search(String keyword) {
        List<Threat> list = new ArrayList<>();
        String sql = "SELECT * FROM threats WHERE threat_type LIKE ? OR source_ip LIKE ? "
                   + "OR target_system LIKE ? ORDER BY detected_at DESC";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            String term = "%" + keyword + "%";
            ps.setString(1, term);
            ps.setString(2, term);
            ps.setString(3, term);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    list.add(extractThreat(rs));
                }
            }

        } catch (SQLException e) {
            System.out.println("Error searching threats: " + e.getMessage());
        }
        return list;
    }

    /**
     * Returns a list of distinct target system names for building the Network Map tree.
     */
    public List<String> getDistinctTargetSystems() {
        List<String> systems = new ArrayList<>();
        String sql = "SELECT DISTINCT target_system FROM threats ORDER BY target_system ASC";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {

            while (rs.next()) {
                systems.add(rs.getString("target_system"));
            }

        } catch (SQLException e) {
            System.out.println("Error fetching distinct target systems: " + e.getMessage());
        }
        return systems;
    }

    /**
     * Returns threats detected within the last N days.
     */
    public List<Threat> getRecentThreats(int days) {
        List<Threat> list = new ArrayList<>();
        String sql = "SELECT * FROM threats WHERE detected_at >= DATE_SUB(NOW(), INTERVAL ? DAY) "
                   + "ORDER BY detected_at DESC";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, days);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    list.add(extractThreat(rs));
                }
            }

        } catch (SQLException e) {
            System.out.println("Error fetching recent threats: " + e.getMessage());
        }
        return list;
    }
}
