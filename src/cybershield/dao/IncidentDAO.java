package cybershield.dao;

import cybershield.model.Incident;
import cybershield.util.DBConnection;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.List;

/**
 * IncidentDAO — Handles all database operations for the incidents table.
 * Implements GenericDAO, demonstrating POLYMORPHISM (same interface, incident-specific SQL).
 */
public class IncidentDAO implements GenericDAO<Incident> {

    /** Inserts a new incident into the database. */
    @Override
    public void add(Incident incident) {
        String sql = "INSERT INTO incidents (threat_id, title, description, assigned_to, priority, status) "
                   + "VALUES (?, ?, ?, ?, ?, ?)";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, incident.getThreatId());
            ps.setString(2, incident.getTitle());
            ps.setString(3, incident.getDescription());
            ps.setInt(4, incident.getAssignedTo());
            ps.setString(5, incident.getPriority());
            ps.setString(6, incident.getStatus());
            ps.executeUpdate();
            System.out.println("Incident added: " + incident.getTitle());

        } catch (SQLException e) {
            System.out.println("Error adding incident: " + e.getMessage());
        }
    }

    /** Updates an existing incident in the database. */
    @Override
    public void update(Incident incident) {
        String sql = "UPDATE incidents SET threat_id=?, title=?, description=?, assigned_to=?, "
                   + "priority=?, status=?, closed_at=? WHERE id=?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, incident.getThreatId());
            ps.setString(2, incident.getTitle());
            ps.setString(3, incident.getDescription());
            ps.setInt(4, incident.getAssignedTo());
            ps.setString(5, incident.getPriority());
            ps.setString(6, incident.getStatus());
            // closed_at can be null
            if (incident.getClosedAt() != null) {
                ps.setTimestamp(7, incident.getClosedAt());
            } else {
                ps.setNull(7, Types.TIMESTAMP);
            }
            ps.setInt(8, incident.getId());
            ps.executeUpdate();
            System.out.println("Incident updated: id=" + incident.getId());

        } catch (SQLException e) {
            System.out.println("Error updating incident: " + e.getMessage());
        }
    }

    /** Deletes an incident by its id. */
    @Override
    public void delete(int id) {
        String sql = "DELETE FROM incidents WHERE id = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, id);
            ps.executeUpdate();
            System.out.println("Incident deleted: id=" + id);

        } catch (SQLException e) {
            System.out.println("Error deleting incident: " + e.getMessage());
        }
    }

    /** Returns a single incident by id, or null if not found. */
    @Override
    public Incident getById(int id) {
        String sql = "SELECT * FROM incidents WHERE id = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return extractIncident(rs);
                }
            }

        } catch (SQLException e) {
            System.out.println("Error fetching incident: " + e.getMessage());
        }
        return null;
    }

    /** Returns all incidents from the database. */
    @Override
    public List<Incident> getAll() {
        List<Incident> incidents = new ArrayList<>();
        String sql = "SELECT * FROM incidents ORDER BY created_at DESC";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {

            while (rs.next()) {
                incidents.add(extractIncident(rs));
            }

        } catch (SQLException e) {
            System.out.println("Error fetching incidents: " + e.getMessage());
        }
        return incidents;
    }

    /** Helper method — builds an Incident object from the current row of a ResultSet. */
    private Incident extractIncident(ResultSet rs) throws SQLException {
        return new Incident(
            rs.getInt("id"),
            rs.getInt("threat_id"),
            rs.getString("title"),
            rs.getString("description"),
            rs.getInt("assigned_to"),
            rs.getString("priority"),
            rs.getString("status"),
            rs.getTimestamp("created_at"),
            rs.getTimestamp("closed_at")
        );
    }

    /**
     * Searches incidents across title and description keywords.
     */
    public List<Incident> search(String keyword) {
        List<Incident> list = new ArrayList<>();
        String sql = "SELECT * FROM incidents WHERE title LIKE ? OR description LIKE ? ORDER BY created_at DESC";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            String term = "%" + keyword + "%";
            ps.setString(1, term);
            ps.setString(2, term);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    list.add(extractIncident(rs));
                }
            }

        } catch (SQLException e) {
            System.out.println("Error searching incidents: " + e.getMessage());
        }
        return list;
    }

    /**
     * Returns incidents matching a specific status (OPEN, IN_PROGRESS, CLOSED).
     */
    public List<Incident> getByStatus(String status) {
        List<Incident> list = new ArrayList<>();
        String sql = "SELECT * FROM incidents WHERE status = ? ORDER BY created_at DESC";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, status);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    list.add(extractIncident(rs));
                }
            }

        } catch (SQLException e) {
            System.out.println("Error fetching incidents by status: " + e.getMessage());
        }
        return list;
    }

    /**
     * Assigns an incident to a specified user ID.
     */
    public void assignTo(int incidentId, int userId) {
        String sql = "UPDATE incidents SET assigned_to = ? WHERE id = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, userId);
            ps.setInt(2, incidentId);
            ps.executeUpdate();
            System.out.println("Incident #" + incidentId + " assigned to user #" + userId);

        } catch (SQLException e) {
            System.out.println("Error assigning incident: " + e.getMessage());
        }
    }

    /**
     * Marks an incident as CLOSED and sets the closed_at timestamp to now.
     */
    public void closeIncident(int incidentId) {
        String sql = "UPDATE incidents SET status = 'CLOSED', closed_at = CURRENT_TIMESTAMP WHERE id = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, incidentId);
            ps.executeUpdate();
            System.out.println("Incident #" + incidentId + " closed");

        } catch (SQLException e) {
            System.out.println("Error closing incident: " + e.getMessage());
        }
    }

    /**
     * Updates an incident status (OPEN, IN_PROGRESS, CLOSED) and adjusts closed_at accordingly.
     */
    public void updateStatus(int incidentId, String status) {
        String sql = status.equals("CLOSED")
            ? "UPDATE incidents SET status = ?, closed_at = CURRENT_TIMESTAMP WHERE id = ?"
            : "UPDATE incidents SET status = ?, closed_at = NULL WHERE id = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, status);
            ps.setInt(2, incidentId);
            ps.executeUpdate();
            System.out.println("Incident #" + incidentId + " status updated to " + status);

        } catch (SQLException e) {
            System.out.println("Error updating incident status: " + e.getMessage());
        }
    }
}
