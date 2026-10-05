package cybershield.dao;

import cybershield.model.BlockedIP;
import cybershield.util.DBConnection;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * BlockedIPDAO — Handles all database operations for the blocked_ips table.
 * Implements GenericDAO, demonstrating POLYMORPHISM (same interface, blocked-IP-specific SQL).
 */
public class BlockedIPDAO implements GenericDAO<BlockedIP> {

    /** Inserts a new blocked IP into the database. */
    @Override
    public void add(BlockedIP blockedIP) {
        String sql = "INSERT INTO blocked_ips (ip_address, reason) VALUES (?, ?)";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, blockedIP.getIpAddress());
            ps.setString(2, blockedIP.getReason());
            ps.executeUpdate();
            System.out.println("IP blocked: " + blockedIP.getIpAddress());

        } catch (SQLException e) {
            System.out.println("Error blocking IP: " + e.getMessage());
        }
    }

    /** Updates an existing blocked IP record. */
    @Override
    public void update(BlockedIP blockedIP) {
        String sql = "UPDATE blocked_ips SET ip_address=?, reason=? WHERE id=?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, blockedIP.getIpAddress());
            ps.setString(2, blockedIP.getReason());
            ps.setInt(3, blockedIP.getId());
            ps.executeUpdate();
            System.out.println("Blocked IP updated: id=" + blockedIP.getId());

        } catch (SQLException e) {
            System.out.println("Error updating blocked IP: " + e.getMessage());
        }
    }

    /** Deletes (unblocks) an IP by its id. */
    @Override
    public void delete(int id) {
        String sql = "DELETE FROM blocked_ips WHERE id = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, id);
            ps.executeUpdate();
            System.out.println("Blocked IP removed: id=" + id);

        } catch (SQLException e) {
            System.out.println("Error removing blocked IP: " + e.getMessage());
        }
    }

    /** Returns a single blocked IP by id, or null if not found. */
    @Override
    public BlockedIP getById(int id) {
        String sql = "SELECT * FROM blocked_ips WHERE id = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return extractBlockedIP(rs);
                }
            }

        } catch (SQLException e) {
            System.out.println("Error fetching blocked IP: " + e.getMessage());
        }
        return null;
    }

    /** Returns all blocked IPs from the database. */
    @Override
    public List<BlockedIP> getAll() {
        List<BlockedIP> blockedIPs = new ArrayList<>();
        String sql = "SELECT * FROM blocked_ips ORDER BY blocked_at DESC";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {

            while (rs.next()) {
                blockedIPs.add(extractBlockedIP(rs));
            }

        } catch (SQLException e) {
            System.out.println("Error fetching blocked IPs: " + e.getMessage());
        }
        return blockedIPs;
    }

    /** Helper method — builds a BlockedIP object from the current row of a ResultSet. */
    private BlockedIP extractBlockedIP(ResultSet rs) throws SQLException {
        return new BlockedIP(
            rs.getInt("id"),
            rs.getString("ip_address"),
            rs.getString("reason"),
            rs.getTimestamp("blocked_at")
        );
    }
}
