package com.cybershield.repository;

import com.cybershield.exception.DatabaseOperationException;
import com.cybershield.model.User;
import com.cybershield.model.enums.UserRole;
import com.cybershield.util.DateTimeUtils;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Repository performing CRUD operations on User entities in SQLite.
 * Demonstrates JDBC prepared statements and Resource Management with try-with-resources.
 */
public class UserRepository {

    private final DatabaseManager databaseManager;

    public UserRepository() {
        this.databaseManager = DatabaseManager.getInstance();
    }

    public UserRepository(DatabaseManager databaseManager) {
        this.databaseManager = databaseManager;
    }

    public User findByUsername(String username) throws DatabaseOperationException {
        String sql = "SELECT id, username, password_hash, full_name, role, active, created_at, last_login FROM users WHERE username = ?";
        try (Connection conn = databaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, username);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return mapRowToUser(rs);
                }
            }
            return null;
        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to find user by username: " + username, e);
        }
    }

    public User findById(int id) throws DatabaseOperationException {
        String sql = "SELECT id, username, password_hash, full_name, role, active, created_at, last_login FROM users WHERE id = ?";
        try (Connection conn = databaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, id);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return mapRowToUser(rs);
                }
            }
            return null;
        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to find user by id: " + id, e);
        }
    }

    public List<User> findAll() throws DatabaseOperationException {
        List<User> list = new ArrayList<>();
        String sql = "SELECT id, username, password_hash, full_name, role, active, created_at, last_login FROM users ORDER BY id ASC";
        try (Connection conn = databaseManager.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                list.add(mapRowToUser(rs));
            }
            return list;
        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to list users", e);
        }
    }

    public User save(User user) throws DatabaseOperationException {
        String sql = "INSERT INTO users (username, password_hash, full_name, role, active, created_at) VALUES (?, ?, ?, ?, ?, ?)";
        try (Connection conn = databaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {

            pstmt.setString(1, user.getUsername());
            pstmt.setString(2, user.getPasswordHash());
            pstmt.setString(3, user.getFullName());
            pstmt.setString(4, user.getRole().name());
            pstmt.setInt(5, user.isActive() ? 1 : 0);
            pstmt.setString(6, DateTimeUtils.format(user.getCreatedAt()));

            int affected = pstmt.executeUpdate();
            if (affected > 0) {
                try (ResultSet keys = pstmt.getGeneratedKeys()) {
                    if (keys.next()) {
                        user.setId(keys.getInt(1));
                    }
                }
            }
            return user;
        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to insert user: " + user.getUsername(), e);
        }
    }

    public void update(User user) throws DatabaseOperationException {
        String sql = "UPDATE users SET full_name = ?, role = ?, active = ? WHERE id = ?";
        try (Connection conn = databaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, user.getFullName());
            pstmt.setString(2, user.getRole().name());
            pstmt.setInt(3, user.isActive() ? 1 : 0);
            pstmt.setInt(4, user.getId());

            pstmt.executeUpdate();
        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to update user: " + user.getUsername(), e);
        }
    }

    public void updateLastLogin(int userId) throws DatabaseOperationException {
        String sql = "UPDATE users SET last_login = ? WHERE id = ?";
        try (Connection conn = databaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, DateTimeUtils.format(LocalDateTime.now()));
            pstmt.setInt(2, userId);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to update last login for user: " + userId, e);
        }
    }

    public boolean delete(int userId) throws DatabaseOperationException {
        String sql = "DELETE FROM users WHERE id = ?";
        try (Connection conn = databaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, userId);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to delete user: " + userId, e);
        }
    }

    private User mapRowToUser(ResultSet rs) throws SQLException {
        User user = new User();
        user.setId(rs.getInt("id"));
        user.setUsername(rs.getString("username"));
        user.setPasswordHash(rs.getString("password_hash"));
        user.setFullName(rs.getString("full_name"));
        user.setRole(UserRole.fromString(rs.getString("role")));
        user.setActive(rs.getInt("active") == 1);
        user.setCreatedAt(DateTimeUtils.parse(rs.getString("created_at")));
        String lastLoginStr = rs.getString("last_login");
        if (lastLoginStr != null && !lastLoginStr.isEmpty()) {
            user.setLastLogin(DateTimeUtils.parse(lastLoginStr));
        }
        return user;
    }
}
