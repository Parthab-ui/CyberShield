package cybershield.dao;

import cybershield.model.User;
import cybershield.util.DBConnection;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * UserDAO — Handles all database operations for the users table.
 * Does NOT implement GenericDAO fully because users should not be freely deleted/updated
 * from module code. Provides add, getAll, getById, and validateLogin instead.
 */
public class UserDAO {

    /** Inserts a new user into the database with SHA-256 password hashing. */
    public void add(User user) {
        String sql = "INSERT INTO users (username, password, role) VALUES (?, ?, ?)";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            String pass = user.getPassword();
            if (pass != null && pass.length() != 64) {
                pass = hashPassword(pass);
            }

            ps.setString(1, user.getUsername());
            ps.setString(2, pass);
            ps.setString(3, user.getRole());
            ps.executeUpdate();
            System.out.println("User added: " + user.getUsername());

        } catch (SQLException e) {
            System.out.println("Error adding user: " + e.getMessage());
        }
    }

    /** Returns a list of all users in the database. */
    public List<User> getAll() {
        List<User> users = new ArrayList<>();
        String sql = "SELECT * FROM users ORDER BY id";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {

            while (rs.next()) {
                User user = new User(
                    rs.getInt("id"),
                    rs.getString("username"),
                    rs.getString("password"),
                    rs.getString("role"),
                    rs.getTimestamp("created_at")
                );
                users.add(user);
            }

        } catch (SQLException e) {
            System.out.println("Error fetching users: " + e.getMessage());
        }
        return users;
    }

    /** Returns a single user by id, or null if not found. */
    public User getById(int id) {
        String sql = "SELECT * FROM users WHERE id = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return new User(
                        rs.getInt("id"),
                        rs.getString("username"),
                        rs.getString("password"),
                        rs.getString("role"),
                        rs.getTimestamp("created_at")
                    );
                }
            }

        } catch (SQLException e) {
            System.out.println("Error fetching user by id: " + e.getMessage());
        }
        return null;
    }

    /**
     * Hashes a password using SHA-256 for secure cryptographic storage.
     */
    public static String hashPassword(String password) {
        if (password == null) return null;
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(password.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            return password; // Fallback
        }
    }

    /**
     * Checks if a username and password combination is valid.
     * Supports both SHA-256 hashed passwords and legacy plain passwords.
     * Upgrades legacy plain passwords to SHA-256 hash automatically upon successful login.
     * Returns the User object if login is successful, or null if it fails.
     */
    public User validateLogin(String username, String password) {
        String sql = "SELECT * FROM users WHERE username = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    String stored = rs.getString("password");
                    String hashedInput = hashPassword(password);
                    boolean match = (stored != null) && (stored.equals(password) || stored.equalsIgnoreCase(hashedInput));
                    if (match) {
                        int id = rs.getInt("id");
                        // If password was stored in plain text, silently upgrade it to hash
                        if (stored != null && !stored.equalsIgnoreCase(hashedInput)) {
                            updatePassword(id, password);
                        }
                        return new User(
                            id,
                            rs.getString("username"),
                            hashedInput,
                            rs.getString("role"),
                            rs.getTimestamp("created_at")
                        );
                    }
                }
            }

        } catch (SQLException e) {
            System.out.println("Error during login validation: " + e.getMessage());
        }
        return null; // Login failed
    }

    /**
     * Returns true if a user with the given username already exists in the database.
     * Used by RegisterDialog to prevent duplicate usernames.
     */
    public boolean usernameExists(String username) {
        String sql = "SELECT COUNT(*) FROM users WHERE username = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt(1) > 0;
                }
            }

        } catch (SQLException e) {
            System.out.println("Error checking username: " + e.getMessage());
        }
        return false;
    }

    /**
     * Returns a list of all usernames for assigning incidents.
     */
    public List<String> getAllUsernames() {
        List<String> usernames = new ArrayList<>();
        String sql = "SELECT username FROM users ORDER BY username ASC";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {

            while (rs.next()) {
                usernames.add(rs.getString("username"));
            }

        } catch (SQLException e) {
            System.out.println("Error fetching usernames: " + e.getMessage());
        }
        return usernames;
    }

    /**
     * Returns the user ID for a given username, or 1 as fallback.
     */
    public int getUserIdByUsername(String username) {
        String sql = "SELECT id FROM users WHERE username = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt("id");
                }
            }

        } catch (SQLException e) {
            System.out.println("Error fetching user ID by username: " + e.getMessage());
        }
        return 1;
    }

    /**
     * Returns the username for a given user ID.
     */
    public String getUsernameById(int id) {
        String sql = "SELECT username FROM users WHERE id = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("username");
                }
            }

        } catch (SQLException e) {
            System.out.println("Error fetching username by ID: " + e.getMessage());
        }
        return "User #" + id;
    }

    /**
     * Updates a user's password with SHA-256 hashing.
     */
    public boolean updatePassword(int userId, String newPassword) {
        String sql = "UPDATE users SET password = ? WHERE id = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            String pass = (newPassword != null && newPassword.length() == 64)
                    ? newPassword
                    : hashPassword(newPassword);
            ps.setString(1, pass);
            ps.setInt(2, userId);
            int rows = ps.executeUpdate();
            return rows > 0;

        } catch (SQLException e) {
            System.out.println("Error updating password: " + e.getMessage());
        }
        return false;
    }
}
