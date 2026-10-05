package cybershield.model;

import java.sql.Timestamp;

/**
 * User — Represents a system user (Admin or Analyst).
 * Demonstrates ENCAPSULATION: all fields are private, accessed through getters/setters.
 */
public class User {

    private int id;
    private String username;
    private String password;
    private String role;          // "ADMIN" or "ANALYST"
    private Timestamp createdAt;

    // Default constructor
    public User() { }

    // Constructor with all fields
    public User(int id, String username, String password, String role, Timestamp createdAt) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.role = role;
        this.createdAt = createdAt;
    }

    // Constructor without id (for inserting new users — DB generates the id)
    public User(String username, String password, String role) {
        this.username = username;
        this.password = password;
        this.role = role;
    }

    // -------- Getters and Setters (Encapsulation) --------

    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }

    public Timestamp getCreatedAt() { return createdAt; }
    public void setCreatedAt(Timestamp createdAt) { this.createdAt = createdAt; }

    /** Returns a readable string representation of this user. */
    @Override
    public String toString() {
        return "User{id=" + id + ", username='" + username + "', role='" + role + "'}";
    }
}
