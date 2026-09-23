package com.cybershield.model;

import com.cybershield.model.enums.UserRole;
import java.time.LocalDateTime;

/**
 * Represents an authenticated operator or administrator in the CyberShield system.
 * Demonstrates Encapsulation through private attributes and controlled access.
 */
public class User {
    private int id;
    private String username;
    private String passwordHash;
    private String fullName;
    private UserRole role;
    private boolean active;
    private LocalDateTime createdAt;
    private LocalDateTime lastLogin;

    public User() {
        this.active = true;
        this.createdAt = LocalDateTime.now();
    }

    public User(int id, String username, String passwordHash, String fullName, UserRole role) {
        this.id = id;
        this.username = username;
        this.passwordHash = passwordHash;
        this.fullName = fullName;
        this.role = role != null ? role : UserRole.ANALYST;
        this.active = true;
        this.createdAt = LocalDateTime.now();
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be empty");
        }
        this.username = username.trim();
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public UserRole getRole() {
        return role;
    }

    public void setRole(UserRole role) {
        this.role = role != null ? role : UserRole.ANALYST;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getLastLogin() {
        return lastLogin;
    }

    public void setLastLogin(LocalDateTime lastLogin) {
        this.lastLogin = lastLogin;
    }

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", role=" + role +
                ", active=" + active +
                '}';
    }
}
