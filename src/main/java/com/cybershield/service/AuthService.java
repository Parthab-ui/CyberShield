package com.cybershield.service;

import com.cybershield.exception.AuthenticationException;
import com.cybershield.exception.DatabaseOperationException;
import com.cybershield.model.User;
import com.cybershield.model.enums.UserRole;
import com.cybershield.repository.DatabaseManager;
import com.cybershield.repository.UserRepository;
import com.cybershield.util.SecurityUtils;
import com.cybershield.util.ValidationUtils;

/**
 * Service managing user authentication, login session state, and credential validation.
 */
public class AuthService {

    private final UserRepository userRepository;
    private static User currentUser; // In-memory active session user

    public AuthService() {
        this(new UserRepository(DatabaseManager.getInstance()));
    }

    public AuthService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Authenticates an analyst or administrator against stored SHA-256 hashes in SQLite.
     * @param username Plain username input
     * @param password Plain password input
     * @return Authenticated User object
     * @throws AuthenticationException If username/password mismatch or user inactive
     */
    public User login(String username, String password) throws AuthenticationException {
        if (!ValidationUtils.isNotEmpty(username) || !ValidationUtils.isNotEmpty(password)) {
            throw new AuthenticationException("Username and password must not be empty.");
        }

        try {
            User user = userRepository.findByUsername(username.trim());
            if (user == null) {
                throw new AuthenticationException("Invalid username or password.");
            }

            if (!user.isActive()) {
                throw new AuthenticationException("User account is deactivated. Contact security administrator.");
            }

            if (!SecurityUtils.verifyPassword(password, user.getPasswordHash())) {
                throw new AuthenticationException("Invalid username or password.");
            }

            // Update last login
            userRepository.updateLastLogin(user.getId());

            currentUser = user;
            return user;

        } catch (DatabaseOperationException e) {
            throw new AuthenticationException("Database error during authentication: " + e.getMessage(), e);
        }
    }

    public static User getCurrentUser() {
        return currentUser;
    }

    public static void setCurrentUser(User user) {
        currentUser = user;
    }

    public static void logout() {
        currentUser = null;
    }

    public static boolean isLoggedIn() {
        return currentUser != null;
    }

    public static boolean isAdmin() {
        return currentUser != null && currentUser.getRole() == UserRole.ADMIN;
    }
}
