package cybershield;

import cybershield.database.DatabaseManager;
import cybershield.model.User;
import cybershield.security.PasswordUtils;
import cybershield.service.UserService;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * PasswordUtilsTest — Comprehensive tests for PBKDF2WithHmacSHA256 password hashing,
 * legacy SHA-256 verification, and transparent hash upgrading on login.
 */
public class PasswordUtilsTest {

    @BeforeAll
    public static void setUp() throws SQLException {
        DatabaseManager.initialize();
    }

    @Test
    @DisplayName("Test 1: PBKDF2 new-format roundtrip verification")
    public void testPbkdf2Roundtrip() {
        String password = "SecurePassword@2026!";
        String salt = PasswordUtils.generateSalt();
        assertNotNull(salt);
        assertEquals(32, salt.length(), "Salt should be 16 bytes = 32 hex chars");

        String hash = PasswordUtils.hashPassword(password, salt);
        assertNotNull(hash);
        assertTrue(PasswordUtils.isPbkdf2Hash(hash));
        assertFalse(PasswordUtils.isLegacyHash(hash));
        assertTrue(hash.startsWith("pbkdf2$120000$"));

        // Verify with matching password
        assertTrue(PasswordUtils.verifyPassword(password, salt, hash));
        // Verify with embedded salt overload
        assertTrue(PasswordUtils.verifyPassword(password, hash));
    }

    @Test
    @DisplayName("Test 2: Legacy single-round SHA-256 hash verification")
    public void testLegacySha256Verification() {
        String password = "LegacyPassword#123";
        String salt = PasswordUtils.generateSalt();
        String legacyHash = PasswordUtils.hashPasswordLegacy(password, salt);

        assertNotNull(legacyHash);
        assertTrue(PasswordUtils.isLegacyHash(legacyHash));
        assertFalse(PasswordUtils.isPbkdf2Hash(legacyHash));
        assertEquals(64, legacyHash.length(), "Legacy SHA-256 hash is 64 hex characters");

        // Must verify with correct password & salt
        assertTrue(PasswordUtils.verifyPassword(password, salt, legacyHash));

        // Must fail with incorrect password
        assertFalse(PasswordUtils.verifyPassword("WrongPassword", salt, legacyHash));
    }

    @Test
    @DisplayName("Test 3: Wrong password fails verification in both formats")
    public void testWrongPassword() {
        String password = "CorrectPassword123";
        String salt = PasswordUtils.generateSalt();

        String pbkdf2Hash = PasswordUtils.hashPassword(password, salt);
        assertFalse(PasswordUtils.verifyPassword("IncorrectPassword", salt, pbkdf2Hash));
        assertFalse(PasswordUtils.verifyPassword("correctpassword123", salt, pbkdf2Hash)); // case sensitivity

        String legacyHash = PasswordUtils.hashPasswordLegacy(password, salt);
        assertFalse(PasswordUtils.verifyPassword("IncorrectPassword", salt, legacyHash));
    }

    @Test
    @DisplayName("Test 4: Null and empty inputs handled safely without throwing exceptions")
    public void testNullInputs() {
        String salt = PasswordUtils.generateSalt();
        String hash = PasswordUtils.hashPassword("SomePass", salt);

        assertFalse(PasswordUtils.verifyPassword(null, salt, hash));
        assertFalse(PasswordUtils.verifyPassword("SomePass", salt, null));
        assertFalse(PasswordUtils.verifyPassword(null, null, null));
        assertFalse(PasswordUtils.verifyPassword(null, hash));

        // Null checks on hashPassword
        assertThrows(IllegalArgumentException.class, () -> PasswordUtils.hashPassword(null, salt));
        assertThrows(IllegalArgumentException.class, () -> PasswordUtils.hashPassword("Pass", null));
        assertThrows(IllegalArgumentException.class, () -> PasswordUtils.hashPasswordLegacy(null, salt));
        assertThrows(IllegalArgumentException.class, () -> PasswordUtils.hashPasswordLegacy("Pass", null));
    }

    @Test
    @DisplayName("Test 5: Transparent upgrade from legacy hash to PBKDF2 on successful login")
    public void testUpgradeOnLogin() throws SQLException {
        UserService userService = new UserService();
        String testUser = "legacy_user_test_" + System.currentTimeMillis();
        String password = "LegacyPassword@123";
        String salt = PasswordUtils.generateSalt();
        String legacyHash = PasswordUtils.hashPasswordLegacy(password, salt);

        // Insert user directly with legacy hash
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(
                     "INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, datetime('now'))")) {
            pstmt.setString(1, testUser);
            pstmt.setString(2, legacyHash);
            pstmt.setString(3, salt);
            pstmt.setString(4, "ANALYST");
            pstmt.executeUpdate();
        }

        // Verify DB initially has legacy hash
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement("SELECT password_hash FROM users WHERE username = ?")) {
            pstmt.setString(1, testUser);
            try (ResultSet rs = pstmt.executeQuery()) {
                assertTrue(rs.next());
                String initialHash = rs.getString("password_hash");
                assertTrue(PasswordUtils.isLegacyHash(initialHash), "Initial hash must be legacy format");
            }
        }

        // Authenticate with UserService — should succeed and transparently upgrade
        User authenticated = userService.authenticate(testUser, password, "127.0.0.1", "TEST");
        assertNotNull(authenticated, "Authentication with legacy hash must succeed");

        // Verify DB now has upgraded PBKDF2 hash
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement("SELECT password_hash FROM users WHERE username = ?")) {
            pstmt.setString(1, testUser);
            try (ResultSet rs = pstmt.executeQuery()) {
                assertTrue(rs.next());
                String upgradedHash = rs.getString("password_hash");
                assertTrue(PasswordUtils.isPbkdf2Hash(upgradedHash), "Hash must be upgraded to PBKDF2 format in DB");
                assertTrue(upgradedHash.startsWith("pbkdf2$120000$"));
                // Verify password still verifies against new upgraded hash
                assertTrue(PasswordUtils.verifyPassword(password, upgradedHash));
            }
        }
    }
}
