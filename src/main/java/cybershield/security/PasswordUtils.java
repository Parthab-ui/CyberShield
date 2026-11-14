package cybershield.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * PasswordUtils — Provides cryptographic hashing and verification for user passwords.
 * Demonstrates: Secure password storage using SHA-256 with unique cryptographic salts.
 * Never stores plaintext passwords in the database, protecting against rainbow table attacks.
 */
public class PasswordUtils {

    private static final SecureRandom RANDOM = new SecureRandom();

    private PasswordUtils() {
        // Utility class: prevent instantiation
    }

    /**
     * Generates a 16-byte cryptographically secure random salt in hexadecimal format.
     */
    public static String generateSalt() {
        byte[] saltBytes = new byte[16];
        RANDOM.nextBytes(saltBytes);
        return bytesToHex(saltBytes);
    }

    /**
     * Computes the SHA-256 hash of a password concatenated with the given salt.
     * @param password The plaintext password to hash.
     * @param salt The unique salt string.
     * @return The 64-character hexadecimal SHA-256 hash.
     */
    public static String hashPassword(String password, String salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            // Combine salt + password to produce distinct hashes even for identical passwords
            String combined = salt + password;
            byte[] hashBytes = md.digest(combined.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm unavailable in this Java runtime", e);
        }
    }

    /**
     * Verifies that a plaintext password matches the stored salt and hash.
     * Uses constant-time comparison to prevent timing attack vulnerabilities.
     */
    public static boolean verifyPassword(String plaintext, String salt, String expectedHash) {
        if (plaintext == null || salt == null || expectedHash == null) {
            return false;
        }
        String calculated = hashPassword(plaintext, salt);
        return MessageDigest.isEqual(calculated.getBytes(StandardCharsets.UTF_8),
                                     expectedHash.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Helper method: Converts a byte array into a lowercase hexadecimal string.
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
