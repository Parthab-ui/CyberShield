package cybershield.security;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * PasswordUtils — Provides cryptographic hashing and verification for user passwords.
 * Implements PBKDF2WithHmacSHA256 with 120,000+ iterations, 16-byte random salt, and 256-bit key.
 * Backwards compatible with legacy single-round salted SHA-256 hashes.
 */
public class PasswordUtils {

    public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    public static final int DEFAULT_ITERATIONS = 120000;
    public static final int KEY_LENGTH_BITS = 256;
    public static final int SALT_LENGTH_BYTES = 16;
    public static final String PBKDF2_PREFIX = "pbkdf2$";

    private static final SecureRandom RANDOM = new SecureRandom();

    private PasswordUtils() {
        // Utility class: prevent instantiation
    }

    /**
     * Generates a 16-byte cryptographically secure random salt in hexadecimal format.
     */
    public static String generateSalt() {
        byte[] saltBytes = new byte[SALT_LENGTH_BYTES];
        RANDOM.nextBytes(saltBytes);
        return bytesToHex(saltBytes);
    }

    /**
     * Computes PBKDF2WithHmacSHA256 hash using default 120,000 iterations and 256-bit key length.
     * Returns a self-describing string in format: pbkdf2$<iterations>$<saltHex>$<hashHex>.
     *
     * @param password The plaintext password to hash.
     * @param salt The hexadecimal salt string.
     * @return The self-describing PBKDF2 hash string.
     */
    public static String hashPassword(String password, String salt) {
        return hashPasswordPBKDF2(password, salt, DEFAULT_ITERATIONS);
    }

    /**
     * Computes PBKDF2WithHmacSHA256 hash with explicit iteration count.
     */
    public static String hashPasswordPBKDF2(String password, String saltHex, int iterations) {
        if (password == null || saltHex == null) {
            throw new IllegalArgumentException("Password and salt must not be null");
        }
        try {
            byte[] saltBytes = hexToBytes(saltHex);
            KeySpec spec = new PBEKeySpec(password.toCharArray(), saltBytes, iterations, KEY_LENGTH_BITS);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            byte[] hashBytes = factory.generateSecret(spec).getEncoded();
            return PBKDF2_PREFIX + iterations + "$" + saltHex + "$" + bytesToHex(hashBytes);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("PBKDF2WithHmacSHA256 unavailable in this Java runtime", e);
        }
    }

    /**
     * Computes legacy single-round SHA-256 hash: SHA-256(salt + password).
     * Retained solely for backwards compatibility verification of legacy database records.
     */
    public static String hashPasswordLegacy(String password, String salt) {
        if (password == null || salt == null) {
            throw new IllegalArgumentException("Password and salt must not be null");
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            String combined = salt + password;
            byte[] hashBytes = md.digest(combined.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm unavailable in this Java runtime", e);
        }
    }

    /**
     * Checks if a stored hash is in the legacy SHA-256 format.
     */
    public static boolean isLegacyHash(String hash) {
        return hash != null && !hash.startsWith(PBKDF2_PREFIX);
    }

    /**
     * Checks if a stored hash is in the modern PBKDF2 format.
     */
    public static boolean isPbkdf2Hash(String hash) {
        return hash != null && hash.startsWith(PBKDF2_PREFIX);
    }

    /**
     * Verifies that a plaintext password matches the stored hash.
     * Supports BOTH the new PBKDF2 format (pbkdf2$<iterations>$<saltHex>$<hashHex>)
     * and legacy SHA-256 format, using constant-time comparison to prevent timing attacks.
     *
     * @param plaintext The entered password.
     * @param salt The stored salt (optional for PBKDF2 since salt is embedded, required for legacy).
     * @param expectedHash The stored hash string.
     * @return true if password matches, false otherwise.
     */
    public static boolean verifyPassword(String plaintext, String salt, String expectedHash) {
        if (plaintext == null || expectedHash == null) {
            return false;
        }

        if (isPbkdf2Hash(expectedHash)) {
            String[] parts = expectedHash.split("\\$");
            if (parts.length != 4) {
                return false;
            }
            try {
                int iterations = Integer.parseInt(parts[1]);
                String saltHex = parts[2];
                String storedHashHex = parts[3];

                byte[] saltBytes = hexToBytes(saltHex);
                KeySpec spec = new PBEKeySpec(plaintext.toCharArray(), saltBytes, iterations, KEY_LENGTH_BITS);
                SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
                byte[] calculatedHash = factory.generateSecret(spec).getEncoded();
                String calculatedHex = bytesToHex(calculatedHash);

                return MessageDigest.isEqual(calculatedHex.getBytes(StandardCharsets.UTF_8),
                                             storedHashHex.getBytes(StandardCharsets.UTF_8));
            } catch (Exception e) {
                return false;
            }
        } else {
            // Legacy SHA-256 verification
            if (salt == null) {
                return false;
            }
            String calculated = hashPasswordLegacy(plaintext, salt);
            return MessageDigest.isEqual(calculated.getBytes(StandardCharsets.UTF_8),
                                         expectedHash.getBytes(StandardCharsets.UTF_8));
        }
    }

    /**
     * Overload for self-describing PBKDF2 hashes where salt is embedded inside the hash string.
     */
    public static boolean verifyPassword(String plaintext, String expectedHash) {
        return verifyPassword(plaintext, null, expectedHash);
    }

    /**
     * Converts a byte array into a lowercase hexadecimal string.
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Converts a hexadecimal string back into a byte array.
     */
    public static byte[] hexToBytes(String hex) {
        if (hex == null || hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Invalid hex string");
        }
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int high = Character.digit(hex.charAt(i), 16);
            int low = Character.digit(hex.charAt(i + 1), 16);
            if (high == -1 || low == -1) {
                throw new IllegalArgumentException("Invalid hex character in: " + hex);
            }
            data[i / 2] = (byte) ((high << 4) + low);
        }
        return data;
    }
}
