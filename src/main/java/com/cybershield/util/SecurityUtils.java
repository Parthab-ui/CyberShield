package com.cybershield.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

/**
 * Security and hashing utility class.
 * Implements deterministic SHA-256 hashing without storing plaintext passwords.
 */
public final class SecurityUtils {

    private SecurityUtils() {
        // Private constructor for static utility class
    }

    /**
     * Hashes a password string using SHA-256 algorithm.
     * @param plainText The plaintext password
     * @return Hex-encoded SHA-256 hash string
     */
    public static String hashPassword(String plainText) {
        if (plainText == null) {
            return "";
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedHash = digest.digest(plainText.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : encodedHash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available in runtime", e);
        }
    }

    /**
     * Compares a plaintext password against a stored SHA-256 hash.
     */
    public static boolean verifyPassword(String plainText, String storedHash) {
        if (plainText == null || storedHash == null) {
            return false;
        }
        return hashPassword(plainText).equalsIgnoreCase(storedHash);
    }

    /**
     * Generates a readable unique identifier with a given prefix (e.g. EVT-ABCD, THR-1234, INC-5678).
     */
    public static String generateId(String prefix) {
        String randomPart = UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        return (prefix != null ? prefix + "-" : "") + randomPart;
    }
}
