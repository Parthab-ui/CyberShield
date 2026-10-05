package cybershield.util;

/**
 * Validator — Provides simple input validation methods used throughout the app.
 */
public class Validator {

    // Private constructor — this class should not be instantiated
    private Validator() { }

    /**
     * Returns true if the string is null or blank (empty or only whitespace).
     */
    public static boolean isEmpty(String value) {
        return value == null || value.trim().isEmpty();
    }

    /**
     * Returns true if the string is a valid IPv4 address (e.g. 192.168.1.1).
     */
    public static boolean isValidIP(String ip) {
        if (isEmpty(ip)) {
            return false;
        }
        // Split by dots and check each part
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            try {
                int num = Integer.parseInt(part);
                if (num < 0 || num > 255) {
                    return false;
                }
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

    /**
     * Returns true if the password is at least 6 characters long.
     */
    public static boolean isValidPassword(String password) {
        return !isEmpty(password) && password.length() >= 6;
    }
}
