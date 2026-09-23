package com.cybershield.util;

import java.util.regex.Pattern;

/**
 * Validation utility for validating network addresses, user inputs, and fields.
 */
public final class ValidationUtils {

    private static final Pattern IP_PATTERN = Pattern.compile(
        "^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.){3}(25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)$"
    );

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
        "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$"
    );

    private ValidationUtils() {
        // Utility class
    }

    public static boolean isValidIp(String ip) {
        if (ip == null || ip.trim().isEmpty()) {
            return false;
        }
        return IP_PATTERN.matcher(ip.trim()).matches();
    }

    public static boolean isValidEmail(String email) {
        if (email == null || email.trim().isEmpty()) {
            return false;
        }
        return EMAIL_PATTERN.matcher(email.trim()).matches();
    }

    public static boolean isValidUsername(String username) {
        return username != null && username.trim().length() >= 3 && username.trim().matches("^[a-zA-Z0-9_.-]+$");
    }

    public static boolean isNotEmpty(String value) {
        return value != null && !value.trim().isEmpty();
    }
}
