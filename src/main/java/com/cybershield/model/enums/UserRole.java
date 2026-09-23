package com.cybershield.model.enums;

/**
 * Access roles for CyberShield users.
 */
public enum UserRole {
    ADMIN("Security Administrator"),
    ANALYST("SOC Analyst");

    private final String displayName;

    UserRole(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    public static UserRole fromString(String val) {
        if (val == null) return ANALYST;
        for (UserRole r : UserRole.values()) {
            if (r.name().equalsIgnoreCase(val.trim())) {
                return r;
            }
        }
        return ANALYST;
    }
}
