package com.cybershield.model.enums;

/**
 * Severity levels for detected security threats and escalated incidents.
 */
public enum Severity {
    LOW(1, "LOW", "#10B981"),        // Emerald Green
    MEDIUM(2, "MEDIUM", "#F59E0B"),    // Amber
    HIGH(3, "HIGH", "#F97316"),        // Orange
    CRITICAL(4, "CRITICAL", "#EF4444"); // Crimson Red

    private final int level;
    private final String label;
    private final String hexColor;

    Severity(int level, String label, String hexColor) {
        this.level = level;
        this.label = label;
        this.hexColor = hexColor;
    }

    public int getLevel() {
        return level;
    }

    public String getLabel() {
        return label;
    }

    public String getHexColor() {
        return hexColor;
    }

    public static Severity fromString(String val) {
        if (val == null) return LOW;
        for (Severity s : Severity.values()) {
            if (s.name().equalsIgnoreCase(val.trim())) {
                return s;
            }
        }
        return LOW;
    }
}
