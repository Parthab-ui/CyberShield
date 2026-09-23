package com.cybershield.model.enums;

/**
 * Status lifecycle states for detected threats.
 */
public enum ThreatStatus {
    NEW("NEW", "#EF4444"),
    INVESTIGATING("INVESTIGATING", "#F59E0B"),
    RESOLVED("RESOLVED", "#10B981"),
    FALSE_POSITIVE("FALSE_POSITIVE", "#64748B");

    private final String label;
    private final String hexColor;

    ThreatStatus(String label, String hexColor) {
        this.label = label;
        this.hexColor = hexColor;
    }

    public String getLabel() {
        return label;
    }

    public String getHexColor() {
        return hexColor;
    }

    public static ThreatStatus fromString(String val) {
        if (val == null) return NEW;
        for (ThreatStatus s : ThreatStatus.values()) {
            if (s.name().equalsIgnoreCase(val.trim())) {
                return s;
            }
        }
        return NEW;
    }
}
