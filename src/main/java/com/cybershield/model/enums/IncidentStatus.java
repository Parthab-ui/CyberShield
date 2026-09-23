package com.cybershield.model.enums;

/**
 * Status lifecycle states for escalated security incidents.
 */
public enum IncidentStatus {
    OPEN("OPEN", "#EF4444"),
    INVESTIGATING("INVESTIGATING", "#F59E0B"),
    RESOLVED("RESOLVED", "#10B981"),
    CLOSED("CLOSED", "#64748B");

    private final String label;
    private final String hexColor;

    IncidentStatus(String label, String hexColor) {
        this.label = label;
        this.hexColor = hexColor;
    }

    public String getLabel() {
        return label;
    }

    public String getHexColor() {
        return hexColor;
    }

    public static IncidentStatus fromString(String val) {
        if (val == null) return OPEN;
        for (IncidentStatus s : IncidentStatus.values()) {
            if (s.name().equalsIgnoreCase(val.trim())) {
                return s;
            }
        }
        return OPEN;
    }
}
