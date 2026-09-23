package com.cybershield.model.enums;

/**
 * Types of incident response actions (purely simulated containment actions).
 */
public enum ResponseActionType {
    BLOCK_IP("Block IP", "Applies simulated firewall block rule against source IP address."),
    DISABLE_USER("Disable User", "Revokes active user session and disables target user credentials."),
    MARK_FOR_REVIEW("Mark for Review", "Escalates telemetry payload to tier-2 security analyst review queue."),
    QUARANTINE_SIMULATION("Quarantine Simulation", "Simulates host endpoint network isolation and file quarantine.");

    private final String displayName;
    private final String description;

    ResponseActionType(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }

    public static ResponseActionType fromString(String val) {
        if (val == null) return MARK_FOR_REVIEW;
        for (ResponseActionType r : ResponseActionType.values()) {
            if (r.name().equalsIgnoreCase(val.trim())) {
                return r;
            }
        }
        return MARK_FOR_REVIEW;
    }
}
