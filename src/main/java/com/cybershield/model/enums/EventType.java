package com.cybershield.model.enums;

/**
 * Categories of simulated security events ingested by the telemetry pipeline.
 */
public enum EventType {
    AUTH_FAILURE("Authentication Failure", "Failed login or unauthorized credential attempt"),
    AUTH_SUCCESS("Authentication Success", "Authorized login session established"),
    SUSPICIOUS_EMAIL("Suspicious Email", "Inbound email flagged with suspicious indicators or spoofing"),
    FILE_ACCESS("File Modification", "Unauthorized file alteration or unexpected binary dropped"),
    NETWORK_SCAN("Network Port Scan", "Sequential probing of server communication ports"),
    PRIVILEGE_ESCALATION("Privilege Escalation", "Standard user process requesting elevated administrator privileges");

    private final String displayName;
    private final String description;

    EventType(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }

    public static EventType fromString(String val) {
        if (val == null) return AUTH_FAILURE;
        for (EventType e : EventType.values()) {
            if (e.name().equalsIgnoreCase(val.trim())) {
                return e;
            }
        }
        return AUTH_FAILURE;
    }
}
