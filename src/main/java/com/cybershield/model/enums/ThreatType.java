package com.cybershield.model.enums;

/**
 * Types of security threats detected in the system.
 */
public enum ThreatType {
    BRUTE_FORCE("Brute Force Attack", "Repeated authentication failures against targeted account"),
    PHISHING("Phishing Threat", "Deceptive email with suspicious links or domain spoofing"),
    MALWARE("Malware Threat", "Simulated suspicious file payload or malicious hash signature"),
    SUSPICIOUS_LOGIN("Suspicious Login", "Anomalous login location, unusual hour, or unfamiliar device");

    private final String displayName;
    private final String description;

    ThreatType(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }

    public static ThreatType fromString(String val) {
        if (val == null) return BRUTE_FORCE;
        for (ThreatType t : ThreatType.values()) {
            if (t.name().equalsIgnoreCase(val.trim())) {
                return t;
            }
        }
        return BRUTE_FORCE;
    }
}
