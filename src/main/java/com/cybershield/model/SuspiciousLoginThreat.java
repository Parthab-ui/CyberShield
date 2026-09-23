package com.cybershield.model;

import com.cybershield.model.enums.ResponseActionType;
import com.cybershield.model.enums.Severity;
import com.cybershield.model.enums.ThreatType;

/**
 * Concrete Threat subclass representing an anomalous login detection.
 * Demonstrates Inheritance and polymorphic response actions.
 */
public class SuspiciousLoginThreat extends Threat {
    private boolean geoAnomaly;
    private boolean unusualHour;
    private String deviceFingerprint;

    public SuspiciousLoginThreat(String threatId, String sourceIp, String targetAccount,
                                 boolean geoAnomaly, boolean unusualHour, String deviceFingerprint,
                                 String description) {
        super(threatId, ThreatType.SUSPICIOUS_LOGIN, sourceIp, targetAccount, description);
        this.geoAnomaly = geoAnomaly;
        this.unusualHour = unusualHour;
        this.deviceFingerprint = deviceFingerprint != null ? deviceFingerprint : "DEV-UNKNOWN";
        setSeverity(evaluateSeverity());
    }

    @Override
    public Severity evaluateSeverity() {
        if (geoAnomaly && unusualHour) {
            return Severity.HIGH;
        } else if (geoAnomaly || unusualHour) {
            return Severity.MEDIUM;
        } else {
            return Severity.LOW;
        }
    }

    @Override
    public String generateIncidentReport() {
        return String.format(
            "=== SUSPICIOUS LOGIN ANOMALY DOSSIER ===\n" +
            "Threat ID: %s\n" +
            "Target User: %s\n" +
            "Originating IP: %s\n" +
            "Geographic Velocity Anomaly: %b\n" +
            "Unusual Off-Hours Access: %b\n" +
            "Device Fingerprint: %s\n" +
            "Calculated Severity: %s\n" +
            "Remediation Advice: Temporarily disable user account and challenge with multifactor re-verification.\n",
            getThreatId(), getTargetAsset(), getSourceIp(),
            geoAnomaly, unusualHour, deviceFingerprint, getSeverity()
        );
    }

    @Override
    public ResponseActionType getRecommendedAction() {
        return ResponseActionType.DISABLE_USER;
    }

    public boolean isGeoAnomaly() {
        return geoAnomaly;
    }

    public void setGeoAnomaly(boolean geoAnomaly) {
        this.geoAnomaly = geoAnomaly;
        setSeverity(evaluateSeverity());
    }

    public boolean isUnusualHour() {
        return unusualHour;
    }

    public void setUnusualHour(boolean unusualHour) {
        this.unusualHour = unusualHour;
        setSeverity(evaluateSeverity());
    }

    public String getDeviceFingerprint() {
        return deviceFingerprint;
    }

    public void setDeviceFingerprint(String deviceFingerprint) {
        this.deviceFingerprint = deviceFingerprint;
    }
}
