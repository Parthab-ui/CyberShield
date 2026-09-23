package com.cybershield.model;

import com.cybershield.model.enums.ResponseActionType;
import com.cybershield.model.enums.Severity;
import com.cybershield.model.enums.ThreatType;

/**
 * Concrete Threat subclass representing a simulated Brute Force authentication attack.
 * Demonstrates Inheritance and Polymorphic method implementations.
 */
public class BruteForceThreat extends Threat {
    private int failedAttempts;
    private String targetAccount;
    private int windowDurationSeconds;

    public BruteForceThreat(String threatId, String sourceIp, String targetAccount,
                            int failedAttempts, int windowDurationSeconds, String description) {
        super(threatId, ThreatType.BRUTE_FORCE, sourceIp, targetAccount, description);
        this.targetAccount = targetAccount != null ? targetAccount : "admin";
        this.failedAttempts = failedAttempts;
        this.windowDurationSeconds = windowDurationSeconds;
        // Re-evaluate severity after specialized attributes are initialized
        setSeverity(evaluateSeverity());
    }

    @Override
    public Severity evaluateSeverity() {
        if (failedAttempts >= 10) {
            return Severity.CRITICAL;
        } else if (failedAttempts >= 5) {
            return Severity.HIGH;
        } else {
            return Severity.MEDIUM;
        }
    }

    @Override
    public String generateIncidentReport() {
        return String.format(
            "=== BRUTE FORCE THREAT DOSSIER ===\n" +
            "Threat ID: %s\n" +
            "Target Account: %s\n" +
            "Attacker Source IP: %s\n" +
            "Failed Attempts: %d recorded within %d seconds\n" +
            "Calculated Severity: %s\n" +
            "Detection Timestamp: %s\n" +
            "Remediation Advice: Block IP at network perimeter and temporarily lock target user credentials.\n",
            getThreatId(), targetAccount, getSourceIp(), failedAttempts,
            windowDurationSeconds, getSeverity(), getDetectedAt()
        );
    }

    @Override
    public ResponseActionType getRecommendedAction() {
        return ResponseActionType.BLOCK_IP;
    }

    public int getFailedAttempts() {
        return failedAttempts;
    }

    public void setFailedAttempts(int failedAttempts) {
        this.failedAttempts = failedAttempts;
        setSeverity(evaluateSeverity());
    }

    public String getTargetAccount() {
        return targetAccount;
    }

    public void setTargetAccount(String targetAccount) {
        this.targetAccount = targetAccount;
    }

    public int getWindowDurationSeconds() {
        return windowDurationSeconds;
    }

    public void setWindowDurationSeconds(int windowDurationSeconds) {
        this.windowDurationSeconds = windowDurationSeconds;
    }
}
