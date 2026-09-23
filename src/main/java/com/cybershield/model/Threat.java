package com.cybershield.model;

import com.cybershield.model.enums.ResponseActionType;
import com.cybershield.model.enums.Severity;
import com.cybershield.model.enums.ThreatStatus;
import com.cybershield.model.enums.ThreatType;
import java.time.LocalDateTime;

/**
 * Abstract base class representing a detected security threat.
 * 
 * CORE OOP PRINCIPLES DEMONSTRATED:
 * 1. Abstraction: Defines contract and shared attributes without binding to a specific attack mechanism.
 * 2. Inheritance: Extended by specialized threats (BruteForce, Phishing, Malware, SuspiciousLogin).
 * 3. Polymorphism: Abstract methods overridden differently by each concrete threat subclass.
 */
public abstract class Threat {
    private int id;
    private String threatId;
    private ThreatType threatType;
    private Severity severity;
    private ThreatStatus status;
    private String sourceIp;
    private String targetAsset;
    private LocalDateTime detectedAt;
    private String description;

    public Threat(String threatId, ThreatType threatType, String sourceIp, String targetAsset, String description) {
        this.threatId = threatId;
        this.threatType = threatType;
        this.sourceIp = sourceIp != null ? sourceIp : "127.0.0.1";
        this.targetAsset = targetAsset != null ? targetAsset : "Endpoint";
        this.description = description != null ? description : "";
        this.status = ThreatStatus.NEW;
        this.detectedAt = LocalDateTime.now();
        // Severity dynamically determined by concrete subclass polymorphic logic
        this.severity = evaluateSeverity();
    }

    // Abstract methods demonstrating Polymorphism
    /**
     * Dynamically calculates threat severity based on specific attack telemetry metrics.
     * @return Calculated Severity (LOW, MEDIUM, HIGH, CRITICAL)
     */
    public abstract Severity evaluateSeverity();

    /**
     * Generates a detailed incident report tailored to this threat category.
     * @return Formatted multi-line text briefing
     */
    public abstract String generateIncidentReport();

    /**
     * Determines the recommended simulated incident response containment action.
     * @return Recommended ResponseActionType
     */
    public abstract ResponseActionType getRecommendedAction();

    // Getters and Setters (Encapsulation)
    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getThreatId() {
        return threatId;
    }

    public void setThreatId(String threatId) {
        this.threatId = threatId;
    }

    public ThreatType getThreatType() {
        return threatType;
    }

    public void setThreatType(ThreatType threatType) {
        this.threatType = threatType;
    }

    public Severity getSeverity() {
        return severity;
    }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }

    public ThreatStatus getStatus() {
        return status;
    }

    public void setStatus(ThreatStatus status) {
        this.status = status != null ? status : ThreatStatus.NEW;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public void setSourceIp(String sourceIp) {
        this.sourceIp = sourceIp;
    }

    public String getTargetAsset() {
        return targetAsset;
    }

    public void setTargetAsset(String targetAsset) {
        this.targetAsset = targetAsset;
    }

    public LocalDateTime getDetectedAt() {
        return detectedAt;
    }

    public void setDetectedAt(LocalDateTime detectedAt) {
        this.detectedAt = detectedAt;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    @Override
    public String toString() {
        return String.format("[%s] %s | Type: %s | Severity: %s | Status: %s | Source: %s",
                threatId, description, threatType, severity, status, sourceIp);
    }
}
