package cybershield.model;

import java.sql.Timestamp;

/**
 * Threat — Represents a detected cybersecurity threat (e.g. Phishing, Malware, DDoS).
 * Demonstrates ENCAPSULATION: all fields are private, accessed through getters/setters.
 */
public class Threat {

    private int id;
    private String threatType;    // e.g. "Phishing", "Malware", "DDoS"
    private String sourceIp;
    private String targetSystem;
    private String severity;      // "LOW", "MEDIUM", "HIGH", "CRITICAL"
    private String status;        // "DETECTED", "INVESTIGATING", "RESOLVED"
    private Timestamp detectedAt;

    // Default constructor
    public Threat() { }

    // Constructor with all fields
    public Threat(int id, String threatType, String sourceIp, String targetSystem,
                  String severity, String status, Timestamp detectedAt) {
        this.id = id;
        this.threatType = threatType;
        this.sourceIp = sourceIp;
        this.targetSystem = targetSystem;
        this.severity = severity;
        this.status = status;
        this.detectedAt = detectedAt;
    }

    // Constructor without id (for inserting new threats)
    public Threat(String threatType, String sourceIp, String targetSystem,
                  String severity, String status) {
        this.threatType = threatType;
        this.sourceIp = sourceIp;
        this.targetSystem = targetSystem;
        this.severity = severity;
        this.status = status;
    }

    // -------- Getters and Setters (Encapsulation) --------

    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    public String getThreatType() { return threatType; }
    public void setThreatType(String threatType) { this.threatType = threatType; }

    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }

    public String getTargetSystem() { return targetSystem; }
    public void setTargetSystem(String targetSystem) { this.targetSystem = targetSystem; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public Timestamp getDetectedAt() { return detectedAt; }
    public void setDetectedAt(Timestamp detectedAt) { this.detectedAt = detectedAt; }

    /** Returns a readable string representation of this threat. */
    @Override
    public String toString() {
        return "Threat{id=" + id + ", type='" + threatType + "', severity='" + severity
                + "', status='" + status + "'}";
    }
}
