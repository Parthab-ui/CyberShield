package cybershield.model;

/**
 * ThreatResponse — Represents an automated or manual defensive mitigation action
 * executed in response to a detected cybersecurity threat or security incident.
 *
 * Demonstrates: Domain modeling for automated response auditing, incident linkage,
 * and completion status tracking (EXECUTED, FAILED, PENDING).
 */
public class ThreatResponse {

    private int id;
    private Integer incidentId;         // Optional foreign reference to associated incident
    private String threatType;          // e.g. "BRUTE_FORCE_ATTACK", "CREDENTIAL_STUFFING"
    private String actionTaken;         // e.g. "BLOCK_IP", "LOCK_ACCOUNT", "FORCE_LOGOUT"
    private String targetIdentifier;    // e.g. Target IP address ("192.168.1.105") or username ("admin")
    private String status;              // "EXECUTED", "FAILED", "PENDING"
    private long executedAt;            // Epoch millis when defense action was initiated
    private Long completedAt;           // Epoch millis when defense action completed
    private String details;             // Forensic description (e.g. "Automated block applied for 15 minutes")

    /** Default constructor required for Google Gson */
    public ThreatResponse() {
    }

    /** Full parameterized constructor */
    public ThreatResponse(int id, Integer incidentId, String threatType, String actionTaken,
                          String targetIdentifier, String status, long executedAt, Long completedAt, String details) {
        this.id = id;
        this.incidentId = incidentId;
        this.threatType = threatType;
        this.actionTaken = actionTaken;
        this.targetIdentifier = targetIdentifier;
        this.status = (status != null && !status.trim().isEmpty()) ? status.trim().toUpperCase() : "EXECUTED";
        this.executedAt = executedAt;
        this.completedAt = completedAt;
        this.details = details;
    }

    /** Constructor for creating new response records before database insertion */
    public ThreatResponse(Integer incidentId, String threatType, String actionTaken,
                          String targetIdentifier, String status, long executedAt, String details) {
        this(-1, incidentId, threatType, actionTaken, targetIdentifier, status, executedAt, executedAt, details);
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public Integer getIncidentId() {
        return incidentId;
    }

    public void setIncidentId(Integer incidentId) {
        this.incidentId = incidentId;
    }

    public String getThreatType() {
        return threatType;
    }

    public void setThreatType(String threatType) {
        this.threatType = threatType;
    }

    public String getActionTaken() {
        return actionTaken;
    }

    public void setActionTaken(String actionTaken) {
        this.actionTaken = actionTaken;
    }

    public String getTargetIdentifier() {
        return targetIdentifier;
    }

    public void setTargetIdentifier(String targetIdentifier) {
        this.targetIdentifier = targetIdentifier;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = (status != null && !status.trim().isEmpty()) ? status.trim().toUpperCase() : "EXECUTED";
    }

    public long getExecutedAt() {
        return executedAt;
    }

    public void setExecutedAt(long executedAt) {
        this.executedAt = executedAt;
    }

    public Long getCompletedAt() {
        return completedAt;
    }

    public void setCompletedAt(Long completedAt) {
        this.completedAt = completedAt;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }

    @Override
    public String toString() {
        return "ThreatResponse{" +
                "id=" + id +
                ", incidentId=" + incidentId +
                ", threatType='" + threatType + '\'' +
                ", actionTaken='" + actionTaken + '\'' +
                ", targetIdentifier='" + targetIdentifier + '\'' +
                ", status='" + status + '\'' +
                ", executedAt=" + executedAt +
                '}';
    }
}

