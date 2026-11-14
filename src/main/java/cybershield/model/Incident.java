package cybershield.model;

/**
 * Incident — Represents a security incident tracked in CyberShield.
 * Demonstrates: Domain model encapsulation, status management, and severity tracking.
 * Supported Severities: "LOW", "MEDIUM", "HIGH", "CRITICAL"
 * Supported Statuses: "OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"
 *
 * Review 3 Phase 5 Enhancements:
 * - assignedTo: Username of assigned security analyst or admin investigator.
 * - rootCauseCategory: Classified attack root cause (e.g. "BRUTE_FORCE_ATTACK", "CREDENTIAL_STUFFING").
 * - resolutionSummary: Technical resolution narrative documented upon incident closure.
 */
public class Incident {

    private int id;
    private String title;
    private String description;
    private String severity; // LOW, MEDIUM, HIGH, CRITICAL
    private String status;   // OPEN, INVESTIGATING, RESOLVED, CLOSED
    private String createdBy;
    private String createdAt;
    private String updatedAt;

    // Review 3 Phase 5 Investigation Fields
    private String assignedTo;
    private String rootCauseCategory;
    private String resolutionSummary;

    // Default constructor for JSON deserialization
    public Incident() {
    }

    // Backwards-compatible 8-param constructor for records loaded from earlier schema versions
    public Incident(int id, String title, String description, String severity, String status,
                    String createdBy, String createdAt, String updatedAt) {
        this(id, title, description, severity, status, createdBy, createdAt, updatedAt, null, null, null);
    }

    // Full 11-param constructor including Review 3 Phase 5 investigation properties
    public Incident(int id, String title, String description, String severity, String status,
                    String createdBy, String createdAt, String updatedAt,
                    String assignedTo, String rootCauseCategory, String resolutionSummary) {
        this.id = id;
        this.title = title;
        this.description = description;
        this.severity = severity;
        this.status = status;
        this.createdBy = createdBy;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
        this.assignedTo = assignedTo;
        this.rootCauseCategory = rootCauseCategory;
        this.resolutionSummary = resolutionSummary;
    }

    // Constructor for creating new incidents before database persistence
    public Incident(String title, String description, String severity, String status, String createdBy) {
        this(-1, title, description, severity, status, createdBy, null, null, null, null, null);
    }

    // Convenience constructor without explicit author
    public Incident(String title, String description, String severity, String status) {
        this(title, description, severity, status, "analyst");
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    public String getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(String createdAt) {
        this.createdAt = createdAt;
    }

    public String getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(String updatedAt) {
        this.updatedAt = updatedAt;
    }

    public String getAssignedTo() {
        return assignedTo;
    }

    public void setAssignedTo(String assignedTo) {
        this.assignedTo = assignedTo;
    }

    public String getRootCauseCategory() {
        return rootCauseCategory;
    }

    public void setRootCauseCategory(String rootCauseCategory) {
        this.rootCauseCategory = rootCauseCategory;
    }

    public String getResolutionSummary() {
        return resolutionSummary;
    }

    public void setResolutionSummary(String resolutionSummary) {
        this.resolutionSummary = resolutionSummary;
    }

    @Override
    public String toString() {
        return "Incident{" +
                "id=" + id +
                ", title='" + title + '\'' +
                ", severity='" + severity + '\'' +
                ", status='" + status + '\'' +
                ", assignedTo='" + assignedTo + '\'' +
                ", rootCauseCategory='" + rootCauseCategory + '\'' +
                '}';
    }
}
