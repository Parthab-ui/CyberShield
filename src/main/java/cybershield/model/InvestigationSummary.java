package cybershield.model;

/**
 * InvestigationSummary — High-level case brief summarizing the forensic triage state of an incident.
 * Combines incident metadata, investigator ownership, root cause analysis, note counts,
 * and resolution outcomes into a comprehensive management report.
 */
public class InvestigationSummary {

    private int incidentId;
    private String title;
    private String severity;
    private String status;
    private String assignedInvestigator;
    private String rootCauseCategory;
    private int totalInvestigationNotes;
    private int totalThreatResponses;
    private String createdAt;
    private long latestInvestigationTimestamp;  // Epoch millis (0 if no notes)
    private String resolutionSummary;

    public InvestigationSummary() {
    }

    public InvestigationSummary(int incidentId, String title, String severity, String status,
                                String assignedInvestigator, String rootCauseCategory,
                                int totalInvestigationNotes, int totalThreatResponses,
                                String createdAt, long latestInvestigationTimestamp,
                                String resolutionSummary) {
        this.incidentId = incidentId;
        this.title = title;
        this.severity = severity;
        this.status = status;
        this.assignedInvestigator = assignedInvestigator;
        this.rootCauseCategory = rootCauseCategory;
        this.totalInvestigationNotes = totalInvestigationNotes;
        this.totalThreatResponses = totalThreatResponses;
        this.createdAt = createdAt;
        this.latestInvestigationTimestamp = latestInvestigationTimestamp;
        this.resolutionSummary = resolutionSummary;
    }

    public int getIncidentId() {
        return incidentId;
    }

    public void setIncidentId(int incidentId) {
        this.incidentId = incidentId;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
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

    public String getAssignedInvestigator() {
        return assignedInvestigator;
    }

    public void setAssignedInvestigator(String assignedInvestigator) {
        this.assignedInvestigator = assignedInvestigator;
    }

    public String getRootCauseCategory() {
        return rootCauseCategory;
    }

    public void setRootCauseCategory(String rootCauseCategory) {
        this.rootCauseCategory = rootCauseCategory;
    }

    public int getTotalInvestigationNotes() {
        return totalInvestigationNotes;
    }

    public void setTotalInvestigationNotes(int totalInvestigationNotes) {
        this.totalInvestigationNotes = totalInvestigationNotes;
    }

    public int getTotalThreatResponses() {
        return totalThreatResponses;
    }

    public void setTotalThreatResponses(int totalThreatResponses) {
        this.totalThreatResponses = totalThreatResponses;
    }

    public String getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(String createdAt) {
        this.createdAt = createdAt;
    }

    public long getLatestInvestigationTimestamp() {
        return latestInvestigationTimestamp;
    }

    public void setLatestInvestigationTimestamp(long latestInvestigationTimestamp) {
        this.latestInvestigationTimestamp = latestInvestigationTimestamp;
    }

    public String getResolutionSummary() {
        return resolutionSummary;
    }

    public void setResolutionSummary(String resolutionSummary) {
        this.resolutionSummary = resolutionSummary;
    }

    @Override
    public String toString() {
        return "InvestigationSummary{" +
                "incidentId=" + incidentId +
                ", title='" + title + '\'' +
                ", status='" + status + '\'' +
                ", assignedInvestigator='" + assignedInvestigator + '\'' +
                ", rootCauseCategory='" + rootCauseCategory + '\'' +
                ", totalNotes=" + totalInvestigationNotes +
                '}';
    }
}
