package cybershield.model;

/**
 * InvestigationNote — Represents an analyst forensic note or evidence item
 * attached to an incident during triage, investigation, or resolution.
 *
 * Demonstrates: Domain modeling for collaborative SOC incident triage,
 * multi-note correlation, and evidence logging with foreign key integrity.
 */
public class InvestigationNote {

    private int id;
    private int incidentId;             // Foreign key to incidents table
    private String analystUsername;     // Security analyst or admin author
    private String notes;               // Technical investigation narrative
    private String evidenceData;        // Optional evidence payload (hashes, log snippets, PCAP refs)
    private long createdAt;             // Epoch millis when note was recorded

    /** Default constructor required for Google Gson */
    public InvestigationNote() {
    }

    /** Full parameterized constructor */
    public InvestigationNote(int id, int incidentId, String analystUsername,
                             String notes, String evidenceData, long createdAt) {
        this.id = id;
        this.incidentId = incidentId;
        this.analystUsername = analystUsername;
        this.notes = notes;
        this.evidenceData = evidenceData;
        this.createdAt = createdAt;
    }

    /** Constructor for creating new notes before database insertion */
    public InvestigationNote(int incidentId, String analystUsername, String notes, String evidenceData, long createdAt) {
        this(-1, incidentId, analystUsername, notes, evidenceData, createdAt);
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public int getIncidentId() {
        return incidentId;
    }

    public void setIncidentId(int incidentId) {
        this.incidentId = incidentId;
    }

    public String getAnalystUsername() {
        return analystUsername;
    }

    public void setAnalystUsername(String analystUsername) {
        this.analystUsername = analystUsername;
    }

    public String getNotes() {
        return notes;
    }

    public void setNotes(String notes) {
        this.notes = notes;
    }

    public String getEvidenceData() {
        return evidenceData;
    }

    public void setEvidenceData(String evidenceData) {
        this.evidenceData = evidenceData;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }

    @Override
    public String toString() {
        return "InvestigationNote{" +
                "id=" + id +
                ", incidentId=" + incidentId +
                ", analystUsername='" + analystUsername + '\'' +
                ", notes='" + notes + '\'' +
                ", createdAt=" + createdAt +
                '}';
    }
}

