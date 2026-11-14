package cybershield.model;

/**
 * InvestigationTimelineItem — Chronological milestone in the lifecycle of an incident investigation.
 * Aggregates incident creation, analyst notes, investigator assignments, root cause categorizations,
 * defensive countermeasures, and final resolution events into a unified forensic event sequence.
 */
public class InvestigationTimelineItem {

    private long timestamp;         // Epoch milliseconds
    private String eventType;       // e.g. "INCIDENT_CREATED", "INVESTIGATION_NOTE_ADDED", "THREAT_RESPONSE_EXECUTED"
    private String actor;           // Username or service (e.g. "IDS_ENGINE", "analyst", "admin")
    private String description;     // Human-readable event description
    private String details;         // Detailed evidence data or payload (optional)

    public InvestigationTimelineItem() {
    }

    public InvestigationTimelineItem(long timestamp, String eventType, String actor, String description, String details) {
        this.timestamp = timestamp;
        this.eventType = eventType;
        this.actor = actor;
        this.description = description;
        this.details = details;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public String getEventType() {
        return eventType;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    public String getActor() {
        return actor;
    }

    public void setActor(String actor) {
        this.actor = actor;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }

    @Override
    public String toString() {
        return "InvestigationTimelineItem{" +
                "timestamp=" + timestamp +
                ", eventType='" + eventType + '\'' +
                ", actor='" + actor + '\'' +
                ", description='" + description + '\'' +
                '}';
    }
}
