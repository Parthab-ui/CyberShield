package cybershield.model;

import java.sql.Timestamp;

/**
 * Incident — Represents an incident report linked to a threat.
 * Demonstrates ENCAPSULATION: all fields are private, accessed through getters/setters.
 */
public class Incident {

    private int id;
    private int threatId;         // FK to threats table
    private String title;
    private String description;
    private int assignedTo;       // FK to users table
    private String priority;      // "LOW", "MEDIUM", "HIGH", "CRITICAL"
    private String status;        // "OPEN", "IN_PROGRESS", "CLOSED"
    private Timestamp createdAt;
    private Timestamp closedAt;   // null if not yet closed

    // Default constructor
    public Incident() { }

    // Constructor with all fields
    public Incident(int id, int threatId, String title, String description,
                    int assignedTo, String priority, String status,
                    Timestamp createdAt, Timestamp closedAt) {
        this.id = id;
        this.threatId = threatId;
        this.title = title;
        this.description = description;
        this.assignedTo = assignedTo;
        this.priority = priority;
        this.status = status;
        this.createdAt = createdAt;
        this.closedAt = closedAt;
    }

    // Constructor without id (for inserting new incidents)
    public Incident(int threatId, String title, String description,
                    int assignedTo, String priority, String status) {
        this.threatId = threatId;
        this.title = title;
        this.description = description;
        this.assignedTo = assignedTo;
        this.priority = priority;
        this.status = status;
    }

    // -------- Getters and Setters (Encapsulation) --------

    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    public int getThreatId() { return threatId; }
    public void setThreatId(int threatId) { this.threatId = threatId; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public int getAssignedTo() { return assignedTo; }
    public void setAssignedTo(int assignedTo) { this.assignedTo = assignedTo; }

    public String getPriority() { return priority; }
    public void setPriority(String priority) { this.priority = priority; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public Timestamp getCreatedAt() { return createdAt; }
    public void setCreatedAt(Timestamp createdAt) { this.createdAt = createdAt; }

    public Timestamp getClosedAt() { return closedAt; }
    public void setClosedAt(Timestamp closedAt) { this.closedAt = closedAt; }

    /** Returns a readable string representation of this incident. */
    @Override
    public String toString() {
        return "Incident{id=" + id + ", title='" + title + "', priority='" + priority
                + "', status='" + status + "'}";
    }
}
