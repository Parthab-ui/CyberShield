package cybershield.model;

import java.sql.Timestamp;

/**
 * LogEntry — Represents one audit log record (who did what and when).
 * Demonstrates ENCAPSULATION: all fields are private, accessed through getters/setters.
 */
public class LogEntry {

    private int id;
    private int userId;       // FK to users table
    private String action;    // Description of the action performed
    private Timestamp logTime;

    // Default constructor
    public LogEntry() { }

    // Constructor with all fields
    public LogEntry(int id, int userId, String action, Timestamp logTime) {
        this.id = id;
        this.userId = userId;
        this.action = action;
        this.logTime = logTime;
    }

    // Constructor without id (for inserting new log entries)
    public LogEntry(int userId, String action) {
        this.userId = userId;
        this.action = action;
    }

    // -------- Getters and Setters (Encapsulation) --------

    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    public int getUserId() { return userId; }
    public void setUserId(int userId) { this.userId = userId; }

    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }

    public Timestamp getLogTime() { return logTime; }
    public void setLogTime(Timestamp logTime) { this.logTime = logTime; }

    /** Returns a readable string representation of this log entry. */
    @Override
    public String toString() {
        return "LogEntry{id=" + id + ", userId=" + userId + ", action='" + action + "'}";
    }
}
