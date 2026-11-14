package cybershield.model;

/**
 * AccessEvent — Records security events such as login attempts,
 * failed logins, and potential unauthorized access or simulated intrusion attempts.
 * Demonstrates: Security audit trail tracking and event result status.
 */
public class AccessEvent {
    private int id;
    private String attemptedUsername;
    private String source;     // "WEB", "DESKTOP", "SIMULATION"
    private String eventType;  // "LOGIN_SUCCESS", "LOGIN_FAILED", "UNAUTHORIZED_ACCESS", "BRUTE_FORCE_SIM"
    private String result;     // "SUCCESS", "FAILED", "BLOCKED"
    private String createdAt;

    public AccessEvent() {
    }

    public AccessEvent(int id, String attemptedUsername, String source, String eventType, String result, String createdAt) {
        this.id = id;
        this.attemptedUsername = attemptedUsername;
        this.source = source;
        this.eventType = eventType;
        this.result = result;
        this.createdAt = createdAt;
    }

    public AccessEvent(String attemptedUsername, String source, String eventType, String result) {
        this.attemptedUsername = attemptedUsername;
        this.source = source;
        this.eventType = eventType;
        this.result = result;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getAttemptedUsername() {
        return attemptedUsername;
    }

    public void setAttemptedUsername(String attemptedUsername) {
        this.attemptedUsername = attemptedUsername;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getEventType() {
        return eventType;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    public String getResult() {
        return result;
    }

    public void setResult(String result) {
        this.result = result;
    }

    public String getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(String createdAt) {
        this.createdAt = createdAt;
    }

    @Override
    public String toString() {
        return "AccessEvent{id=" + id + ", user='" + attemptedUsername + "', event='" + eventType + "', result='" + result + "'}";
    }
}
