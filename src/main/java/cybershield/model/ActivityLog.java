package cybershield.model;

/**
 * ActivityLog — Records business and administrative operations performed by users.
 * Demonstrates: Non-repudiation, accountability, and system audit history.
 * Examples of actions: "USER_LOGIN", "USER_LOGOUT", "INCIDENT_CREATED", "INCIDENT_UPDATED", "INCIDENT_DELETED".
 */
public class ActivityLog {
    private int id;
    private String username;
    private String action;
    private String details;
    private String createdAt;

    public ActivityLog() {
    }

    public ActivityLog(int id, String username, String action, String details, String createdAt) {
        this.id = id;
        this.username = username;
        this.action = action;
        this.details = details;
        this.createdAt = createdAt;
    }

    public ActivityLog(String username, String action, String details) {
        this.username = username;
        this.action = action;
        this.details = details;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }

    public String getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(String createdAt) {
        this.createdAt = createdAt;
    }

    @Override
    public String toString() {
        return "ActivityLog{id=" + id + ", user='" + username + "', action='" + action + "'}";
    }
}
