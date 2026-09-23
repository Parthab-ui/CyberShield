package com.cybershield.model;

import com.cybershield.model.enums.EventType;
import com.cybershield.model.enums.Severity;
import java.time.LocalDateTime;

/**
 * Domain entity representing raw simulated telemetry events.
 * Demonstrates Encapsulation of event attributes.
 */
public class SecurityEvent {
    private int id;
    private String eventId;
    private LocalDateTime timestamp;
    private EventType eventType;
    private String sourceIp;
    private String username;
    private String description;
    private String rawPayload;
    private Severity severity;

    public SecurityEvent() {
        this.timestamp = LocalDateTime.now();
        this.severity = Severity.LOW;
    }

    public SecurityEvent(String eventId, LocalDateTime timestamp, EventType eventType,
                         String sourceIp, String username, String description,
                         String rawPayload, Severity severity) {
        this.eventId = eventId;
        this.timestamp = timestamp != null ? timestamp : LocalDateTime.now();
        this.eventType = eventType != null ? eventType : EventType.AUTH_FAILURE;
        this.sourceIp = sourceIp != null ? sourceIp : "127.0.0.1";
        this.username = username != null ? username : "system";
        this.description = description != null ? description : "";
        this.rawPayload = rawPayload != null ? rawPayload : "";
        this.severity = severity != null ? severity : Severity.LOW;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getEventId() {
        return eventId;
    }

    public void setEventId(String eventId) {
        this.eventId = eventId;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }

    public EventType getEventType() {
        return eventType;
    }

    public void setEventType(EventType eventType) {
        this.eventType = eventType;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public void setSourceIp(String sourceIp) {
        this.sourceIp = sourceIp;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getRawPayload() {
        return rawPayload;
    }

    public void setRawPayload(String rawPayload) {
        this.rawPayload = rawPayload;
    }

    public Severity getSeverity() {
        return severity;
    }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }

    @Override
    public String toString() {
        return String.format("[%s] %s | %s | User: %s | %s",
                timestamp, eventType, sourceIp, username, description);
    }
}
