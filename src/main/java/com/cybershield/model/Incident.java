package com.cybershield.model;

import com.cybershield.model.enums.IncidentStatus;
import com.cybershield.model.enums.Severity;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Domain entity representing an escalated security incident.
 * 
 * CORE OOP PRINCIPLE DEMONSTRATED:
 * Composition:
 * - Incident HAS-A Threat (associatedThreat)
 * - Incident HAS-MANY ResponseAction (responseActions collection)
 */
public class Incident {
    private int id;
    private String incidentId;
    private String title;
    private String description;
    private Severity severity;
    private IncidentStatus status;
    private Threat associatedThreat; // Composition: HAS-A Threat
    private final List<ResponseAction> responseActions; // Composition: HAS-MANY ResponseAction
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    public Incident() {
        this.responseActions = new ArrayList<>();
        this.status = IncidentStatus.OPEN;
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    public Incident(String incidentId, String title, String description,
                    Severity severity, Threat associatedThreat) {
        this.incidentId = incidentId;
        this.title = title;
        this.description = description;
        this.severity = severity != null ? severity : (associatedThreat != null ? associatedThreat.getSeverity() : Severity.LOW);
        this.associatedThreat = associatedThreat;
        this.status = IncidentStatus.OPEN;
        this.responseActions = new ArrayList<>();
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    // Controlled mutator for Composition collection (Encapsulation)
    public void addResponseAction(ResponseAction action) {
        if (action != null) {
            this.responseActions.add(action);
            this.updatedAt = LocalDateTime.now();
        }
    }

    public List<ResponseAction> getResponseActions() {
        return Collections.unmodifiableList(responseActions);
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getIncidentId() {
        return incidentId;
    }

    public void setIncidentId(String incidentId) {
        this.incidentId = incidentId;
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

    public Severity getSeverity() {
        return severity;
    }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }

    public IncidentStatus getStatus() {
        return status;
    }

    public void setStatus(IncidentStatus status) {
        this.status = status != null ? status : IncidentStatus.OPEN;
        this.updatedAt = LocalDateTime.now();
    }

    public Threat getAssociatedThreat() {
        return associatedThreat;
    }

    public void setAssociatedThreat(Threat associatedThreat) {
        this.associatedThreat = associatedThreat;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    @Override
    public String toString() {
        return String.format("[%s] %s | Severity: %s | Status: %s | Threat: %s",
                incidentId, title, severity, status,
                associatedThreat != null ? associatedThreat.getThreatId() : "N/A");
    }
}
