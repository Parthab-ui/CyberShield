package com.cybershield.model;

import com.cybershield.model.enums.ResponseActionType;
import java.time.LocalDateTime;

/**
 * Domain entity representing a simulated containment response action.
 * Demonstrates Encapsulation of response lifecycle data.
 */
public class ResponseAction {
    private int id;
    private String actionId;
    private String incidentId;
    private ResponseActionType actionType;
    private String target;
    private String executedBy;
    private String status;
    private String details;
    private LocalDateTime executedAt;

    public ResponseAction() {
        this.executedAt = LocalDateTime.now();
        this.status = "EXECUTED";
    }

    public ResponseAction(String actionId, String incidentId, ResponseActionType actionType,
                          String target, String executedBy, String details) {
        this.actionId = actionId;
        this.incidentId = incidentId;
        this.actionType = actionType;
        this.target = target != null ? target : "N/A";
        this.executedBy = executedBy != null ? executedBy : "system";
        this.details = details != null ? details : "";
        this.status = "EXECUTED";
        this.executedAt = LocalDateTime.now();
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getActionId() {
        return actionId;
    }

    public void setActionId(String actionId) {
        this.actionId = actionId;
    }

    public String getIncidentId() {
        return incidentId;
    }

    public void setIncidentId(String incidentId) {
        this.incidentId = incidentId;
    }

    public ResponseActionType getActionType() {
        return actionType;
    }

    public void setActionType(ResponseActionType actionType) {
        this.actionType = actionType;
    }

    public String getTarget() {
        return target;
    }

    public void setTarget(String target) {
        this.target = target;
    }

    public String getExecutedBy() {
        return executedBy;
    }

    public void setExecutedBy(String executedBy) {
        this.executedBy = executedBy;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }

    public LocalDateTime getExecutedAt() {
        return executedAt;
    }

    public void setExecutedAt(LocalDateTime executedAt) {
        this.executedAt = executedAt;
    }

    @Override
    public String toString() {
        return String.format("[%s] Action: %s on %s by %s -> Status: %s",
                actionId, actionType, target, executedBy, status);
    }
}
