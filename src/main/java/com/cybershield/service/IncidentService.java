package com.cybershield.service;

import com.cybershield.exception.DatabaseOperationException;
import com.cybershield.exception.IncidentManagementException;
import com.cybershield.model.Incident;
import com.cybershield.model.ResponseAction;
import com.cybershield.model.Threat;
import com.cybershield.model.enums.IncidentStatus;
import com.cybershield.model.enums.ResponseActionType;
import com.cybershield.model.enums.ThreatStatus;
import com.cybershield.repository.DatabaseManager;
import com.cybershield.repository.IncidentRepository;
import com.cybershield.repository.ResponseActionRepository;
import com.cybershield.repository.ThreatRepository;
import com.cybershield.util.SecurityUtils;
import java.time.LocalDateTime;
import java.util.List;

/**
 * Service managing incident case management and response action orchestration.
 * Implements business workflows for threat escalation, containment, and resolution.
 */
public class IncidentService {

    private final IncidentRepository incidentRepository;
    private final ThreatRepository threatRepository;
    private final ResponseActionRepository responseActionRepository;

    public IncidentService() {
        DatabaseManager db = DatabaseManager.getInstance();
        this.threatRepository = new ThreatRepository(db);
        this.responseActionRepository = new ResponseActionRepository(db);
        this.incidentRepository = new IncidentRepository(db, threatRepository, responseActionRepository);
    }

    public IncidentService(IncidentRepository incidentRepository,
                           ThreatRepository threatRepository,
                           ResponseActionRepository responseActionRepository) {
        this.incidentRepository = incidentRepository;
        this.threatRepository = threatRepository;
        this.responseActionRepository = responseActionRepository;
    }

    /**
     * Escalates an active Threat into an official Incident case.
     * @param threat The detected threat to escalate
     * @param title Custom or generated case title
     * @return Newly created Incident case
     */
    public Incident escalateThreatToIncident(Threat threat, String title) throws IncidentManagementException {
        if (threat == null) {
            throw new IncidentManagementException("Cannot escalate null threat to an incident");
        }

        try {
            String incidentId = SecurityUtils.generateId("INC");
            String caseTitle = (title != null && !title.trim().isEmpty()) ? title :
                    "Security Incident: " + threat.getThreatType().getDisplayName() + " on " + threat.getTargetAsset();

            String description = threat.generateIncidentReport();

            Incident incident = new Incident(incidentId, caseTitle, description, threat.getSeverity(), threat);

            // Update threat status in DB
            threat.setStatus(ThreatStatus.INVESTIGATING);
            threatRepository.updateStatus(threat.getThreatId(), ThreatStatus.INVESTIGATING);

            // Save incident to database
            return incidentRepository.save(incident);

        } catch (DatabaseOperationException e) {
            throw new IncidentManagementException("Failed to escalate threat to incident: " + e.getMessage(), e);
        }
    }

    /**
     * Executes a simulated incident response containment action.
     * Note: purely simulated state update for educational demonstration.
     * @param incidentId Target incident ID
     * @param actionType The response action category to dispatch
     * @param executedBy Analyst executing the action
     * @param customDetails Additional containment notes
     * @return Recorded ResponseAction entity
     */
    public ResponseAction executeResponseAction(String incidentId, ResponseActionType actionType,
                                                String executedBy, String customDetails) throws IncidentManagementException {
        if (incidentId == null || actionType == null) {
            throw new IncidentManagementException("Incident ID and Response Action Type are mandatory");
        }

        try {
            Incident incident = incidentRepository.findById(incidentId);
            if (incident == null) {
                throw new IncidentManagementException("Incident not found: " + incidentId);
            }

            String target = (incident.getAssociatedThreat() != null) ?
                    incident.getAssociatedThreat().getSourceIp() : "Endpoint";

            if (actionType == ResponseActionType.DISABLE_USER && incident.getAssociatedThreat() != null) {
                target = incident.getAssociatedThreat().getTargetAsset();
            }

            String actionId = SecurityUtils.generateId("ACT");
            String details = (customDetails != null && !customDetails.trim().isEmpty()) ? customDetails :
                    actionType.getDescription() + " (Target: " + target + ")";

            ResponseAction action = new ResponseAction(actionId, incidentId, actionType, target, executedBy, details);

            // Persist action
            responseActionRepository.save(action);

            // Update incident state
            incident.addResponseAction(action);
            incident.setStatus(IncidentStatus.INVESTIGATING);
            incident.setUpdatedAt(LocalDateTime.now());
            incidentRepository.update(incident);

            // If threat is associated, update its status
            if (incident.getAssociatedThreat() != null) {
                threatRepository.updateStatus(incident.getAssociatedThreat().getThreatId(), ThreatStatus.INVESTIGATING);
            }

            return action;

        } catch (DatabaseOperationException e) {
            throw new IncidentManagementException("Failed to execute response action: " + e.getMessage(), e);
        }
    }

    /**
     * Resolves an open incident and updates the associated threat to RESOLVED status.
     */
    public void resolveIncident(String incidentId, String analystNotes) throws IncidentManagementException {
        try {
            Incident incident = incidentRepository.findById(incidentId);
            if (incident == null) {
                throw new IncidentManagementException("Incident not found: " + incidentId);
            }

            incident.setStatus(IncidentStatus.RESOLVED);
            if (analystNotes != null && !analystNotes.trim().isEmpty()) {
                incident.setDescription(incident.getDescription() + "\n\n=== RESOLUTION NOTES ===\n" + analystNotes);
            }
            incident.setUpdatedAt(LocalDateTime.now());
            incidentRepository.update(incident);

            if (incident.getAssociatedThreat() != null) {
                threatRepository.updateStatus(incident.getAssociatedThreat().getThreatId(), ThreatStatus.RESOLVED);
            }

        } catch (DatabaseOperationException e) {
            throw new IncidentManagementException("Failed to resolve incident " + incidentId + ": " + e.getMessage(), e);
        }
    }

    public List<Incident> getAllIncidents() throws DatabaseOperationException {
        return incidentRepository.findAll();
    }

    public Incident getIncidentById(String incidentId) throws DatabaseOperationException {
        return incidentRepository.findById(incidentId);
    }
}
