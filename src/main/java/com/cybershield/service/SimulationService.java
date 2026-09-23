package com.cybershield.service;

import com.cybershield.exception.DatabaseOperationException;
import com.cybershield.exception.ThreatDetectionException;
import com.cybershield.model.SecurityEvent;
import com.cybershield.model.Threat;
import com.cybershield.repository.DatabaseManager;
import com.cybershield.repository.SecurityEventRepository;
import com.cybershield.util.SimulationDataGenerator;
import java.util.ArrayList;
import java.util.List;

/**
 * Service orchestrating simulated attack scenarios for live demonstration.
 * NOTE: Educational simulation only - safe mock telemetry without actual exploits.
 */
public class SimulationService {

    private final SecurityEventRepository eventRepository;
    private final ThreatDetectionEngine detectionEngine;

    public SimulationService() {
        this(new SecurityEventRepository(DatabaseManager.getInstance()), new ThreatDetectionEngine());
    }

    public SimulationService(SecurityEventRepository eventRepository, ThreatDetectionEngine detectionEngine) {
        this.eventRepository = eventRepository;
        this.detectionEngine = detectionEngine;
    }

    /**
     * Data transfer object returning execution results of a simulation run.
     */
    public record SimulationResult(
        String scenarioName,
        List<SecurityEvent> generatedEvents,
        List<Threat> detectedThreats,
        String summaryMessage
    ) {}

    /**
     * Scenario 1: Simulates Brute Force authentication attack against SSH service.
     */
    public SimulationResult simulateBruteForce(String targetUser, String attackerIp, int attempts) throws ThreatDetectionException, DatabaseOperationException {
        int count = attempts > 0 ? attempts : 6;
        List<SecurityEvent> events = SimulationDataGenerator.generateBruteForceEvents(targetUser, attackerIp, count);

        // Persist events to database
        eventRepository.saveAll(events);

        // Process through detection engine
        List<Threat> threats = detectionEngine.processEvents(events);

        String summary = String.format("Simulated %d failed login attempts targeting '%s' from IP %s. Detected %d threat(s).",
                count, targetUser, attackerIp, threats.size());

        return new SimulationResult("Brute Force on SSH", events, threats, summary);
    }

    /**
     * Scenario 2: Simulates Spear Phishing inbound email attack.
     */
    public SimulationResult simulatePhishing(String recipient, String sender, String subject, String url) throws ThreatDetectionException, DatabaseOperationException {
        SecurityEvent event = SimulationDataGenerator.generatePhishingEvent(recipient, sender, subject, url);

        eventRepository.save(event);

        List<SecurityEvent> events = List.of(event);
        List<Threat> threats = detectionEngine.processEvent(event);

        String summary = String.format("Simulated deceptive phishing email targeting '%s'. Detected %d threat(s).",
                recipient, threats.size());

        return new SimulationResult("Spear Phishing Campaign", events, threats, summary);
    }

    /**
     * Scenario 3: Simulates Ransomware / Malware file drop on endpoint.
     */
    public SimulationResult simulateMalware(String hostname, String fileName, String hash) throws ThreatDetectionException, DatabaseOperationException {
        SecurityEvent event = SimulationDataGenerator.generateMalwareEvent(hostname, fileName, hash);

        eventRepository.save(event);

        List<SecurityEvent> events = List.of(event);
        List<Threat> threats = detectionEngine.processEvent(event);

        String summary = String.format("Simulated suspicious executable creation on host '%s'. Detected %d threat(s).",
                hostname, threats.size());

        return new SimulationResult("Ransomware File Drop Simulation", events, threats, summary);
    }

    /**
     * Scenario 4: Simulates Suspicious Login from atypical foreign location.
     */
    public SimulationResult simulateSuspiciousLogin(String user, String location, String ip) throws ThreatDetectionException, DatabaseOperationException {
        SecurityEvent event = SimulationDataGenerator.generateSuspiciousLoginEvent(user, location, ip);

        eventRepository.save(event);

        List<SecurityEvent> events = List.of(event);
        List<Threat> threats = detectionEngine.processEvent(event);

        String summary = String.format("Simulated anomalous login for user '%s' from %s. Detected %d threat(s).",
                user, location, threats.size());

        return new SimulationResult("Suspicious Login from New Location", events, threats, summary);
    }

    /**
     * Simulates benign background telemetry.
     */
    public List<SecurityEvent> simulateBenignTraffic(int count) throws DatabaseOperationException {
        List<SecurityEvent> list = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            list.add(SimulationDataGenerator.generateBenignEvent());
        }
        eventRepository.saveAll(list);
        return list;
    }
}
