package com.cybershield.service;

import com.cybershield.exception.DatabaseOperationException;
import com.cybershield.exception.ThreatDetectionException;
import com.cybershield.model.SecurityEvent;
import com.cybershield.model.Threat;
import com.cybershield.repository.DatabaseManager;
import com.cybershield.repository.ThreatRepository;
import com.cybershield.service.detector.BruteForceDetector;
import com.cybershield.service.detector.MalwareDetector;
import com.cybershield.service.detector.PhishingDetector;
import com.cybershield.service.detector.SuspiciousLoginDetector;
import com.cybershield.service.detector.ThreatDetector;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Orchestrator engine for running detection algorithms over inbound telemetry.
 * 
 * CORE OOP PRINCIPLES DEMONSTRATED:
 * 1. Composition: ThreatDetectionEngine HAS-MANY ThreatDetector instances.
 * 2. Runtime Polymorphism: Iterates over the List<ThreatDetector> and dispatches
 *    canDetect() and detect() dynamically without casting or manual instance checks.
 */
public class ThreatDetectionEngine {

    // Composition: holds collection of polymorphic detectors
    private final List<ThreatDetector> detectors;
    private final ThreatRepository threatRepository;

    public ThreatDetectionEngine() {
        this(new ThreatRepository(DatabaseManager.getInstance()));
    }

    public ThreatDetectionEngine(ThreatRepository threatRepository) {
        this.threatRepository = threatRepository;
        this.detectors = new ArrayList<>();

        // Register standard detection modules polymorphically
        registerDetector(new BruteForceDetector());
        registerDetector(new PhishingDetector());
        registerDetector(new MalwareDetector());
        registerDetector(new SuspiciousLoginDetector());
    }

    public void registerDetector(ThreatDetector detector) {
        if (detector != null && !detectors.contains(detector)) {
            detectors.add(detector);
        }
    }

    public List<ThreatDetector> getRegisteredDetectors() {
        return Collections.unmodifiableList(detectors);
    }

    /**
     * Evaluates a security event across all registered detectors polymorphically.
     * @param event Inbound security event
     * @return List of newly detected threats (if any)
     * @throws ThreatDetectionException If a detector encounters a critical evaluation error
     */
    public List<Threat> processEvent(SecurityEvent event) throws ThreatDetectionException {
        List<Threat> detectedThreats = new ArrayList<>();
        if (event == null) return detectedThreats;

        // Pure Runtime Polymorphism
        for (ThreatDetector detector : detectors) {
            if (detector.canDetect(event)) {
                Threat threat = detector.detect(event);
                if (threat != null) {
                    detectedThreats.add(threat);
                    try {
                        threatRepository.save(threat);
                    } catch (DatabaseOperationException e) {
                        System.err.println("Warning: Failed to persist detected threat to database: " + e.getMessage());
                    }
                }
            }
        }
        return detectedThreats;
    }

    /**
     * Processes a stream or batch of security events.
     * @param events List of security events
     * @return List of all threats detected across the batch
     * @throws ThreatDetectionException If detection evaluation fails
     */
    public List<Threat> processEvents(List<SecurityEvent> events) throws ThreatDetectionException {
        List<Threat> allThreats = new ArrayList<>();
        if (events == null || events.isEmpty()) return allThreats;

        for (SecurityEvent event : events) {
            List<Threat> threats = processEvent(event);
            allThreats.addAll(threats);
        }
        return allThreats;
    }
}
