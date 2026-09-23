package com.cybershield.service.detector;

import com.cybershield.exception.ThreatDetectionException;
import com.cybershield.model.SecurityEvent;
import com.cybershield.model.Threat;

/**
 * Interface defining contract for detection algorithms in CyberShield.
 * 
 * CORE OOP PRINCIPLES DEMONSTRATED:
 * 1. Interface: Defines a clean behavioral specification for threat detection.
 * 2. Polymorphism: Used in ThreatDetectionEngine to process events across multiple
 *    concrete implementations without coupling to specific attack types.
 */
public interface ThreatDetector {

    /**
     * Inspects whether this detector is capable of evaluating the given telemetry event.
     * @param event Inbound raw security telemetry event
     * @return true if the event matches this detector's domain
     */
    boolean canDetect(SecurityEvent event);

    /**
     * Executes the detection algorithm and generates a concrete Threat if malicious heuristics match.
     * @param event The security event to analyze
     * @return Concrete Threat subclass instance, or null if below threshold
     * @throws ThreatDetectionException If detection heuristic evaluation encounters an error
     */
    Threat detect(SecurityEvent event) throws ThreatDetectionException;

    /**
     * Returns the human-readable name of this detector for display and reporting.
     */
    String getName();
}
