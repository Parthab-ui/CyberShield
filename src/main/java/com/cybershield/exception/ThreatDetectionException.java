package com.cybershield.exception;

/**
 * Exception thrown when threat parsing, detection heuristics, or detector evaluation fails.
 */
public class ThreatDetectionException extends CyberShieldException {
    public ThreatDetectionException(String message) {
        super(message);
    }

    public ThreatDetectionException(String message, Throwable cause) {
        super(message, cause);
    }
}
