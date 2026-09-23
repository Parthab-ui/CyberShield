package com.cybershield.exception;

/**
 * Exception thrown when creating, updating, escalating, or mitigating incidents fails.
 */
public class IncidentManagementException extends CyberShieldException {
    public IncidentManagementException(String message) {
        super(message);
    }

    public IncidentManagementException(String message, Throwable cause) {
        super(message, cause);
    }
}
