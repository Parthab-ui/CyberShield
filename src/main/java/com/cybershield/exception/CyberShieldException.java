package com.cybershield.exception;

/**
 * Base checked exception class for all CyberShield application-specific errors.
 * Demonstrates clean, domain-specific Exception Handling hierarchy in Java.
 */
public class CyberShieldException extends Exception {
    public CyberShieldException(String message) {
        super(message);
    }

    public CyberShieldException(String message, Throwable cause) {
        super(message, cause);
    }
}
