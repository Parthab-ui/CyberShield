package com.cybershield.exception;

/**
 * Exception thrown when user authentication or authorization fails.
 */
public class AuthenticationException extends CyberShieldException {
    public AuthenticationException(String message) {
        super(message);
    }

    public AuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
