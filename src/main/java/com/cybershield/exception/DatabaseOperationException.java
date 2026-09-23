package com.cybershield.exception;

/**
 * Exception thrown when database read, write, connection, or transaction operations fail.
 */
public class DatabaseOperationException extends CyberShieldException {
    public DatabaseOperationException(String message) {
        super(message);
    }

    public DatabaseOperationException(String message, Throwable cause) {
        super(message, cause);
    }
}
