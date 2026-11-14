package cybershield.model;

/**
 * IntrusionDetectionConfig — Centralized configuration parameters for the CyberShield
 * Rule-Based Intrusion Detection System.
 *
 * Demonstrates:
 * - Clear encapsulation of detection rule parameters.
 * - Easy runtime customization and testing flexibility.
 * - Default production constants aligned with academic review specifications:
 *   MAX_FAILED_ATTEMPTS = 5
 *   TIME_WINDOW_MINUTES = 2
 *   ALERT_COOLDOWN_MINUTES = 10
 */
public class IntrusionDetectionConfig {

    public static final int DEFAULT_MAX_FAILED_ATTEMPTS = 5;
    public static final long DEFAULT_TIME_WINDOW_MINUTES = 2;
    public static final long DEFAULT_ALERT_COOLDOWN_MINUTES = 10;

    private int maxFailedAttempts;
    private long timeWindowMinutes;
    private long alertCooldownMinutes;

    public IntrusionDetectionConfig() {
        this(DEFAULT_MAX_FAILED_ATTEMPTS, DEFAULT_TIME_WINDOW_MINUTES, DEFAULT_ALERT_COOLDOWN_MINUTES);
    }

    public IntrusionDetectionConfig(int maxFailedAttempts, long timeWindowMinutes, long alertCooldownMinutes) {
        this.maxFailedAttempts = maxFailedAttempts;
        this.timeWindowMinutes = timeWindowMinutes;
        this.alertCooldownMinutes = alertCooldownMinutes;
    }

    public int getMaxFailedAttempts() {
        return maxFailedAttempts;
    }

    public void setMaxFailedAttempts(int maxFailedAttempts) {
        if (maxFailedAttempts < 1) {
            throw new IllegalArgumentException("Max failed attempts must be at least 1.");
        }
        this.maxFailedAttempts = maxFailedAttempts;
    }

    public long getTimeWindowMinutes() {
        return timeWindowMinutes;
    }

    public void setTimeWindowMinutes(long timeWindowMinutes) {
        if (timeWindowMinutes < 1) {
            throw new IllegalArgumentException("Time window minutes must be at least 1.");
        }
        this.timeWindowMinutes = timeWindowMinutes;
    }

    public long getAlertCooldownMinutes() {
        return alertCooldownMinutes;
    }

    public void setAlertCooldownMinutes(long alertCooldownMinutes) {
        if (alertCooldownMinutes < 0) {
            throw new IllegalArgumentException("Alert cooldown cannot be negative.");
        }
        this.alertCooldownMinutes = alertCooldownMinutes;
    }

    /** Returns time window in milliseconds. */
    public long getTimeWindowMillis() {
        return timeWindowMinutes * 60 * 1000;
    }

    /** Returns cooldown in milliseconds. */
    public long getAlertCooldownMillis() {
        return alertCooldownMinutes * 60 * 1000;
    }

    @Override
    public String toString() {
        return "IntrusionDetectionConfig{" +
                "maxFailedAttempts=" + maxFailedAttempts +
                ", timeWindowMinutes=" + timeWindowMinutes +
                ", alertCooldownMinutes=" + alertCooldownMinutes +
                '}';
    }
}

