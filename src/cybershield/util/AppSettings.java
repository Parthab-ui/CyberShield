package cybershield.util;

/**
 * AppSettings — Stores application-wide settings that can be changed at runtime.
 * Uses static fields so any class can read or write them without creating an object.
 * Covers: alert sensitivity (set by the slider) and auto-refresh interval (set by spinner).
 */
public class AppSettings {

    // How sensitive the alert system should be (1 = low, 10 = high). Default is 5.
    private static int alertSensitivity = 5;

    // How many seconds between auto-refresh ticks. Default is 10.
    private static int refreshIntervalSeconds = 10;

    // Private constructor — this class is never instantiated
    private AppSettings() { }

    /** Returns the current alert sensitivity level (1-10). */
    public static int getAlertSensitivity() {
        return alertSensitivity;
    }

    /** Sets the alert sensitivity level. Value must be between 1 and 10. */
    public static void setAlertSensitivity(int value) {
        alertSensitivity = value;
    }

    /** Returns the auto-refresh interval in seconds. */
    public static int getRefreshIntervalSeconds() {
        return refreshIntervalSeconds;
    }

    /** Sets the auto-refresh interval in seconds. Value must be between 5 and 60. */
    public static void setRefreshIntervalSeconds(int value) {
        refreshIntervalSeconds = value;
    }
}
