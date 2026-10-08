package cybershield.util;

import java.awt.Color;

/**
 * ThemeSettings — Stores runtime theme, alert, and session preferences.
 * Holds static fields so settings can be read or modified across all GUI panels.
 * Preserves AppSettings without modification while handling Module C settings.
 */
public class ThemeSettings {

    // Default configuration constants
    public static final Color DEFAULT_ACCENT = Theme.ACCENT;
    public static final String DEFAULT_FONT_SIZE = "Medium";
    public static final boolean DEFAULT_SOUND_ALERTS = true;
    public static final boolean DEFAULT_AUTO_REFRESH = true;
    public static final int DEFAULT_SESSION_TIMEOUT = 30;
    public static final boolean DEFAULT_DARK_MODE = true;

    // Runtime state variables
    private static Color accentColor = DEFAULT_ACCENT;
    private static String fontSize = DEFAULT_FONT_SIZE;
    private static boolean soundAlertsEnabled = DEFAULT_SOUND_ALERTS;
    private static boolean autoRefreshDashboard = DEFAULT_AUTO_REFRESH;
    private static int sessionTimeoutMinutes = DEFAULT_SESSION_TIMEOUT;
    private static boolean isDarkMode = DEFAULT_DARK_MODE;

    // Private constructor prevents instantiation
    private ThemeSettings() { }

    /** Returns the current UI accent color. */
    public static Color getAccentColor() {
        return accentColor;
    }

    /** Updates the UI accent color. */
    public static void setAccentColor(Color color) {
        if (color != null) {
            accentColor = color;
        }
    }

    /** Returns the current font size setting ("Small", "Medium", "Large"). */
    public static String getFontSize() {
        return fontSize;
    }

    /** Updates the font size setting. */
    public static void setFontSize(String size) {
        if (size != null) {
            fontSize = size;
        }
    }

    /** Returns the base integer font point size based on fontSize name. */
    public static int getBaseFontSize() {
        if ("Small".equalsIgnoreCase(fontSize)) {
            return 12;
        } else if ("Large".equalsIgnoreCase(fontSize)) {
            return 16;
        }
        return 14; // Medium default
    }

    /** Returns true if audible alert notifications are enabled. */
    public static boolean isSoundAlertsEnabled() {
        return soundAlertsEnabled;
    }

    /** Sets whether audible alert notifications are enabled. */
    public static void setSoundAlertsEnabled(boolean enabled) {
        soundAlertsEnabled = enabled;
    }

    /** Returns true if dashboard auto-refresh is active. */
    public static boolean isAutoRefreshDashboard() {
        return autoRefreshDashboard;
    }

    /** Sets whether dashboard auto-refresh is active. */
    public static void setAutoRefreshDashboard(boolean enabled) {
        autoRefreshDashboard = enabled;
    }

    /** Returns the session inactivity timeout in minutes. */
    public static int getSessionTimeoutMinutes() {
        return sessionTimeoutMinutes;
    }

    /** Updates the session inactivity timeout in minutes (min 5, max 120). */
    public static void setSessionTimeoutMinutes(int minutes) {
        if (minutes >= 5 && minutes <= 120) {
            sessionTimeoutMinutes = minutes;
        }
    }

    /** Returns true if dark mode is active, false if light mode. */
    public static boolean isDarkMode() {
        return isDarkMode;
    }

    /** Sets dark mode active or inactive. */
    public static void setDarkMode(boolean darkMode) {
        isDarkMode = darkMode;
    }

    /** Resets all configuration settings to factory default values. */
    public static void resetToDefaults() {
        accentColor = DEFAULT_ACCENT;
        fontSize = DEFAULT_FONT_SIZE;
        soundAlertsEnabled = DEFAULT_SOUND_ALERTS;
        autoRefreshDashboard = DEFAULT_AUTO_REFRESH;
        sessionTimeoutMinutes = DEFAULT_SESSION_TIMEOUT;
        isDarkMode = DEFAULT_DARK_MODE;
    }
}
