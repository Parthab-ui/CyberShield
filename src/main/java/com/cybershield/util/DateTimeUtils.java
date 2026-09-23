package com.cybershield.util;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Utility for formatting and parsing local date and time timestamps.
 */
public final class DateTimeUtils {

    public static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    public static final DateTimeFormatter TIME_ONLY_FORMATTER = DateTimeFormatter.ofPattern("HH:mm:ss");

    private DateTimeUtils() {
        // Utility class
    }

    public static String format(LocalDateTime dateTime) {
        if (dateTime == null) {
            return "-";
        }
        return dateTime.format(ISO_FORMATTER);
    }

    public static String formatTimeOnly(LocalDateTime dateTime) {
        if (dateTime == null) {
            return "-";
        }
        return dateTime.format(TIME_ONLY_FORMATTER);
    }

    public static LocalDateTime parse(String str) {
        if (str == null || str.trim().isEmpty()) {
            return LocalDateTime.now();
        }
        try {
            return LocalDateTime.parse(str.trim(), ISO_FORMATTER);
        } catch (Exception e) {
            try {
                return LocalDateTime.parse(str.trim(), DateTimeFormatter.ISO_LOCAL_DATE_TIME);
            } catch (Exception ex) {
                return LocalDateTime.now();
            }
        }
    }
}
