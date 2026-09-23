package com.cybershield.service.detector;

import com.cybershield.exception.ThreatDetectionException;
import com.cybershield.model.BruteForceThreat;
import com.cybershield.model.SecurityEvent;
import com.cybershield.model.Threat;
import com.cybershield.model.enums.EventType;
import com.cybershield.util.SecurityUtils;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Concrete ThreatDetector for identifying Brute Force attacks.
 * Tracks consecutive failed authentication attempts within a sliding time window.
 * Demonstrates Collections (Map, List) and Polymorphic interface implementation.
 */
public class BruteForceDetector implements ThreatDetector {

    private static final int DEFAULT_THRESHOLD = 5;
    private static final int WINDOW_SECONDS = 120;

    // Track failed attempt timestamps per target username (Collections: HashMap, List)
    private final Map<String, List<LocalDateTime>> attemptsByUser = new HashMap<>();

    @Override
    public boolean canDetect(SecurityEvent event) {
        return event != null && event.getEventType() == EventType.AUTH_FAILURE;
    }

    @Override
    public Threat detect(SecurityEvent event) throws ThreatDetectionException {
        if (!canDetect(event)) {
            return null;
        }

        try {
            String userKey = event.getUsername().toLowerCase();
            LocalDateTime eventTime = event.getTimestamp() != null ? event.getTimestamp() : LocalDateTime.now();

            attemptsByUser.putIfAbsent(userKey, new ArrayList<>());
            List<LocalDateTime> timestamps = attemptsByUser.get(userKey);
            timestamps.add(eventTime);

            // Filter out timestamps outside the sliding window
            timestamps.removeIf(t -> Duration.between(t, eventTime).abs().getSeconds() > WINDOW_SECONDS);

            int currentAttempts = timestamps.size();

            // Trigger threat when threshold reached
            if (currentAttempts >= DEFAULT_THRESHOLD) {
                String threatId = SecurityUtils.generateId("THR-BF");
                String desc = String.format("Brute force authentication barrage: %d failed attempts on user '%s'",
                        currentAttempts, event.getUsername());

                return new BruteForceThreat(
                    threatId,
                    event.getSourceIp(),
                    event.getUsername(),
                    currentAttempts,
                    WINDOW_SECONDS,
                    desc
                );
            }

            return null;
        } catch (Exception e) {
            throw new ThreatDetectionException("Failed to evaluate brute force heuristic on event " + event.getEventId(), e);
        }
    }

    @Override
    public String getName() {
        return "Brute Force Detector";
    }

    public void reset() {
        attemptsByUser.clear();
    }
}
