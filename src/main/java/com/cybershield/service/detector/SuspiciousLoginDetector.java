package com.cybershield.service.detector;

import com.cybershield.exception.ThreatDetectionException;
import com.cybershield.model.SecurityEvent;
import com.cybershield.model.SuspiciousLoginThreat;
import com.cybershield.model.Threat;
import com.cybershield.model.enums.EventType;
import com.cybershield.util.SecurityUtils;

/**
 * Concrete ThreatDetector for identifying anomalous user login behavior.
 * Evaluates geographical velocity anomalies, atypical off-hours, and unrecognized device fingerprints.
 */
public class SuspiciousLoginDetector implements ThreatDetector {

    @Override
    public boolean canDetect(SecurityEvent event) {
        return event != null && event.getEventType() == EventType.AUTH_SUCCESS;
    }

    @Override
    public Threat detect(SecurityEvent event) throws ThreatDetectionException {
        if (!canDetect(event)) {
            return null;
        }

        try {
            String payload = (event.getRawPayload() != null ? event.getRawPayload() : "") + " " +
                             (event.getDescription() != null ? event.getDescription() : "");
            String lower = payload.toLowerCase();

            boolean geoAnomaly = lower.contains("impossible_travel=true") || lower.contains("new geolocated") || lower.contains("foreign");
            boolean unusualHour = lower.contains("outside standard") || lower.contains("off-hours") || lower.contains("time_of_day='03:");

            if (geoAnomaly || unusualHour) {
                String device = "DEV-UNTRUSTED";
                if (payload.contains("DEVICE_ID='")) {
                    int start = payload.indexOf("DEVICE_ID='") + 11;
                    int end = payload.indexOf("'", start);
                    if (end > start) {
                        device = payload.substring(start, end);
                    }
                }

                String threatId = SecurityUtils.generateId("THR-LOGIN");
                String desc = String.format("Anomalous authentication detected for user '%s' from IP %s",
                        event.getUsername(), event.getSourceIp());

                return new SuspiciousLoginThreat(
                    threatId,
                    event.getSourceIp(),
                    event.getUsername(),
                    geoAnomaly,
                    unusualHour,
                    device,
                    desc
                );
            }

            return null;
        } catch (Exception e) {
            throw new ThreatDetectionException("Failed to evaluate suspicious login heuristic on event " + event.getEventId(), e);
        }
    }

    @Override
    public String getName() {
        return "Suspicious Login Anomaly Detector";
    }
}
