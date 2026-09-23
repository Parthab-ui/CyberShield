package com.cybershield.service.detector;

import com.cybershield.exception.ThreatDetectionException;
import com.cybershield.model.PhishingThreat;
import com.cybershield.model.SecurityEvent;
import com.cybershield.model.Threat;
import com.cybershield.model.enums.EventType;
import com.cybershield.util.SecurityUtils;
import java.util.ArrayList;
import java.util.List;

/**
 * Concrete ThreatDetector for identifying simulated phishing campaigns.
 * Heuristically inspects inbound email payloads for suspicious domains, deceptive URLs, and keywords.
 */
public class PhishingDetector implements ThreatDetector {

    private static final String[] PHISHING_KEYWORDS = {
        "verify", "urgent", "payroll", "suspended", "password", "bank", "invoice", "gift card", "wire transfer", "login"
    };

    @Override
    public boolean canDetect(SecurityEvent event) {
        return event != null && (event.getEventType() == EventType.SUSPICIOUS_EMAIL ||
                (event.getDescription() != null && event.getDescription().toLowerCase().contains("email")));
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

            List<String> matchedKeywords = new ArrayList<>();
            for (String kw : PHISHING_KEYWORDS) {
                if (lower.contains(kw)) {
                    matchedKeywords.add(kw);
                }
            }

            // Extract embedded URL if present
            String url = "http://suspicious-link.net/login";
            if (payload.contains("EMBEDDED_URL='")) {
                int start = payload.indexOf("EMBEDDED_URL='") + 14;
                int end = payload.indexOf("'", start);
                if (end > start) {
                    url = payload.substring(start, end);
                }
            }

            // Extract sender if present
            String sender = "spoofed@external-alert.org";
            if (payload.contains("MAIL_FROM=<")) {
                int start = payload.indexOf("MAIL_FROM=<") + 11;
                int end = payload.indexOf(">", start);
                if (end > start) {
                    sender = payload.substring(start, end);
                }
            }

            // Trigger threat if suspicious keywords or URLs found
            if (!matchedKeywords.isEmpty() || url.contains("login") || url.contains("verify") || lower.contains("spf=fail")) {
                String threatId = SecurityUtils.generateId("THR-PHISH");
                String desc = String.format("Phishing email detected with %d deceptive keywords targeting '%s'",
                        matchedKeywords.size(), event.getUsername());

                return new PhishingThreat(
                    threatId,
                    event.getSourceIp(),
                    event.getUsername(),
                    sender,
                    url,
                    matchedKeywords,
                    desc
                );
            }

            return null;
        } catch (Exception e) {
            throw new ThreatDetectionException("Failed to analyze phishing indicators on event " + event.getEventId(), e);
        }
    }

    @Override
    public String getName() {
        return "Phishing Detector";
    }
}
