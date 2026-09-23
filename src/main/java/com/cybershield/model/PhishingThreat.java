package com.cybershield.model;

import com.cybershield.model.enums.ResponseActionType;
import com.cybershield.model.enums.Severity;
import com.cybershield.model.enums.ThreatType;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Concrete Threat subclass representing a simulated phishing email attack.
 * Demonstrates Inheritance and Polymorphic reporting.
 */
public class PhishingThreat extends Threat {
    private String senderEmail;
    private String suspiciousUrl;
    private List<String> keywordHits;

    public PhishingThreat(String threatId, String sourceIp, String targetAccount,
                          String senderEmail, String suspiciousUrl, List<String> keywordHits,
                          String description) {
        super(threatId, ThreatType.PHISHING, sourceIp, targetAccount, description);
        this.senderEmail = senderEmail != null ? senderEmail : "unknown@external.net";
        this.suspiciousUrl = suspiciousUrl != null ? suspiciousUrl : "";
        this.keywordHits = keywordHits != null ? new ArrayList<>(keywordHits) : new ArrayList<>();
        setSeverity(evaluateSeverity());
    }

    @Override
    public Severity evaluateSeverity() {
        if (suspiciousUrl.contains("login") || suspiciousUrl.contains("verify") || (keywordHits != null && keywordHits.size() >= 3)) {
            return Severity.HIGH;
        } else if (keywordHits != null && !keywordHits.isEmpty()) {
            return Severity.MEDIUM;
        } else {
            return Severity.LOW;
        }
    }

    @Override
    public String generateIncidentReport() {
        return String.format(
            "=== PHISHING CAMPAIGN DOSSIER ===\n" +
            "Threat ID: %s\n" +
            "Sender Address: %s\n" +
            "Deceptive URL: %s\n" +
            "Matched Indicators: %s\n" +
            "Target User: %s\n" +
            "Calculated Severity: %s\n" +
            "Remediation Advice: Mark message for security review, block inbound sender domain, reset potentially harvested user tokens.\n",
            getThreatId(), senderEmail, suspiciousUrl, keywordHits,
            getTargetAsset(), getSeverity()
        );
    }

    @Override
    public ResponseActionType getRecommendedAction() {
        return ResponseActionType.MARK_FOR_REVIEW;
    }

    public String getSenderEmail() {
        return senderEmail;
    }

    public void setSenderEmail(String senderEmail) {
        this.senderEmail = senderEmail;
    }

    public String getSuspiciousUrl() {
        return suspiciousUrl;
    }

    public void setSuspiciousUrl(String suspiciousUrl) {
        this.suspiciousUrl = suspiciousUrl;
        setSeverity(evaluateSeverity());
    }

    public List<String> getKeywordHits() {
        return Collections.unmodifiableList(keywordHits);
    }

    public void setKeywordHits(List<String> keywordHits) {
        this.keywordHits = keywordHits != null ? new ArrayList<>(keywordHits) : new ArrayList<>();
        setSeverity(evaluateSeverity());
    }
}
