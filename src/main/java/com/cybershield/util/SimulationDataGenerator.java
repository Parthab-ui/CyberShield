package com.cybershield.util;

import com.cybershield.model.SecurityEvent;
import com.cybershield.model.enums.EventType;
import com.cybershield.model.enums.Severity;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Generates realistic, strictly simulated security event telemetry datasets.
 * NOTE: Educational simulation only - no actual network requests or exploits.
 */
public final class SimulationDataGenerator {

    private static final Random RANDOM = new Random();

    private SimulationDataGenerator() {
        // Utility class
    }

    /**
     * Generates a rapid cluster of simulated authentication failure events targeting an account.
     */
    public static List<SecurityEvent> generateBruteForceEvents(String targetUser, String attackerIp, int count) {
        List<SecurityEvent> events = new ArrayList<>();
        String user = (targetUser != null && !targetUser.isEmpty()) ? targetUser : "root";
        String ip = (attackerIp != null && !attackerIp.isEmpty()) ? attackerIp : "192.168.1.105";

        LocalDateTime baseTime = LocalDateTime.now().minusSeconds(count * 3L);
        for (int i = 1; i <= count; i++) {
            LocalDateTime eventTime = baseTime.plusSeconds(i * 3L);
            String eventId = SecurityUtils.generateId("EVT");
            String description = String.format("Failed SSH authentication password attempt #%d for user '%s'", i, user);
            String rawPayload = String.format("sshd[2841]: Failed password for %s from %s port %d ssh2", user, ip, 49152 + i);

            SecurityEvent event = new SecurityEvent(
                eventId, eventTime, EventType.AUTH_FAILURE, ip, user,
                description, rawPayload, (i >= 5 ? Severity.HIGH : Severity.MEDIUM)
            );
            events.add(event);
        }
        return events;
    }

    /**
     * Generates a simulated spear phishing inbound email telemetry event.
     */
    public static SecurityEvent generatePhishingEvent(String recipient, String sender, String subject, String url) {
        String target = (recipient != null && !recipient.isEmpty()) ? recipient : "finance@corporate.internal";
        String from = (sender != null && !sender.isEmpty()) ? sender : "security-update@paypal-verify-alert.com";
        String subj = (subject != null && !subject.isEmpty()) ? subject : "URGENT: Verify your payroll credentials immediately";
        String link = (url != null && !url.isEmpty()) ? url : "http://portal-verify-login.com/auth";
        String ip = "198.51.100." + (RANDOM.nextInt(200) + 10);

        String eventId = SecurityUtils.generateId("EVT");
        String desc = String.format("Inbound deceptive email received with suspicious URL matching phishing heuristic");
        String payload = String.format("MAIL_FROM=<%s> RCPT_TO=<%s> SUBJECT='%s' EMBEDDED_URL='%s' SPF=FAIL DMARC=FAIL",
                from, target, subj, link);

        return new SecurityEvent(eventId, LocalDateTime.now(), EventType.SUSPICIOUS_EMAIL, ip, target, desc, payload, Severity.HIGH);
    }

    /**
     * Generates a simulated ransomware or trojan binary drop telemetry event.
     */
    public static SecurityEvent generateMalwareEvent(String hostname, String fileName, String hash) {
        String host = (hostname != null && !hostname.isEmpty()) ? hostname : "WORKSTATION-04";
        String file = (fileName != null && !fileName.isEmpty()) ? fileName : "C:\\Users\\Public\\invoice_macro_updater.exe";
        String sha256 = (hash != null && !hash.isEmpty()) ? hash : "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        String ip = "10.0.4.88";

        String eventId = SecurityUtils.generateId("EVT");
        String desc = String.format("Suspicious executable creation and process spawn detected on endpoint '%s'", host);
        String payload = String.format("ENDPOINT='%s' FILE='%s' SHA256='%s' ACTION='PROCESS_CREATE' INTEGRITY='SYSTEM'",
                host, file, sha256);

        return new SecurityEvent(eventId, LocalDateTime.now(), EventType.FILE_ACCESS, ip, host, desc, payload, Severity.CRITICAL);
    }

    /**
     * Generates a simulated geographical anomaly / unusual hour login event.
     */
    public static SecurityEvent generateSuspiciousLoginEvent(String user, String anomalyLocation, String foreignIp) {
        String target = (user != null && !user.isEmpty()) ? user : "sarah.admin";
        String loc = (anomalyLocation != null && !anomalyLocation.isEmpty()) ? anomalyLocation : "Vladivostok, Russia";
        String ip = (foreignIp != null && !foreignIp.isEmpty()) ? foreignIp : "185.220.101.5";

        String eventId = SecurityUtils.generateId("EVT");
        String desc = String.format("Atypical authentication outside standard business hours from new geolocated region (%s)", loc);
        String payload = String.format("USER='%s' SRC_IP='%s' GEO='%s' TIME_OF_DAY='03:42:11' DEVICE_ID='DEV-FIREFOX-LINUX-9874' IMPOSSIBLE_TRAVEL=TRUE",
                target, ip, loc);

        return new SecurityEvent(eventId, LocalDateTime.now(), EventType.AUTH_SUCCESS, ip, target, desc, payload, Severity.HIGH);
    }

    /**
     * Generates a benign normal baseline event to interleave in the SOC telemetry feed.
     */
    public static SecurityEvent generateBenignEvent() {
        String[] users = {"alice.dev", "bob.ops", "finance.team", "sysadmin", "clara.qa"};
        String[] ips = {"10.0.1.15", "10.0.1.22", "10.0.2.5", "192.168.10.45", "172.16.0.100"};
        String user = users[RANDOM.nextInt(users.length)];
        String ip = ips[RANDOM.nextInt(ips.length)];

        String eventId = SecurityUtils.generateId("EVT");
        String desc = "Authorized routine SSO login token issued to domain user";
        String payload = String.format("AUTH_METHOD=SAML2.0 USER='%s' IP='%s' STATUS=SUCCESS MFA=VERIFIED", user, ip);

        return new SecurityEvent(eventId, LocalDateTime.now(), EventType.AUTH_SUCCESS, ip, user, desc, payload, Severity.LOW);
    }
}
