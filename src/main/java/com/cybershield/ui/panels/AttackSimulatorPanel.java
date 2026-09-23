package com.cybershield.ui.panels;

import com.cybershield.exception.IncidentManagementException;
import com.cybershield.model.Incident;
import com.cybershield.model.SecurityEvent;
import com.cybershield.model.Threat;
import com.cybershield.service.IncidentService;
import com.cybershield.service.SimulationService;
import com.cybershield.ui.CyberTheme;
import com.cybershield.ui.components.StyledButton;
import com.cybershield.util.DateTimeUtils;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.time.LocalDateTime;
import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

/**
 * Panel driving live simulated cyber threat scenarios.
 * NOTE: Educational simulation only - safe mock telemetry without actual exploits.
 */
public class AttackSimulatorPanel extends JPanel {

    private final SimulationService simulationService;
    private final IncidentService incidentService;
    private final JTextArea txtLiveConsole;
    private final JCheckBox chkAutoEscalate;
    private Runnable onSimulationCompleteCallback;

    public AttackSimulatorPanel() {
        this.simulationService = new SimulationService();
        this.incidentService = new IncidentService();

        setLayout(new BorderLayout(12, 12));
        setBackground(CyberTheme.BG_DARK);
        setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        // Top Header and Disclaimer Banner
        JPanel topContainer = new JPanel(new BorderLayout(8, 8));
        topContainer.setOpaque(false);

        JLabel lblTitle = new JLabel("CYBER THREAT ATTACK SCENARIO SIMULATOR");
        lblTitle.setFont(CyberTheme.FONT_TITLE);
        lblTitle.setForeground(CyberTheme.TEXT_PRIMARY);

        JPanel bannerPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 8, 8));
        bannerPanel.setBackground(new Color(69, 10, 10)); // Deep Dark Red Banner
        bannerPanel.setBorder(BorderFactory.createLineBorder(CyberTheme.STATUS_RED, 1));
        JLabel lblBanner = new JLabel("⚠️ SIMULATION ONLY — Educational demonstration tool. No offensive penetration testing, exploits, or packet sniffing performed.");
        lblBanner.setFont(CyberTheme.FONT_BODY_BOLD);
        lblBanner.setForeground(CyberTheme.STATUS_RED);
        bannerPanel.add(lblBanner);

        topContainer.add(lblTitle, BorderLayout.NORTH);
        topContainer.add(bannerPanel, BorderLayout.SOUTH);
        add(topContainer, BorderLayout.NORTH);

        // Center Scenario Cards Grid
        JPanel cardsGrid = new JPanel(new GridLayout(2, 2, 12, 12));
        cardsGrid.setOpaque(false);

        cardsGrid.add(createScenarioCard(
            "1. BRUTE FORCE ATTACK",
            "Simulates rapid SSH password spraying against root/admin account from an external IP.",
            "Target: root | Threshold: 6 failures >= 5 | Category: BRUTE_FORCE",
            "SIMULATE BRUTE FORCE",
            StyledButton.ButtonStyle.DANGER,
            () -> runBruteForceScenario()
        ));

        cardsGrid.add(createScenarioCard(
            "2. SPEAR PHISHING CAMPAIGN",
            "Simulates an inbound deceptive corporate payroll verification email with fraudulent login URL.",
            "Sender: spoofed@alert.net | Target: finance@internal | Category: PHISHING",
            "SIMULATE PHISHING",
            StyledButton.ButtonStyle.PRIMARY,
            () -> runPhishingScenario()
        ));

        cardsGrid.add(createScenarioCard(
            "3. RANSOMWARE FILE DROP",
            "Simulates suspicious binary creation and process spawn signature on an internal endpoint.",
            "Host: WORKSTATION-04 | Payload: updater.exe | Category: MALWARE",
            "SIMULATE MALWARE",
            StyledButton.ButtonStyle.DANGER,
            () -> runMalwareScenario()
        ));

        cardsGrid.add(createScenarioCard(
            "4. SUSPICIOUS LOGIN ANOMALY",
            "Simulates impossible travel velocity anomaly and off-hours login from an unrecognized device.",
            "User: sarah.admin | Geo: Vladivostok | Category: SUSPICIOUS_LOGIN",
            "SIMULATE SUSPICIOUS LOGIN",
            StyledButton.ButtonStyle.PRIMARY,
            () -> runSuspiciousLoginScenario()
        ));

        // Bottom Console Output
        txtLiveConsole = new JTextArea("=== CyberShield Simulation Engine Ready. Select a scenario above to execute. ===\n");
        txtLiveConsole.setEditable(false);
        txtLiveConsole.setFont(CyberTheme.FONT_MONO);
        txtLiveConsole.setBackground(CyberTheme.BG_CARD);
        txtLiveConsole.setForeground(new Color(52, 211, 153)); // Terminal green
        txtLiveConsole.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel bottomContainer = new JPanel(new BorderLayout(8, 8));
        bottomContainer.setOpaque(false);
        bottomContainer.setPreferredSize(new Dimension(800, 220));

        JPanel consoleHeader = new JPanel(new BorderLayout(8, 4));
        consoleHeader.setOpaque(false);
        JLabel lblConsoleTitle = new JLabel("SIMULATION EXECUTION TRACE CONSOLE");
        lblConsoleTitle.setFont(CyberTheme.FONT_HEADER);
        lblConsoleTitle.setForeground(CyberTheme.ACCENT_CYAN);

        chkAutoEscalate = new JCheckBox("Auto-escalate detected threats to formal Incidents for demo", true);
        chkAutoEscalate.setOpaque(false);
        chkAutoEscalate.setFont(CyberTheme.FONT_BODY);
        chkAutoEscalate.setForeground(CyberTheme.TEXT_MUTED);

        StyledButton btnClearConsole = new StyledButton("Clear Console", StyledButton.ButtonStyle.SECONDARY);
        btnClearConsole.addActionListener(e -> txtLiveConsole.setText("=== Simulation Engine Ready. Select a scenario above to test. ===\n"));

        JPanel consoleActions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        consoleActions.setOpaque(false);
        consoleActions.add(chkAutoEscalate);
        consoleActions.add(btnClearConsole);

        consoleHeader.add(lblConsoleTitle, BorderLayout.WEST);
        consoleHeader.add(consoleActions, BorderLayout.EAST);

        JScrollPane consoleScroll = new JScrollPane(txtLiveConsole);
        consoleScroll.setBorder(BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1));

        bottomContainer.add(consoleHeader, BorderLayout.NORTH);
        bottomContainer.add(consoleScroll, BorderLayout.CENTER);

        JPanel centerPanel = new JPanel(new BorderLayout(0, 12));
        centerPanel.setOpaque(false);
        centerPanel.add(cardsGrid, BorderLayout.CENTER);
        centerPanel.add(bottomContainer, BorderLayout.SOUTH);

        add(centerPanel, BorderLayout.CENTER);
    }

    public void setOnSimulationCompleteCallback(Runnable callback) {
        this.onSimulationCompleteCallback = callback;
    }

    private JPanel createScenarioCard(String title, String desc, String meta, String buttonText,
                                      StyledButton.ButtonStyle btnStyle, Runnable action) {
        JPanel card = new JPanel(new BorderLayout(8, 8));
        card.setBackground(CyberTheme.BG_CARD);
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                BorderFactory.createEmptyBorder(12, 14, 12, 14)
        ));

        JPanel textPanel = new JPanel(new GridLayout(3, 1, 4, 4));
        textPanel.setOpaque(false);

        JLabel lblTitle = new JLabel(title);
        lblTitle.setFont(CyberTheme.FONT_HEADER);
        lblTitle.setForeground(CyberTheme.ACCENT_CYAN);

        JLabel lblDesc = new JLabel("<html>" + desc + "</html>");
        lblDesc.setFont(CyberTheme.FONT_BODY);
        lblDesc.setForeground(CyberTheme.TEXT_PRIMARY);

        JLabel lblMeta = new JLabel(meta);
        lblMeta.setFont(CyberTheme.FONT_SMALL);
        lblMeta.setForeground(CyberTheme.TEXT_MUTED);

        textPanel.add(lblTitle);
        textPanel.add(lblDesc);
        textPanel.add(lblMeta);

        StyledButton btnTrigger = new StyledButton(buttonText, btnStyle);
        btnTrigger.setPreferredSize(new Dimension(200, 36));
        btnTrigger.addActionListener(e -> action.run());

        card.add(textPanel, BorderLayout.CENTER);
        card.add(btnTrigger, BorderLayout.SOUTH);

        return card;
    }

    private void logTrace(String msg) {
        String timestamp = DateTimeUtils.formatTimeOnly(LocalDateTime.now());
        txtLiveConsole.append(String.format("[%s] %s\n", timestamp, msg));
        txtLiveConsole.setCaretPosition(txtLiveConsole.getDocument().getLength());
    }

    private void runBruteForceScenario() {
        new Thread(() -> {
            try {
                logTrace(">>> STARTING SCENARIO: Brute Force on SSH Port 22");
                logTrace("Generating 6 rapid simulated failed authentication events...");
                var result = simulationService.simulateBruteForce("root", "192.168.1.188", 6);

                for (SecurityEvent evt : result.generatedEvents()) {
                    logTrace("Ingested Event: " + evt.getEventId() + " | " + evt.getDescription());
                }

                logTrace("ThreatDetectionEngine dispatched to: BruteForceDetector (Polymorphic match)");
                for (Threat t : result.detectedThreats()) {
                    logTrace("⚡ THREAT DETECTED: " + t.getThreatId() + " | Type: " + t.getThreatType() + " | Severity: " + t.getSeverity());
                    if (chkAutoEscalate.isSelected()) {
                        Incident inc = incidentService.escalateThreatToIncident(t, "Auto-Escalated Brute Force Incident");
                        logTrace("▲ Auto-Escalated Threat to Incident: " + inc.getIncidentId() + " (Status: OPEN)");
                    }
                }

                logTrace(">>> SCENARIO COMPLETED: " + result.summaryMessage());
                triggerCallback();
            } catch (Exception ex) {
                logTrace("ERROR during scenario execution: " + ex.getMessage());
            }
        }).start();
    }

    private void runPhishingScenario() {
        new Thread(() -> {
            try {
                logTrace(">>> STARTING SCENARIO: Spear Phishing Campaign");
                var result = simulationService.simulatePhishing(
                    "finance@corporate.internal",
                    "payroll-update@secure-portal-verify.com",
                    "URGENT: Mandatory payroll verification required",
                    "http://verify-creds.phish-domain.com/login"
                );

                for (SecurityEvent evt : result.generatedEvents()) {
                    logTrace("Ingested Event: " + evt.getEventId() + " | " + evt.getDescription());
                }

                logTrace("ThreatDetectionEngine dispatched to: PhishingDetector (Polymorphic match)");
                for (Threat t : result.detectedThreats()) {
                    logTrace("⚡ THREAT DETECTED: " + t.getThreatId() + " | Type: " + t.getThreatType() + " | Severity: " + t.getSeverity());
                    if (chkAutoEscalate.isSelected()) {
                        Incident inc = incidentService.escalateThreatToIncident(t, "Auto-Escalated Phishing Incident");
                        logTrace("▲ Auto-Escalated Threat to Incident: " + inc.getIncidentId() + " (Status: OPEN)");
                    }
                }

                logTrace(">>> SCENARIO COMPLETED: " + result.summaryMessage());
                triggerCallback();
            } catch (Exception ex) {
                logTrace("ERROR during scenario execution: " + ex.getMessage());
            }
        }).start();
    }

    private void runMalwareScenario() {
        new Thread(() -> {
            try {
                logTrace(">>> STARTING SCENARIO: Ransomware File Drop Simulation");
                var result = simulationService.simulateMalware(
                    "WORKSTATION-04",
                    "C:\\Users\\Public\\ransom_encryptor_sim.exe",
                    "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
                );

                for (SecurityEvent evt : result.generatedEvents()) {
                    logTrace("Ingested Event: " + evt.getEventId() + " | " + evt.getDescription());
                }

                logTrace("ThreatDetectionEngine dispatched to: MalwareDetector (Polymorphic match)");
                for (Threat t : result.detectedThreats()) {
                    logTrace("⚡ THREAT DETECTED: " + t.getThreatId() + " | Type: " + t.getThreatType() + " | Severity: " + t.getSeverity());
                    if (chkAutoEscalate.isSelected()) {
                        Incident inc = incidentService.escalateThreatToIncident(t, "Auto-Escalated Ransomware Incident");
                        logTrace("▲ Auto-Escalated Threat to Incident: " + inc.getIncidentId() + " (Status: OPEN)");
                    }
                }

                logTrace(">>> SCENARIO COMPLETED: " + result.summaryMessage());
                triggerCallback();
            } catch (Exception ex) {
                logTrace("ERROR during scenario execution: " + ex.getMessage());
            }
        }).start();
    }

    private void runSuspiciousLoginScenario() {
        new Thread(() -> {
            try {
                logTrace(">>> STARTING SCENARIO: Suspicious Login Anomaly");
                var result = simulationService.simulateSuspiciousLogin("sarah.admin", "Vladivostok, Russia", "185.220.101.5");

                for (SecurityEvent evt : result.generatedEvents()) {
                    logTrace("Ingested Event: " + evt.getEventId() + " | " + evt.getDescription());
                }

                logTrace("ThreatDetectionEngine dispatched to: SuspiciousLoginDetector (Polymorphic match)");
                for (Threat t : result.detectedThreats()) {
                    logTrace("⚡ THREAT DETECTED: " + t.getThreatId() + " | Type: " + t.getThreatType() + " | Severity: " + t.getSeverity());
                    if (chkAutoEscalate.isSelected()) {
                        Incident inc = incidentService.escalateThreatToIncident(t, "Auto-Escalated Suspicious Login Incident");
                        logTrace("▲ Auto-Escalated Threat to Incident: " + inc.getIncidentId() + " (Status: OPEN)");
                    }
                }

                logTrace(">>> SCENARIO COMPLETED: " + result.summaryMessage());
                triggerCallback();
            } catch (Exception ex) {
                logTrace("ERROR during scenario execution: " + ex.getMessage());
            }
        }).start();
    }

    private void triggerCallback() {
        if (onSimulationCompleteCallback != null) {
            javax.swing.SwingUtilities.invokeLater(onSimulationCompleteCallback);
        }
    }
}
