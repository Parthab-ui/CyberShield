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
import java.awt.Toolkit;
import java.time.LocalDateTime;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JSlider;
import javax.swing.JTextArea;

/**
 * Panel driving live simulated cyber threat scenarios.
 * NOTE: Educational simulation only - safe mock telemetry without actual exploits.
 * Demonstrates:
 * - Swing components: JProgressBar, JRadioButton, ButtonGroup, JSlider, JCheckBox, JTextArea, JButton.
 */
public class AttackSimulatorPanel extends JPanel {

    private final SimulationService simulationService;
    private final IncidentService incidentService;
    private final JTextArea txtLiveConsole;
    private final JCheckBox chkAutoEscalate;
    private final JCheckBox chkAudioBeep;
    private final JProgressBar progressBar;
    private final JSlider sliderDelay;
    private final JLabel lblDelayVal;

    private JRadioButton rbStandard;
    private JRadioButton rbRapid;
    private JRadioButton rbStealth;

    private Runnable onSimulationCompleteCallback;

    public AttackSimulatorPanel() {
        this.simulationService = new SimulationService();
        this.incidentService = new IncidentService();

        setLayout(new BorderLayout(12, 12));
        setBackground(CyberTheme.BG_DARK);
        setBorder(BorderFactory.createEmptyBorder(14, 14, 14, 14));

        // 1. Top Header and Disclaimer Banner
        JPanel topContainer = new JPanel(new BorderLayout(8, 8));
        topContainer.setOpaque(false);

        JLabel lblTitle = new JLabel("🎯 CYBER THREAT ATTACK SCENARIO SIMULATOR");
        lblTitle.setFont(CyberTheme.FONT_TITLE);
        lblTitle.setForeground(CyberTheme.TEXT_PRIMARY);

        JPanel bannerPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 8, 6));
        bannerPanel.setBackground(new Color(69, 10, 10)); // Deep Dark Red Banner
        bannerPanel.setBorder(BorderFactory.createLineBorder(CyberTheme.STATUS_RED, 1));
        JLabel lblBanner = new JLabel("⚠️ SIMULATION ONLY — Safe educational mock telemetry. No offensive penetration testing, exploits, or packet sniffing performed.");
        lblBanner.setFont(CyberTheme.FONT_BODY_BOLD);
        lblBanner.setForeground(CyberTheme.STATUS_RED);
        bannerPanel.add(lblBanner);

        topContainer.add(lblTitle, BorderLayout.NORTH);
        topContainer.add(bannerPanel, BorderLayout.SOUTH);
        add(topContainer, BorderLayout.NORTH);

        // 2. Center Scenario Cards Grid
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

        // 3. Execution Toolbar: Mode RadioButtons, Pacing Slider, and Progress Bar
        JPanel execControlBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 4));
        execControlBar.setBackground(CyberTheme.BG_CARD);
        execControlBar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                BorderFactory.createEmptyBorder(4, 10, 4, 10)
        ));

        JLabel lblProfile = new JLabel("Profile (JRadioButton):");
        lblProfile.setFont(CyberTheme.FONT_BODY_BOLD);
        lblProfile.setForeground(CyberTheme.ACCENT_CYAN);
        execControlBar.add(lblProfile);

        rbStandard = new JRadioButton("Standard Heuristic", true);
        rbRapid = new JRadioButton("Rapid Spray", false);
        rbStealth = new JRadioButton("Stealth Infiltration", false);

        ButtonGroup profileGroup = new ButtonGroup();
        profileGroup.add(rbStandard);
        profileGroup.add(rbRapid);
        profileGroup.add(rbStealth);

        for (JRadioButton rb : new JRadioButton[]{rbStandard, rbRapid, rbStealth}) {
            rb.setOpaque(false);
            rb.setForeground(CyberTheme.TEXT_PRIMARY);
            rb.setFont(CyberTheme.FONT_SMALL);
            execControlBar.add(rb);
        }

        execControlBar.add(new JSeparator(JSeparator.VERTICAL) {{ setPreferredSize(new Dimension(2, 20)); }});

        JLabel lblSlider = new JLabel("Pace Delay (JSlider):");
        lblSlider.setFont(CyberTheme.FONT_BODY_BOLD);
        lblSlider.setForeground(CyberTheme.STATUS_AMBER);
        execControlBar.add(lblSlider);

        sliderDelay = new JSlider(50, 500, 150);
        sliderDelay.setOpaque(false);
        sliderDelay.setPreferredSize(new Dimension(120, 24));
        lblDelayVal = new JLabel("150ms");
        lblDelayVal.setFont(CyberTheme.FONT_MONO);
        lblDelayVal.setForeground(CyberTheme.TEXT_PRIMARY);

        sliderDelay.addChangeListener(e -> lblDelayVal.setText(sliderDelay.getValue() + "ms"));
        execControlBar.add(sliderDelay);
        execControlBar.add(lblDelayVal);

        execControlBar.add(new JSeparator(JSeparator.VERTICAL) {{ setPreferredSize(new Dimension(2, 20)); }});

        // JProgressBar
        JLabel lblProgress = new JLabel("Execution (JProgressBar):");
        lblProgress.setFont(CyberTheme.FONT_BODY_BOLD);
        lblProgress.setForeground(CyberTheme.STATUS_GREEN);
        execControlBar.add(lblProgress);

        progressBar = new JProgressBar(0, 100);
        progressBar.setValue(0);
        progressBar.setStringPainted(true);
        progressBar.setString("Ready (0%)");
        progressBar.setPreferredSize(new Dimension(160, 20));
        progressBar.setBackground(CyberTheme.BG_DARK);
        progressBar.setForeground(CyberTheme.ACCENT_CYAN);
        execControlBar.add(progressBar);

        // 4. Bottom Console Output
        txtLiveConsole = new JTextArea("=== CyberShield Simulation Engine Ready. Select a scenario above to execute. ===\n");
        txtLiveConsole.setEditable(false);
        txtLiveConsole.setFont(CyberTheme.FONT_MONO);
        txtLiveConsole.setBackground(CyberTheme.BG_CARD);
        txtLiveConsole.setForeground(new Color(52, 211, 153)); // Terminal green
        txtLiveConsole.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel bottomContainer = new JPanel(new BorderLayout(8, 8));
        bottomContainer.setOpaque(false);
        bottomContainer.setPreferredSize(new Dimension(800, 230));

        JPanel consoleHeader = new JPanel(new BorderLayout(8, 4));
        consoleHeader.setOpaque(false);
        JLabel lblConsoleTitle = new JLabel("SIMULATION EXECUTION TRACE CONSOLE");
        lblConsoleTitle.setFont(CyberTheme.FONT_HEADER);
        lblConsoleTitle.setForeground(CyberTheme.ACCENT_CYAN);

        chkAutoEscalate = new JCheckBox("Auto-escalate threats to Incidents (JCheckBox)", true);
        chkAutoEscalate.setOpaque(false);
        chkAutoEscalate.setFont(CyberTheme.FONT_SMALL);
        chkAutoEscalate.setForeground(CyberTheme.TEXT_MUTED);

        chkAudioBeep = new JCheckBox("Audio Chime Alert", true);
        chkAudioBeep.setOpaque(false);
        chkAudioBeep.setFont(CyberTheme.FONT_SMALL);
        chkAudioBeep.setForeground(CyberTheme.TEXT_MUTED);

        StyledButton btnClearConsole = new StyledButton("Clear Console", StyledButton.ButtonStyle.SECONDARY);
        btnClearConsole.addActionListener(e -> {
            txtLiveConsole.setText("=== Simulation Engine Ready. Select a scenario above to test. ===\n");
            progressBar.setValue(0);
            progressBar.setString("Ready (0%)");
        });

        JPanel consoleActions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        consoleActions.setOpaque(false);
        consoleActions.add(chkAutoEscalate);
        consoleActions.add(chkAudioBeep);
        consoleActions.add(btnClearConsole);

        consoleHeader.add(lblConsoleTitle, BorderLayout.WEST);
        consoleHeader.add(consoleActions, BorderLayout.EAST);

        JScrollPane consoleScroll = new JScrollPane(txtLiveConsole);
        consoleScroll.setBorder(BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1));

        bottomContainer.add(execControlBar, BorderLayout.NORTH);
        bottomContainer.add(consoleScroll, BorderLayout.CENTER);

        JPanel centerPanel = new JPanel(new BorderLayout(0, 10));
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

    private void updateProgress(int val, String status) {
        javax.swing.SwingUtilities.invokeLater(() -> {
            progressBar.setValue(val);
            progressBar.setString(status + " (" + val + "%)");
        });
    }

    private void logTrace(String msg) {
        String timestamp = DateTimeUtils.formatTimeOnly(LocalDateTime.now());
        txtLiveConsole.append(String.format("[%s] %s\n", timestamp, msg));
        txtLiveConsole.setCaretPosition(txtLiveConsole.getDocument().getLength());
    }

    private void runBruteForceScenario() {
        new Thread(() -> {
            try {
                updateProgress(10, "Starting Brute Force");
                logTrace(">>> STARTING SCENARIO: Brute Force on SSH Port 22");
                Thread.sleep(sliderDelay.getValue());

                updateProgress(35, "Generating Failed Auth Logs");
                logTrace("Generating 6 rapid simulated failed authentication events...");
                var result = simulationService.simulateBruteForce("root", "192.168.1.188", 6);

                for (SecurityEvent evt : result.generatedEvents()) {
                    logTrace("Ingested Event: " + evt.getEventId() + " | " + evt.getDescription());
                }
                Thread.sleep(sliderDelay.getValue());

                updateProgress(70, "Heuristic Evaluation");
                logTrace("ThreatDetectionEngine dispatched to: BruteForceDetector (Polymorphic match)");
                for (Threat t : result.detectedThreats()) {
                    logTrace("⚡ THREAT DETECTED: " + t.getThreatId() + " | Type: " + t.getThreatType() + " | Severity: " + t.getSeverity());
                    if (chkAudioBeep.isSelected()) {
                        Toolkit.getDefaultToolkit().beep();
                    }
                    if (chkAutoEscalate.isSelected()) {
                        Incident inc = incidentService.escalateThreatToIncident(t, "Auto-Escalated Brute Force Incident");
                        logTrace("▲ Auto-Escalated Threat to Incident: " + inc.getIncidentId() + " (Status: OPEN)");
                    }
                }

                updateProgress(100, "Scenario Completed");
                logTrace(">>> SCENARIO COMPLETED: " + result.summaryMessage());
                triggerCallback();
            } catch (Exception ex) {
                logTrace("ERROR during scenario execution: " + ex.getMessage());
                updateProgress(0, "Error");
            }
        }).start();
    }

    private void runPhishingScenario() {
        new Thread(() -> {
            try {
                updateProgress(15, "Dispatching Inbound Email");
                logTrace(">>> STARTING SCENARIO: Spear Phishing Campaign");
                Thread.sleep(sliderDelay.getValue());

                updateProgress(40, "Ingesting Telemetry");
                var result = simulationService.simulatePhishing(
                    "finance@corporate.internal",
                    "payroll-update@secure-portal-verify.com",
                    "URGENT: Mandatory payroll verification required",
                    "http://verify-creds.phish-domain.com/login"
                );

                for (SecurityEvent evt : result.generatedEvents()) {
                    logTrace("Ingested Event: " + evt.getEventId() + " | " + evt.getDescription());
                }
                Thread.sleep(sliderDelay.getValue());

                updateProgress(75, "PhishingDetector Heuristics");
                logTrace("ThreatDetectionEngine dispatched to: PhishingDetector (Polymorphic match)");
                for (Threat t : result.detectedThreats()) {
                    logTrace("⚡ THREAT DETECTED: " + t.getThreatId() + " | Type: " + t.getThreatType() + " | Severity: " + t.getSeverity());
                    if (chkAudioBeep.isSelected()) {
                        Toolkit.getDefaultToolkit().beep();
                    }
                    if (chkAutoEscalate.isSelected()) {
                        Incident inc = incidentService.escalateThreatToIncident(t, "Auto-Escalated Phishing Incident");
                        logTrace("▲ Auto-Escalated Threat to Incident: " + inc.getIncidentId() + " (Status: OPEN)");
                    }
                }

                updateProgress(100, "Scenario Completed");
                logTrace(">>> SCENARIO COMPLETED: " + result.summaryMessage());
                triggerCallback();
            } catch (Exception ex) {
                logTrace("ERROR during scenario execution: " + ex.getMessage());
                updateProgress(0, "Error");
            }
        }).start();
    }

    private void runMalwareScenario() {
        new Thread(() -> {
            try {
                updateProgress(20, "Dropping Binary Payload");
                logTrace(">>> STARTING SCENARIO: Ransomware File Drop Simulation");
                Thread.sleep(sliderDelay.getValue());

                updateProgress(50, "Process Creation Ingested");
                var result = simulationService.simulateMalware(
                    "WORKSTATION-04",
                    "C:\\Users\\Public\\ransom_encryptor_sim.exe",
                    "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
                );

                for (SecurityEvent evt : result.generatedEvents()) {
                    logTrace("Ingested Event: " + evt.getEventId() + " | " + evt.getDescription());
                }
                Thread.sleep(sliderDelay.getValue());

                updateProgress(80, "MalwareDetector Matched");
                logTrace("ThreatDetectionEngine dispatched to: MalwareDetector (Polymorphic match)");
                for (Threat t : result.detectedThreats()) {
                    logTrace("⚡ THREAT DETECTED: " + t.getThreatId() + " | Type: " + t.getThreatType() + " | Severity: " + t.getSeverity());
                    if (chkAudioBeep.isSelected()) {
                        Toolkit.getDefaultToolkit().beep();
                    }
                    if (chkAutoEscalate.isSelected()) {
                        Incident inc = incidentService.escalateThreatToIncident(t, "Auto-Escalated Ransomware Incident");
                        logTrace("▲ Auto-Escalated Threat to Incident: " + inc.getIncidentId() + " (Status: OPEN)");
                    }
                }

                updateProgress(100, "Scenario Completed");
                logTrace(">>> SCENARIO COMPLETED: " + result.summaryMessage());
                triggerCallback();
            } catch (Exception ex) {
                logTrace("ERROR during scenario execution: " + ex.getMessage());
                updateProgress(0, "Error");
            }
        }).start();
    }

    private void runSuspiciousLoginScenario() {
        new Thread(() -> {
            try {
                updateProgress(20, "Detecting Impossible Travel");
                logTrace(">>> STARTING SCENARIO: Suspicious Login Anomaly");
                Thread.sleep(sliderDelay.getValue());

                updateProgress(55, "Ingesting Geographic Ingress");
                var result = simulationService.simulateSuspiciousLogin("sarah.admin", "Vladivostok, Russia", "185.220.101.5");

                for (SecurityEvent evt : result.generatedEvents()) {
                    logTrace("Ingested Event: " + evt.getEventId() + " | " + evt.getDescription());
                }
                Thread.sleep(sliderDelay.getValue());

                updateProgress(85, "Anomaly Heuristic Fired");
                logTrace("ThreatDetectionEngine dispatched to: SuspiciousLoginDetector (Polymorphic match)");
                for (Threat t : result.detectedThreats()) {
                    logTrace("⚡ THREAT DETECTED: " + t.getThreatId() + " | Type: " + t.getThreatType() + " | Severity: " + t.getSeverity());
                    if (chkAudioBeep.isSelected()) {
                        Toolkit.getDefaultToolkit().beep();
                    }
                    if (chkAutoEscalate.isSelected()) {
                        Incident inc = incidentService.escalateThreatToIncident(t, "Auto-Escalated Suspicious Login Incident");
                        logTrace("▲ Auto-Escalated Threat to Incident: " + inc.getIncidentId() + " (Status: OPEN)");
                    }
                }

                updateProgress(100, "Scenario Completed");
                logTrace(">>> SCENARIO COMPLETED: " + result.summaryMessage());
                triggerCallback();
            } catch (Exception ex) {
                logTrace("ERROR during scenario execution: " + ex.getMessage());
                updateProgress(0, "Error");
            }
        }).start();
    }

    private void triggerCallback() {
        if (onSimulationCompleteCallback != null) {
            javax.swing.SwingUtilities.invokeLater(onSimulationCompleteCallback);
        }
    }
}
