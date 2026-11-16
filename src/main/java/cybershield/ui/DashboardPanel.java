package cybershield.ui;

import cybershield.model.DashboardStats;
import cybershield.model.Incident;
import cybershield.model.SecurityAlert;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.table.DefaultTableModel;

/**
 * DashboardPanel — Displays real-time executive security metrics, dedicated IDS alert banner,
 * and recent incident feeds for the CyberShield desktop application.
 *
 * Review 2 Enhancements:
 * - Dedicated Rule-Based Security Alert section highlighting detected brute-force attacks.
 * - Source IP address, failed attempt count, detection timestamp, severity, and status display.
 * - Dynamic counters for detected threats, active alerts, and automatically generated incidents.
 * - Thread-safe EDT synchronization with SQLite backend.
 */
public class DashboardPanel extends JPanel {

    private final ApiClient apiClient = ApiClient.getInstance();

    // Standard metric labels
    private JLabel totalValLabel;
    private JLabel openValLabel;
    private JLabel criticalValLabel;
    private JLabel unauthorizedValLabel;

    // Review 2 metric labels
    private JLabel threatsValLabel;
    private JLabel alertsValLabel;
    private JLabel autoIncValLabel;

    // Dedicated Security Alert Section components
    private JPanel alertBannerPanel;
    private JLabel alertTitleLabel;
    private JLabel alertBadgeLabel;
    private JLabel alertIpLabel;
    private JLabel alertAttemptsLabel;
    private JLabel alertSeverityLabel;
    private JLabel alertStatusLabel;
    private JLabel alertTimeLabel;
    private JLabel alertRuleLabel;

    // Recent Incidents Table
    private DefaultTableModel incidentsModel;
    private JTable incidentsTable;

    // Recent Activity Table
    private DefaultTableModel activityModel;
    private JTable activityTable;

    public DashboardPanel() {
        setBackground(SwingTheme.BG_DARK);
        setLayout(new BorderLayout(0, 14));
        setBorder(BorderFactory.createEmptyBorder(16, 20, 16, 20));

        // Top Header Bar
        add(createHeaderBar(), BorderLayout.NORTH);

        // Center Area: Alert Banner + Metrics Grid + Split Tables
        JPanel centerPanel = new JPanel(new BorderLayout(0, 14));
        centerPanel.setOpaque(false);

        // Top of Center: Alert Banner + KPI Metrics
        JPanel topCenterBox = new JPanel();
        topCenterBox.setOpaque(false);
        topCenterBox.setLayout(new BoxLayout(topCenterBox, BoxLayout.Y_AXIS));
        topCenterBox.add(createSecurityAlertPanel());
        topCenterBox.add(Box.createRigidArea(new Dimension(0, 14)));
        topCenterBox.add(createMetricsGrid());

        centerPanel.add(topCenterBox, BorderLayout.NORTH);
        centerPanel.add(createSplitFeeds(), BorderLayout.CENTER);

        add(centerPanel, BorderLayout.CENTER);

        // Load initial data
        refreshData();
    }

    private JPanel createHeaderBar() {
        JPanel bar = new JPanel(new BorderLayout());
        bar.setOpaque(false);

        JLabel title = new JLabel("Executive Security Posture");
        title.setFont(SwingTheme.FONT_TITLE);
        title.setForeground(SwingTheme.TEXT_PRIMARY);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        btnPanel.setOpaque(false);

        JButton refreshBtn = new JButton("🔄 Refresh Metrics");
        SwingTheme.styleSecondaryButton(refreshBtn);
        refreshBtn.addActionListener(e -> refreshData());

        btnPanel.add(refreshBtn);

        bar.add(title, BorderLayout.WEST);
        bar.add(btnPanel, BorderLayout.EAST);
        return bar;
    }

    /**
     * Dedicated Security Alert section as mandated by Review 2 specifications.
     * Highlights active brute-force threats, source IP, failed attempts, and detection time.
     */
    private JPanel createSecurityAlertPanel() {
        alertBannerPanel = new JPanel(new BorderLayout(0, 10));
        alertBannerPanel.setBackground(new Color(21, 30, 50));
        alertBannerPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(2, 5, 2, 2, SwingTheme.SEVERITY_CRITICAL),
                BorderFactory.createEmptyBorder(12, 16, 12, 16)
        ));

        // Alert Header
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setOpaque(false);

        alertTitleLabel = new JLabel("🚨 SECURITY ALERT: BRUTE FORCE ATTACK DETECTED");
        alertTitleLabel.setFont(SwingTheme.FONT_TITLE);
        alertTitleLabel.setForeground(SwingTheme.TEXT_PRIMARY);

        alertBadgeLabel = new JLabel(" HIGH SEVERITY ");
        alertBadgeLabel.setFont(SwingTheme.FONT_BOLD);
        alertBadgeLabel.setForeground(Color.WHITE);
        alertBadgeLabel.setOpaque(true);
        alertBadgeLabel.setBackground(SwingTheme.SEVERITY_CRITICAL);
        alertBadgeLabel.setBorder(BorderFactory.createEmptyBorder(3, 8, 3, 8));

        headerPanel.add(alertTitleLabel, BorderLayout.WEST);
        headerPanel.add(alertBadgeLabel, BorderLayout.EAST);

        // Alert Detail Fields Grid (1 row, 5 columns)
        JPanel detailsGrid = new JPanel(new GridLayout(1, 5, 12, 0));
        detailsGrid.setOpaque(false);
        detailsGrid.setBackground(new Color(11, 17, 32));

        alertIpLabel = new JLabel("192.168.1.105", SwingConstants.CENTER);
        alertAttemptsLabel = new JLabel("5 Attempts", SwingConstants.CENTER);
        alertSeverityLabel = new JLabel("HIGH", SwingConstants.CENTER);
        alertStatusLabel = new JLabel("OPEN", SwingConstants.CENTER);
        alertTimeLabel = new JLabel("--", SwingConstants.CENTER);

        detailsGrid.add(createAlertField("Source IP Address", alertIpLabel, SwingTheme.SEVERITY_HIGH));
        detailsGrid.add(createAlertField("Failed Attempts", alertAttemptsLabel, SwingTheme.SEVERITY_CRITICAL));
        detailsGrid.add(createAlertField("Severity", alertSeverityLabel, SwingTheme.SEVERITY_CRITICAL));
        detailsGrid.add(createAlertField("Status", alertStatusLabel, SwingTheme.ACCENT_CYAN));
        detailsGrid.add(createAlertField("Detection Time", alertTimeLabel, SwingTheme.TEXT_PRIMARY));

        // Alert Footer note
        alertRuleLabel = new JLabel("Rule: Threshold of 5 failed attempts within 2 minutes reached. Incident automatically generated.");
        alertRuleLabel.setFont(SwingTheme.FONT_SMALL);
        alertRuleLabel.setForeground(SwingTheme.TEXT_MUTED);

        alertBannerPanel.add(headerPanel, BorderLayout.NORTH);
        alertBannerPanel.add(detailsGrid, BorderLayout.CENTER);
        alertBannerPanel.add(alertRuleLabel, BorderLayout.SOUTH);

        return alertBannerPanel;
    }

    private JPanel createAlertField(String label, JLabel valueLabel, Color valueColor) {
        JPanel p = new JPanel(new BorderLayout(0, 2));
        p.setOpaque(false);

        JLabel lbl = new JLabel(label, SwingConstants.CENTER);
        lbl.setFont(SwingTheme.FONT_SMALL);
        lbl.setForeground(SwingTheme.TEXT_MUTED);

        valueLabel.setFont(SwingTheme.FONT_BOLD);
        valueLabel.setForeground(valueColor);

        p.add(lbl, BorderLayout.NORTH);
        p.add(valueLabel, BorderLayout.CENTER);
        return p;
    }

    /** Creates 6 responsive metric cards using GridLayout(1, 6, 10, 0). */
    private JPanel createMetricsGrid() {
        JPanel grid = new JPanel(new GridLayout(1, 6, 10, 0));
        grid.setOpaque(false);
        grid.setPreferredSize(new Dimension(0, 85));

        totalValLabel = new JLabel("0", SwingConstants.CENTER);
        openValLabel = new JLabel("0", SwingConstants.CENTER);
        criticalValLabel = new JLabel("0", SwingConstants.CENTER);
        unauthorizedValLabel = new JLabel("0", SwingConstants.CENTER);
        threatsValLabel = new JLabel("0", SwingConstants.CENTER);
        autoIncValLabel = new JLabel("0", SwingConstants.CENTER);

        grid.add(createMetricCard("📋 Incidents", totalValLabel, SwingTheme.ACCENT_CYAN));
        grid.add(createMetricCard("⏳ Active", openValLabel, SwingTheme.SEVERITY_MEDIUM));
        grid.add(createMetricCard("🔥 Critical", criticalValLabel, SwingTheme.SEVERITY_CRITICAL));
        grid.add(createMetricCard("🚫 Probes", unauthorizedValLabel, new Color(168, 85, 247)));
        grid.add(createMetricCard("🛡️ Detected Threats", threatsValLabel, new Color(244, 63, 94)));
        grid.add(createMetricCard("🤖 Auto-Incidents", autoIncValLabel, new Color(16, 185, 129)));

        return grid;
    }

    private JPanel createMetricCard(String title, JLabel valueLabel, Color accentColor) {
        JPanel card = new JPanel(new BorderLayout(0, 3));
        card.setBackground(SwingTheme.PANEL_BG);
        card.setBorder(SwingTheme.createCardBorder());

        JLabel titleLbl = new JLabel(title, SwingConstants.CENTER);
        titleLbl.setFont(SwingTheme.FONT_SMALL);
        titleLbl.setForeground(SwingTheme.TEXT_SECONDARY);

        valueLabel.setFont(valueLabel.getFont().deriveFont(24.0f));
        valueLabel.setForeground(accentColor);

        card.add(titleLbl, BorderLayout.NORTH);
        card.add(valueLabel, BorderLayout.CENTER);

        return card;
    }

    /** Creates dual split tables using JSplitPane. */
    private JPanel createSplitFeeds() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setOpaque(false);

        // Left Panel: Recent Incidents Table
        JPanel leftPanel = new JPanel(new BorderLayout(0, 8));
        leftPanel.setBackground(SwingTheme.PANEL_BG);
        leftPanel.setBorder(SwingTheme.createCardBorder());

        JLabel leftTitle = new JLabel("Recent Security Incidents");
        leftTitle.setFont(SwingTheme.FONT_HEADER);
        leftTitle.setForeground(SwingTheme.TEXT_PRIMARY);
        leftPanel.add(leftTitle, BorderLayout.NORTH);

        String[] incCols = {"ID", "Title", "Severity", "Status", "Date"};
        incidentsModel = new DefaultTableModel(incCols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        incidentsTable = new JTable(incidentsModel);
        SwingTheme.styleTable(incidentsTable);
        leftPanel.add(new JScrollPane(incidentsTable), BorderLayout.CENTER);

        // Right Panel: Activity Feed Table
        JPanel rightPanel = new JPanel(new BorderLayout(0, 8));
        rightPanel.setBackground(SwingTheme.PANEL_BG);
        rightPanel.setBorder(SwingTheme.createCardBorder());

        JLabel rightTitle = new JLabel("Live SOC Audit Trail");
        rightTitle.setFont(SwingTheme.FONT_HEADER);
        rightTitle.setForeground(SwingTheme.TEXT_PRIMARY);
        rightPanel.add(rightTitle, BorderLayout.NORTH);

        String[] actCols = {"User", "Action", "Details", "Time"};
        activityModel = new DefaultTableModel(actCols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        activityTable = new JTable(activityModel);
        SwingTheme.styleTable(activityTable);
        rightPanel.add(new JScrollPane(activityTable), BorderLayout.CENTER);

        // Split Pane (55/45 horizontal divider)
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel);
        splitPane.setResizeWeight(0.55);
        splitPane.setDividerSize(6);
        splitPane.setOpaque(false);
        splitPane.setBorder(null);

        panel.add(splitPane, BorderLayout.CENTER);
        return panel;
    }

    /** Refreshes all metrics, security alert banner, and feeds directly from ApiClient. */
    public void refreshData() {
        DashboardStats stats = apiClient.getDashboardStats();

        // Update Counter Labels
        totalValLabel.setText(String.valueOf(stats.getTotalIncidents()));
        openValLabel.setText(String.valueOf(stats.getOpenIncidents()));
        criticalValLabel.setText(String.valueOf(stats.getCriticalIncidents()));
        unauthorizedValLabel.setText(String.valueOf(stats.getUnauthorizedEvents()));
        threatsValLabel.setText(String.valueOf(stats.getTotalDetectedThreats()));
        autoIncValLabel.setText(String.valueOf(stats.getAutoGeneratedIncidents()));

        // Update Dedicated Security Alert Banner
        SecurityAlert alert = stats.getLatestAlert();
        if (alert != null) {
            alertBannerPanel.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createMatteBorder(2, 5, 2, 2, SwingTheme.SEVERITY_CRITICAL),
                    BorderFactory.createEmptyBorder(12, 16, 12, 16)
            ));
            alertTitleLabel.setText("🚨 SECURITY ALERT: " +
                    ("BRUTE_FORCE_ATTACK".equals(alert.getAlertType()) ? "BRUTE FORCE ATTACK DETECTED" : alert.getAlertType()));
            alertBadgeLabel.setText(" HIGH SEVERITY ");
            alertBadgeLabel.setBackground(SwingTheme.SEVERITY_CRITICAL);

            alertIpLabel.setText(alert.getSourceIp());
            alertAttemptsLabel.setText(alert.getFailedAttempts() + " Attempts");
            alertSeverityLabel.setText(alert.getSeverity());
            alertStatusLabel.setText(alert.getStatus());
            alertTimeLabel.setText(alert.getCreatedAt());
            alertRuleLabel.setText("Rule Triggered: 5 failed attempts within 2 minutes generated Incident #" + alert.getIncidentId());
        } else {
            alertBannerPanel.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createMatteBorder(2, 5, 2, 2, SwingTheme.SEVERITY_LOW),
                    BorderFactory.createEmptyBorder(12, 16, 12, 16)
            ));
            alertTitleLabel.setText("🛡️ IDS ACTIVE — SYSTEM NORMAL");
            alertBadgeLabel.setText(" SECURE ");
            alertBadgeLabel.setBackground(SwingTheme.SEVERITY_LOW);

            alertIpLabel.setText("All Subnets Clear");
            alertAttemptsLabel.setText("0 Anomalies");
            alertSeverityLabel.setText("LOW");
            alertStatusLabel.setText("MONITORING");
            alertTimeLabel.setText("--");
            alertRuleLabel.setText("Intrusion Detection Engine active: Monitoring sliding 2-minute login windows.");
        }

        // Populate Incidents Table
        incidentsModel.setRowCount(0);
        List<Incident> recents = stats.getRecentIncidents();
        if (recents != null) {
            for (Incident inc : recents) {
                incidentsModel.addRow(new Object[]{
                    "#" + inc.getId(),
                    inc.getTitle(),
                    inc.getSeverity(),
                    inc.getStatus(),
                    inc.getCreatedAt().substring(0, Math.min(16, inc.getCreatedAt().length()))
                });
            }
        }

        // Populate Activity Table
        activityModel.setRowCount(0);
        var acts = stats.getRecentActivities();
        if (acts != null) {
            for (var a : acts) {
                activityModel.addRow(new Object[]{
                    a.getUsername(),
                    a.getAction(),
                    a.getDetails(),
                    a.getCreatedAt().substring(Math.max(0, a.getCreatedAt().length() - 8))
                });
            }
        }
    }

    /** Alias for refreshData to support unified panel refreshing */
    public void loadStats() {
        refreshData();
    }
}
