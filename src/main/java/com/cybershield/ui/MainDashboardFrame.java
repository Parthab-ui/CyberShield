package com.cybershield.ui;

import com.cybershield.exception.DatabaseOperationException;
import com.cybershield.model.Incident;
import com.cybershield.model.SecurityEvent;
import com.cybershield.model.Threat;
import com.cybershield.model.User;
import com.cybershield.model.enums.IncidentStatus;
import com.cybershield.repository.DatabaseManager;
import com.cybershield.repository.IncidentRepository;
import com.cybershield.repository.ResponseActionRepository;
import com.cybershield.repository.SecurityEventRepository;
import com.cybershield.repository.ThreatRepository;
import com.cybershield.service.AuthService;
import com.cybershield.ui.components.CyberTable;
import com.cybershield.ui.components.MetricCard;
import com.cybershield.ui.components.StyledButton;
import com.cybershield.ui.panels.AnalyticsPanel;
import com.cybershield.ui.panels.AttackSimulatorPanel;
import com.cybershield.ui.panels.IncidentConsolePanel;
import com.cybershield.ui.panels.TelemetryPanel;
import com.cybershield.ui.panels.ThreatMonitorPanel;
import com.cybershield.ui.panels.UsersPanel;
import com.cybershield.util.DateTimeUtils;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.table.DefaultTableModel;

/**
 * Main application window for CyberShield Security Operations Center (SOC).
 */
public class MainDashboardFrame extends JFrame {

    private final SecurityEventRepository eventRepository;
    private final ThreatRepository threatRepository;
    private final IncidentRepository incidentRepository;

    // Metric Cards
    private MetricCard cardEvents;
    private MetricCard cardThreats;
    private MetricCard cardHighCritical;
    private MetricCard cardOpenIncidents;
    private MetricCard cardResolvedIncidents;

    // View panels
    private JPanel centerCardContainer;
    private CardLayout cardLayout;
    private TelemetryPanel telemetryPanel;
    private ThreatMonitorPanel threatMonitorPanel;
    private IncidentConsolePanel incidentConsolePanel;
    private AttackSimulatorPanel attackSimulatorPanel;
    private AnalyticsPanel analyticsPanel;
    private UsersPanel usersPanel;
    private JPanel overviewPanel;

    // Overview tables
    private DefaultTableModel overviewEventsModel;
    private DefaultTableModel overviewThreatsModel;
    private DefaultTableModel overviewIncidentsModel;
    private JLabel lblUserBadge;

    public MainDashboardFrame() {
        super("CYBERSHIELD — Cybersecurity Threat Monitoring & Incident Response System");

        DatabaseManager db = DatabaseManager.getInstance();
        this.eventRepository = new SecurityEventRepository(db);
        this.threatRepository = new ThreatRepository(db);
        ResponseActionRepository actionRepo = new ResponseActionRepository(db);
        this.incidentRepository = new IncidentRepository(db, threatRepository, actionRepo);

        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1280, 840);
        setMinimumSize(new Dimension(1024, 700));
        setLocationRelativeTo(null);
        getContentPane().setBackground(CyberTheme.BG_DARK);
        setLayout(new BorderLayout(0, 0));

        initUi();
        refreshAllMetrics();
    }

    private void initUi() {
        // Top Header
        JPanel header = createHeaderPanel();
        add(header, BorderLayout.NORTH);

        // Sidebar Navigation
        JPanel sidebar = createSidebarPanel();
        add(sidebar, BorderLayout.WEST);

        // Center Area: Top Metric Cards + CardLayout Body
        JPanel centerWrapper = new JPanel(new BorderLayout(0, 10));
        centerWrapper.setOpaque(false);
        centerWrapper.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JPanel metricsPanel = createMetricsPanel();
        centerWrapper.add(metricsPanel, BorderLayout.NORTH);

        // Card Layout for Panes
        cardLayout = new CardLayout();
        centerCardContainer = new JPanel(cardLayout);
        centerCardContainer.setOpaque(false);

        // Create Sub-Panels
        overviewPanel = createOverviewDashboardPanel();
        telemetryPanel = new TelemetryPanel();
        threatMonitorPanel = new ThreatMonitorPanel();
        incidentConsolePanel = new IncidentConsolePanel();
        attackSimulatorPanel = new AttackSimulatorPanel();
        analyticsPanel = new AnalyticsPanel();
        usersPanel = new UsersPanel();

        // Wire Refresh Callbacks between simulator, threats, and incidents
        attackSimulatorPanel.setOnSimulationCompleteCallback(this::refreshAllMetrics);
        threatMonitorPanel.setOnIncidentCreatedCallback(() -> {
            refreshAllMetrics();
            incidentConsolePanel.refreshData();
        });
        incidentConsolePanel.setOnIncidentUpdatedCallback(this::refreshAllMetrics);

        centerCardContainer.add(overviewPanel, "DASHBOARD");
        centerCardContainer.add(telemetryPanel, "TELEMETRY");
        centerCardContainer.add(threatMonitorPanel, "THREATS");
        centerCardContainer.add(incidentConsolePanel, "INCIDENTS");
        centerCardContainer.add(attackSimulatorPanel, "SIMULATOR");
        centerCardContainer.add(analyticsPanel, "ANALYTICS");
        centerCardContainer.add(usersPanel, "USERS");

        centerWrapper.add(centerCardContainer, BorderLayout.CENTER);
        add(centerWrapper, BorderLayout.CENTER);
    }

    private JPanel createHeaderPanel() {
        JPanel header = new JPanel(new BorderLayout(8, 8));
        header.setBackground(CyberTheme.BG_SIDEBAR);
        header.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, CyberTheme.BORDER_COLOR),
                BorderFactory.createEmptyBorder(12, 20, 12, 20)
        ));

        JPanel brand = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        brand.setOpaque(false);
        JLabel lblLogo = new JLabel("🛡 CYBERSHIELD");
        lblLogo.setFont(new Font("Segoe UI", Font.BOLD, 20));
        lblLogo.setForeground(CyberTheme.ACCENT_CYAN);

        JLabel lblTag = new JLabel("| SOC Threat Monitoring & Incident Response");
        lblTag.setFont(CyberTheme.FONT_BODY);
        lblTag.setForeground(CyberTheme.TEXT_MUTED);

        brand.add(lblLogo);
        brand.add(lblTag);

        JPanel userStatus = new JPanel(new FlowLayout(FlowLayout.RIGHT, 14, 0));
        userStatus.setOpaque(false);

        User currentUser = AuthService.getCurrentUser();
        String name = currentUser != null ? currentUser.getFullName() + " (" + currentUser.getRole().name() + ")" : "Analyst";
        lblUserBadge = new JLabel("Logged in: " + name);
        lblUserBadge.setFont(CyberTheme.FONT_BODY_BOLD);
        lblUserBadge.setForeground(CyberTheme.TEXT_PRIMARY);

        JLabel lblSimStatus = new JLabel("● SIMULATION ACTIVE");
        lblSimStatus.setFont(CyberTheme.FONT_SMALL);
        lblSimStatus.setForeground(CyberTheme.STATUS_GREEN);

        userStatus.add(lblSimStatus);
        userStatus.add(lblUserBadge);

        header.add(brand, BorderLayout.WEST);
        header.add(userStatus, BorderLayout.EAST);
        return header;
    }

    private JPanel createSidebarPanel() {
        JPanel sidebar = new JPanel(new BorderLayout(0, 0));
        sidebar.setBackground(CyberTheme.BG_SIDEBAR);
        sidebar.setPreferredSize(new Dimension(210, 800));
        sidebar.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, CyberTheme.BORDER_COLOR));

        JPanel navList = new JPanel(new GridLayout(8, 1, 4, 4));
        navList.setOpaque(false);
        navList.setBorder(BorderFactory.createEmptyBorder(16, 10, 16, 10));

        navList.add(createNavButton("📊 Dashboard", "DASHBOARD"));
        navList.add(createNavButton("📡 Telemetry", "TELEMETRY"));
        navList.add(createNavButton("⚡ Threat Monitor", "THREATS"));
        navList.add(createNavButton("🚨 Incidents", "INCIDENTS"));
        navList.add(createNavButton("🎯 Attack Simulator", "SIMULATOR"));
        navList.add(createNavButton("📈 Analytics", "ANALYTICS"));
        navList.add(createNavButton("👥 Users", "USERS"));

        StyledButton btnLogout = new StyledButton("🚪 Logout", StyledButton.ButtonStyle.SECONDARY);
        btnLogout.addActionListener(e -> handleLogout());
        navList.add(btnLogout);

        sidebar.add(navList, BorderLayout.NORTH);

        // Sidebar Footer Status
        JPanel sysStatus = new JPanel(new GridLayout(3, 1, 2, 2));
        sysStatus.setOpaque(false);
        sysStatus.setBorder(BorderFactory.createEmptyBorder(10, 14, 16, 14));

        JLabel l1 = new JLabel("Database: SQLite (OK)");
        l1.setFont(CyberTheme.FONT_SMALL);
        l1.setForeground(CyberTheme.STATUS_GREEN);

        JLabel l2 = new JLabel("Detectors: 4 Active");
        l2.setFont(CyberTheme.FONT_SMALL);
        l2.setForeground(CyberTheme.ACCENT_CYAN);

        JLabel l3 = new JLabel("Mode: Safe Simulation");
        l3.setFont(CyberTheme.FONT_SMALL);
        l3.setForeground(CyberTheme.TEXT_MUTED);

        sysStatus.add(l1);
        sysStatus.add(l2);
        sysStatus.add(l3);

        sidebar.add(sysStatus, BorderLayout.SOUTH);
        return sidebar;
    }

    private StyledButton createNavButton(String title, String cardKey) {
        StyledButton btn = new StyledButton(title, StyledButton.ButtonStyle.SECONDARY);
        btn.setHorizontalAlignment(JLabel.LEFT);
        btn.setFont(CyberTheme.FONT_BODY_BOLD);
        btn.addActionListener(e -> {
            cardLayout.show(centerCardContainer, cardKey);
            refreshPanelData(cardKey);
        });
        return btn;
    }

    private JPanel createMetricsPanel() {
        JPanel pnl = new JPanel(new GridLayout(1, 5, 10, 10));
        pnl.setOpaque(false);
        pnl.setPreferredSize(new Dimension(800, 95));

        cardEvents = new MetricCard("TOTAL EVENTS", "0", "Telemetry records ingested", CyberTheme.ACCENT_CYAN);
        cardThreats = new MetricCard("TOTAL THREATS", "0", "Threat patterns detected", CyberTheme.ACCENT_BLUE);
        cardHighCritical = new MetricCard("HIGH / CRITICAL", "0", "Urgent security risks", CyberTheme.STATUS_RED);
        cardOpenIncidents = new MetricCard("OPEN INCIDENTS", "0", "Awaiting containment", CyberTheme.STATUS_AMBER);
        cardResolvedIncidents = new MetricCard("RESOLVED INCIDENTS", "0", "Successfully mitigated", CyberTheme.STATUS_GREEN);

        pnl.add(cardEvents);
        pnl.add(cardThreats);
        pnl.add(cardHighCritical);
        pnl.add(cardOpenIncidents);
        pnl.add(cardResolvedIncidents);

        return pnl;
    }

    private JPanel createOverviewDashboardPanel() {
        JPanel overview = new JPanel(new BorderLayout(10, 10));
        overview.setOpaque(false);

        // Header message
        JPanel banner = new JPanel(new BorderLayout(6, 6));
        banner.setBackground(CyberTheme.BG_CARD);
        banner.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                BorderFactory.createEmptyBorder(12, 16, 12, 16)
        ));
        JLabel lblWelcome = new JLabel("SOC Real-Time Threat Activity Overview");
        lblWelcome.setFont(CyberTheme.FONT_HEADER);
        lblWelcome.setForeground(CyberTheme.ACCENT_CYAN);

        JLabel lblSub = new JLabel("Unified telemetry streams, automated polymorphic detection heuristics, and containment status.");
        lblSub.setFont(CyberTheme.FONT_BODY);
        lblSub.setForeground(CyberTheme.TEXT_MUTED);

        banner.add(lblWelcome, BorderLayout.NORTH);
        banner.add(lblSub, BorderLayout.SOUTH);
        overview.add(banner, BorderLayout.NORTH);

        // Split tables: Recent Events on Left, Recent Threats & Incidents on Right
        JPanel tablesGrid = new JPanel(new GridLayout(1, 2, 12, 12));
        tablesGrid.setOpaque(false);

        // Left: Recent Events
        overviewEventsModel = new DefaultTableModel(new String[]{"Time", "Type", "Source IP", "Description"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        CyberTable tblEvents = new CyberTable(overviewEventsModel);
        JScrollPane scrollEvents = CyberTable.wrapInScrollPane(tblEvents);
        scrollEvents.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                " Ingested Telemetry Feed ", 0, 0, CyberTheme.FONT_BODY_BOLD, CyberTheme.ACCENT_BLUE
        ));

        // Right: Threats (top) and Incidents (bottom)
        JPanel rightCol = new JPanel(new GridLayout(2, 1, 8, 8));
        rightCol.setOpaque(false);

        overviewThreatsModel = new DefaultTableModel(new String[]{"ID", "Category", "Severity", "Target", "Status"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        CyberTable tblThreats = new CyberTable(overviewThreatsModel);
        JScrollPane scrollThreats = CyberTable.wrapInScrollPane(tblThreats);
        scrollThreats.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                " Identified Security Threats ", 0, 0, CyberTheme.FONT_BODY_BOLD, CyberTheme.STATUS_RED
        ));

        overviewIncidentsModel = new DefaultTableModel(new String[]{"ID", "Incident Title", "Severity", "Status"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        CyberTable tblIncidents = new CyberTable(overviewIncidentsModel);
        JScrollPane scrollIncidents = CyberTable.wrapInScrollPane(tblIncidents);
        scrollIncidents.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                " Escalated Incident Cases ", 0, 0, CyberTheme.FONT_BODY_BOLD, CyberTheme.STATUS_AMBER
        ));

        rightCol.add(scrollThreats);
        rightCol.add(scrollIncidents);

        tablesGrid.add(scrollEvents);
        tablesGrid.add(rightCol);

        overview.add(tablesGrid, BorderLayout.CENTER);
        return overview;
    }

    public void refreshAllMetrics() {
        try {
            int eventCount = eventRepository.count();
            int threatCount = threatRepository.count();
            int highCritCount = threatRepository.countHighOrCritical();
            int openIncidents = incidentRepository.countByStatus(IncidentStatus.OPEN) +
                                incidentRepository.countByStatus(IncidentStatus.INVESTIGATING);
            int resolvedIncidents = incidentRepository.countByStatus(IncidentStatus.RESOLVED);

            cardEvents.setValue(eventCount);
            cardThreats.setValue(threatCount);
            cardHighCritical.setValue(highCritCount);
            cardOpenIncidents.setValue(openIncidents);
            cardResolvedIncidents.setValue(resolvedIncidents);

            // Refresh Overview Tables
            List<SecurityEvent> recentEvents = eventRepository.findAll(10);
            overviewEventsModel.setRowCount(0);
            for (SecurityEvent e : recentEvents) {
                overviewEventsModel.addRow(new Object[]{
                    DateTimeUtils.formatTimeOnly(e.getTimestamp()),
                    e.getEventType().name(),
                    e.getSourceIp(),
                    e.getDescription()
                });
            }

            List<Threat> recentThreats = threatRepository.findAll();
            overviewThreatsModel.setRowCount(0);
            for (int i = 0; i < Math.min(6, recentThreats.size()); i++) {
                Threat t = recentThreats.get(i);
                overviewThreatsModel.addRow(new Object[]{
                    t.getThreatId(),
                    t.getThreatType().name(),
                    t.getSeverity().name(),
                    t.getTargetAsset(),
                    t.getStatus().name()
                });
            }

            List<Incident> recentIncidents = incidentRepository.findAll();
            overviewIncidentsModel.setRowCount(0);
            for (int i = 0; i < Math.min(6, recentIncidents.size()); i++) {
                Incident inc = recentIncidents.get(i);
                overviewIncidentsModel.addRow(new Object[]{
                    inc.getIncidentId(),
                    inc.getTitle(),
                    inc.getSeverity().name(),
                    inc.getStatus().name()
                });
            }

        } catch (DatabaseOperationException e) {
            System.err.println("Failed to refresh metrics: " + e.getMessage());
        }
    }

    private void refreshPanelData(String cardKey) {
        refreshAllMetrics();
        switch (cardKey) {
            case "TELEMETRY" -> telemetryPanel.refreshData();
            case "THREATS" -> threatMonitorPanel.refreshData();
            case "INCIDENTS" -> incidentConsolePanel.refreshData();
            case "ANALYTICS" -> analyticsPanel.refreshData();
            case "USERS" -> usersPanel.refreshData();
        }
    }

    private void handleLogout() {
        int confirm = JOptionPane.showConfirmDialog(this, "Are you sure you want to end your SOC analyst session?",
                "Confirm Logout", JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            AuthService.logout();
            dispose();
            LoginDialog login = new LoginDialog(null);
            login.setVisible(true);
            if (login.isLoginSuccessful()) {
                new MainDashboardFrame().setVisible(true);
            }
        }
    }
}
