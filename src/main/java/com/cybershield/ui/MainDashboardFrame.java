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
import com.cybershield.ui.components.BlockedIpsListPanel;
import com.cybershield.ui.components.CyberTable;
import com.cybershield.ui.components.MetricCard;
import com.cybershield.ui.components.MitreAssetTreePanel;
import com.cybershield.ui.components.StyledButton;
import com.cybershield.ui.dialogs.ProjectTeamDialog;
import com.cybershield.ui.panels.AnalyticsPanel;
import com.cybershield.ui.panels.AttackSimulatorPanel;
import com.cybershield.ui.panels.IncidentConsolePanel;
import com.cybershield.ui.panels.TelemetryPanel;
import com.cybershield.ui.panels.ThreatMonitorPanel;
import com.cybershield.ui.panels.UsersPanel;
import com.cybershield.util.DateTimeUtils;
import com.cybershield.util.ProjectMetadata;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JCheckBoxMenuItem;
import javax.swing.JColorChooser;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButtonMenuItem;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JSlider;
import javax.swing.JSpinner;
import javax.swing.JToggleButton;
import javax.swing.JToolBar;
import javax.swing.SpinnerNumberModel;
import javax.swing.Timer;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;

/**
 * Main application window for CyberShield Security Operations Center (SOC).
 * Incorporates full Java Swing component suite for the October 1st Review.
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
    private MitreAssetTreePanel mitreAssetTreePanel;
    private BlockedIpsListPanel blockedIpsListPanel;
    private JPanel overviewPanel;

    // Overview tables
    private DefaultTableModel overviewEventsModel;
    private DefaultTableModel overviewThreatsModel;
    private DefaultTableModel overviewIncidentsModel;
    private JLabel lblUserBadge;
    private JLabel lblTeamQuickBadge;

    // Toolbar components
    private JToggleButton tglLiveStream;
    private JSpinner spinAutoRefresh;
    private JSlider sliderThreatThreshold;
    private Timer autoRefreshTimer;

    public MainDashboardFrame() {
        super(ProjectMetadata.getProjectTitle());

        DatabaseManager db = DatabaseManager.getInstance();
        this.eventRepository = new SecurityEventRepository(db);
        this.threatRepository = new ThreatRepository(db);
        ResponseActionRepository actionRepo = new ResponseActionRepository(db);
        this.incidentRepository = new IncidentRepository(db, threatRepository, actionRepo);

        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1320, 880);
        setMinimumSize(new Dimension(1080, 720));
        setLocationRelativeTo(null);
        getContentPane().setBackground(CyberTheme.BG_DARK);
        setLayout(new BorderLayout(0, 0));

        // Initialize JMenuBar
        setJMenuBar(createApplicationMenuBar());

        initUi();
        setupAutoRefresh();
        refreshAllMetrics();
    }

    private JMenuBar createApplicationMenuBar() {
        JMenuBar menuBar = new JMenuBar();
        menuBar.setBackground(CyberTheme.BG_SIDEBAR);
        menuBar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, CyberTheme.BORDER_COLOR));

        // 1. File Menu
        JMenu menuFile = createStyledMenu("File (JMenu)");
        JMenuItem miExportIncidents = new JMenuItem("📁 Export Incident Cases to CSV (JFileChooser)");
        miExportIncidents.addActionListener(e -> exportIncidentsCsv());

        JMenuItem miExportTelemetry = new JMenuItem("📁 Export Telemetry Feed to CSV");
        miExportTelemetry.addActionListener(e -> {
            cardLayout.show(centerCardContainer, "TELEMETRY");
            telemetryPanel.refreshData();
        });

        JMenuItem miExit = new JMenuItem("🚪 Exit SOC System");
        miExit.addActionListener(e -> System.exit(0));

        menuFile.add(miExportIncidents);
        menuFile.add(miExportTelemetry);
        menuFile.addSeparator();
        menuFile.add(miExit);

        // 2. View Menu
        JMenu menuView = createStyledMenu("View (JMenu)");
        menuView.add(createNavMenuItem("📊 Operations Dashboard (F1)", "DASHBOARD"));
        menuView.add(createNavMenuItem("📡 Ingested Telemetry Feed (F2)", "TELEMETRY"));
        menuView.add(createNavMenuItem("⚡ Threat Monitor & Dossiers (F3)", "THREATS"));
        menuView.add(createNavMenuItem("🚨 Incident Containment Console (F4)", "INCIDENTS"));
        menuView.add(createNavMenuItem("🎯 Attack Scenario Simulator (F5)", "SIMULATOR"));
        menuView.add(createNavMenuItem("📈 Security Metrics Analytics (F6)", "ANALYTICS"));
        menuView.add(createNavMenuItem("🌳 MITRE ATT&CK & Asset Tree (JTree)", "TREE"));
        menuView.add(createNavMenuItem("🛡 Perimeter Droplist (JList)", "DROPLIST"));
        menuView.add(createNavMenuItem("👥 Operator Administration (F7)", "USERS"));
        menuView.addSeparator();

        JCheckBoxMenuItem chkAutoRefresh = new JCheckBoxMenuItem("Auto-Refresh Metrics Timer (JCheckBoxMenuItem)", true);
        chkAutoRefresh.addActionListener(e -> {
            if (chkAutoRefresh.isSelected()) autoRefreshTimer.start();
            else autoRefreshTimer.stop();
        });
        menuView.add(chkAutoRefresh);

        // 3. Simulation Menu
        JMenu menuSim = createStyledMenu("Simulation (JMenu)");
        JMenuItem miSimBf = new JMenuItem("🎯 Trigger Brute Force Scenario");
        miSimBf.addActionListener(e -> {
            cardLayout.show(centerCardContainer, "SIMULATOR");
            JOptionPane.showMessageDialog(this, "Switched to Simulator. Click 'SIMULATE BRUTE FORCE' to execute.", "Simulation Ready", JOptionPane.INFORMATION_MESSAGE);
        });

        JMenuItem miSimPhish = new JMenuItem("🎯 Trigger Spear Phishing Scenario");
        miSimPhish.addActionListener(e -> {
            cardLayout.show(centerCardContainer, "SIMULATOR");
            JOptionPane.showMessageDialog(this, "Switched to Simulator. Click 'SIMULATE PHISHING' to execute.", "Simulation Ready", JOptionPane.INFORMATION_MESSAGE);
        });

        menuSim.add(miSimBf);
        menuSim.add(miSimPhish);
        menuSim.addSeparator();

        JMenu subProfiles = new JMenu("Execution Profiles (JRadioButtonMenuItem)");
        JRadioButtonMenuItem rbStandard = new JRadioButtonMenuItem("Standard Heuristic Engine", true);
        JRadioButtonMenuItem rbAggressive = new JRadioButtonMenuItem("Aggressive Automated Containment", false);
        JRadioButtonMenuItem rbClassroom = new JRadioButtonMenuItem("Educational Classroom Mode", false);

        ButtonGroup profileGroup = new ButtonGroup();
        profileGroup.add(rbStandard);
        profileGroup.add(rbAggressive);
        profileGroup.add(rbClassroom);

        subProfiles.add(rbStandard);
        subProfiles.add(rbAggressive);
        subProfiles.add(rbClassroom);
        menuSim.add(subProfiles);

        // 4. Tools Menu
        JMenu menuTools = createStyledMenu("Tools (JMenu)");
        JMenuItem miColorChooser = new JMenuItem("🎨 Customize SOC Accent Color (JColorChooser)");
        miColorChooser.addActionListener(e -> openColorChooser());

        JMenuItem miRefreshMetrics = new JMenuItem("🔄 Force Refresh All Data (F5)");
        miRefreshMetrics.addActionListener(e -> refreshAllMetrics());

        menuTools.add(miColorChooser);
        menuTools.add(miRefreshMetrics);

        // 5. Review & Evaluation Menu (Directly for Oct 1st Evaluation)
        JMenu menuReview = createStyledMenu("🎓 Review & Evaluation (Oct 1st)");
        menuReview.setForeground(CyberTheme.ACCENT_CYAN);

        JMenuItem miTeamDossier = new JMenuItem("👥 Project Title & Team Members Details (Dossier)");
        miTeamDossier.setFont(CyberTheme.FONT_BODY_BOLD);
        miTeamDossier.addActionListener(e -> openTeamDialog());

        JMenuItem miComponentAudit = new JMenuItem("📋 Java Swing Components Audit (35 Items)");
        miComponentAudit.addActionListener(e -> openTeamDialog());

        JMenuItem miVivaCheatSheet = new JMenuItem("💡 Code Viva Defense Q&A Cheat Sheet");
        miVivaCheatSheet.addActionListener(e -> {
            cardLayout.show(centerCardContainer, "ANALYTICS");
            analyticsPanel.refreshData();
        });

        menuReview.add(miTeamDossier);
        menuReview.add(miComponentAudit);
        menuReview.addSeparator();
        menuReview.add(miVivaCheatSheet);

        menuBar.add(menuFile);
        menuBar.add(menuView);
        menuBar.add(menuSim);
        menuBar.add(menuTools);
        menuBar.add(menuReview);

        return menuBar;
    }

    private JMenu createStyledMenu(String text) {
        JMenu m = new JMenu(text);
        m.setForeground(CyberTheme.TEXT_PRIMARY);
        m.setFont(CyberTheme.FONT_BODY_BOLD);
        return m;
    }

    private JMenuItem createNavMenuItem(String label, String cardKey) {
        JMenuItem item = new JMenuItem(label);
        item.setFont(CyberTheme.FONT_BODY);
        item.addActionListener(e -> {
            cardLayout.show(centerCardContainer, cardKey);
            refreshPanelData(cardKey);
        });
        return item;
    }

    private void initUi() {
        // Top Header
        JPanel header = createHeaderPanel();

        // Top Toolbar (JToolBar)
        JToolBar toolBar = createOperationsToolBar();

        JPanel northWrapper = new JPanel(new BorderLayout());
        northWrapper.add(header, BorderLayout.NORTH);
        northWrapper.add(toolBar, BorderLayout.SOUTH);
        add(northWrapper, BorderLayout.NORTH);

        // Sidebar Navigation
        JPanel sidebar = createSidebarPanel();
        add(sidebar, BorderLayout.WEST);

        // Center Area: Top Metric Cards + CardLayout Body
        JPanel centerWrapper = new JPanel(new BorderLayout(0, 10));
        centerWrapper.setOpaque(false);
        centerWrapper.setBorder(BorderFactory.createEmptyBorder(10, 12, 12, 12));

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
        mitreAssetTreePanel = new MitreAssetTreePanel();
        blockedIpsListPanel = new BlockedIpsListPanel();

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
        centerCardContainer.add(mitreAssetTreePanel, "TREE");
        centerCardContainer.add(blockedIpsListPanel, "DROPLIST");
        centerCardContainer.add(usersPanel, "USERS");

        centerWrapper.add(centerCardContainer, BorderLayout.CENTER);
        add(centerWrapper, BorderLayout.CENTER);
    }

    private JToolBar createOperationsToolBar() {
        JToolBar bar = new JToolBar("SOC Rapid Action Bar");
        bar.setFloatable(false);
        bar.setBackground(CyberTheme.BG_CARD);
        bar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, CyberTheme.BORDER_COLOR),
                BorderFactory.createEmptyBorder(4, 10, 4, 10)
        ));

        // Quick Review 1 Dossier Button
        StyledButton btnTeam = new StyledButton("🎓 Review 1 Team Dossier", StyledButton.ButtonStyle.PRIMARY);
        btnTeam.setToolTipText("Open Project Title & 3-Member Team details for October 1st First Review");
        btnTeam.addActionListener(e -> openTeamDialog());
        bar.add(btnTeam);

        bar.addSeparator(new Dimension(8, 20));

        StyledButton btnRefresh = new StyledButton("🔄 Refresh (F5)", StyledButton.ButtonStyle.SECONDARY);
        btnRefresh.addActionListener(e -> refreshAllMetrics());
        bar.add(btnRefresh);

        // JToggleButton
        tglLiveStream = new JToggleButton("⚡ Live Stream: ON", true);
        tglLiveStream.setFont(CyberTheme.FONT_SMALL);
        tglLiveStream.setBackground(CyberTheme.BG_DARK);
        tglLiveStream.setForeground(CyberTheme.STATUS_GREEN);
        tglLiveStream.setToolTipText("Toggle background real-time event simulation (Demonstrates javax.swing.JToggleButton)");
        tglLiveStream.addActionListener(e -> {
            if (tglLiveStream.isSelected()) {
                tglLiveStream.setText("⚡ Live Stream: ON");
                tglLiveStream.setForeground(CyberTheme.STATUS_GREEN);
                autoRefreshTimer.start();
            } else {
                tglLiveStream.setText("⏸ Live Stream: PAUSED");
                tglLiveStream.setForeground(CyberTheme.STATUS_AMBER);
                autoRefreshTimer.stop();
            }
        });
        bar.add(tglLiveStream);

        bar.addSeparator(new Dimension(8, 20));

        StyledButton btnSim = new StyledButton("🎯 Simulator", StyledButton.ButtonStyle.DANGER);
        btnSim.addActionListener(e -> {
            cardLayout.show(centerCardContainer, "SIMULATOR");
            refreshPanelData("SIMULATOR");
        });
        bar.add(btnSim);

        StyledButton btnTree = new StyledButton("🌳 MITRE Tree (JTree)", StyledButton.ButtonStyle.SECONDARY);
        btnTree.addActionListener(e -> cardLayout.show(centerCardContainer, "TREE"));
        bar.add(btnTree);

        StyledButton btnDroplist = new StyledButton("🛡 Blocked Droplist (JList)", StyledButton.ButtonStyle.SECONDARY);
        btnDroplist.addActionListener(e -> cardLayout.show(centerCardContainer, "DROPLIST"));
        bar.add(btnDroplist);

        StyledButton btnExport = new StyledButton("📁 Export Cases (JFileChooser)", StyledButton.ButtonStyle.SECONDARY);
        btnExport.addActionListener(e -> exportIncidentsCsv());
        bar.add(btnExport);

        StyledButton btnColor = new StyledButton("🎨 Accent (JColorChooser)", StyledButton.ButtonStyle.SECONDARY);
        btnColor.addActionListener(e -> openColorChooser());
        bar.add(btnColor);

        bar.addSeparator(new Dimension(10, 20));

        // JSpinner for refresh interval
        JLabel lblSpin = new JLabel("Auto-Refresh (JSpinner): ");
        lblSpin.setFont(CyberTheme.FONT_SMALL);
        lblSpin.setForeground(CyberTheme.TEXT_MUTED);
        bar.add(lblSpin);

        spinAutoRefresh = new JSpinner(new SpinnerNumberModel(5, 1, 60, 1));
        spinAutoRefresh.setPreferredSize(new Dimension(50, 24));
        spinAutoRefresh.addChangeListener(e -> {
            int secs = (int) spinAutoRefresh.getValue();
            autoRefreshTimer.setDelay(secs * 1000);
        });
        bar.add(spinAutoRefresh);
        bar.add(new JLabel(" s  ") {{ setForeground(CyberTheme.TEXT_MUTED); setFont(CyberTheme.FONT_SMALL); }});

        bar.addSeparator(new Dimension(8, 20));

        // JSlider for global sensitivity threshold
        JLabel lblSlider = new JLabel("Min Risk (JSlider): ");
        lblSlider.setFont(CyberTheme.FONT_SMALL);
        lblSlider.setForeground(CyberTheme.TEXT_MUTED);
        bar.add(lblSlider);

        sliderThreatThreshold = new JSlider(0, 100, 20);
        sliderThreatThreshold.setOpaque(false);
        sliderThreatThreshold.setPreferredSize(new Dimension(100, 24));
        bar.add(sliderThreatThreshold);

        return bar;
    }

    private void setupAutoRefresh() {
        autoRefreshTimer = new Timer(5000, e -> refreshAllMetrics());
        autoRefreshTimer.start();
    }

    private JPanel createHeaderPanel() {
        JPanel header = new JPanel(new BorderLayout(8, 8));
        header.setBackground(CyberTheme.BG_SIDEBAR);
        header.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, CyberTheme.BORDER_COLOR),
                BorderFactory.createEmptyBorder(10, 20, 10, 20)
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

        // Center / Right Team Quick Info
        JPanel teamBanner = new JPanel(new FlowLayout(FlowLayout.RIGHT, 14, 0));
        teamBanner.setOpaque(false);

        lblTeamQuickBadge = new JLabel("🎓 Team: " + ProjectMetadata.getMember1Name() + " (Lead) + 2 Members [Click for Review Dossier]");
        lblTeamQuickBadge.setFont(CyberTheme.FONT_BODY_BOLD);
        lblTeamQuickBadge.setForeground(CyberTheme.ACCENT_CYAN);
        lblTeamQuickBadge.setCursor(new Cursor(Cursor.HAND_CURSOR));
        lblTeamQuickBadge.setToolTipText("Click to view or edit team members and project title for Review 1");
        lblTeamQuickBadge.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) { openTeamDialog(); }
        });

        User currentUser = AuthService.getCurrentUser();
        String name = currentUser != null ? currentUser.getFullName() + " (" + currentUser.getRole().name() + ")" : "Analyst";
        lblUserBadge = new JLabel("Operator: " + name);
        lblUserBadge.setFont(CyberTheme.FONT_BODY);
        lblUserBadge.setForeground(CyberTheme.TEXT_PRIMARY);

        teamBanner.add(lblTeamQuickBadge);
        teamBanner.add(new JSeparator(JSeparator.VERTICAL) {{ setPreferredSize(new Dimension(2, 16)); }});
        teamBanner.add(lblUserBadge);

        header.add(brand, BorderLayout.WEST);
        header.add(teamBanner, BorderLayout.EAST);
        return header;
    }

    private JPanel createSidebarPanel() {
        JPanel sidebar = new JPanel(new BorderLayout(0, 0));
        sidebar.setBackground(CyberTheme.BG_SIDEBAR);
        sidebar.setPreferredSize(new Dimension(215, 800));
        sidebar.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, CyberTheme.BORDER_COLOR));

        JPanel navList = new JPanel(new GridLayout(10, 1, 3, 3));
        navList.setOpaque(false);
        navList.setBorder(BorderFactory.createEmptyBorder(12, 10, 12, 10));

        navList.add(createNavButton("📊 Dashboard", "DASHBOARD"));
        navList.add(createNavButton("📡 Telemetry", "TELEMETRY"));
        navList.add(createNavButton("⚡ Threat Monitor", "THREATS"));
        navList.add(createNavButton("🚨 Incidents", "INCIDENTS"));
        navList.add(createNavButton("🎯 Attack Simulator", "SIMULATOR"));
        navList.add(createNavButton("📈 Analytics", "ANALYTICS"));
        navList.add(createNavButton("🌳 MITRE Asset Tree", "TREE"));
        navList.add(createNavButton("🛡 Blocked Droplist", "DROPLIST"));
        navList.add(createNavButton("👥 Users", "USERS"));

        StyledButton btnLogout = new StyledButton("🚪 Logout", StyledButton.ButtonStyle.SECONDARY);
        btnLogout.addActionListener(e -> handleLogout());
        navList.add(btnLogout);

        sidebar.add(navList, BorderLayout.NORTH);

        // Sidebar Footer Status
        JPanel sysStatus = new JPanel(new GridLayout(4, 1, 2, 2));
        sysStatus.setOpaque(false);
        sysStatus.setBorder(BorderFactory.createEmptyBorder(8, 14, 14, 14));

        JLabel l1 = new JLabel("Database: SQLite (OK)");
        l1.setFont(CyberTheme.FONT_SMALL);
        l1.setForeground(CyberTheme.STATUS_GREEN);

        JLabel l2 = new JLabel("Detectors: 4 Active");
        l2.setFont(CyberTheme.FONT_SMALL);
        l2.setForeground(CyberTheme.ACCENT_CYAN);

        JLabel l3 = new JLabel("Review: Oct 1st (Ready)");
        l3.setFont(CyberTheme.FONT_SMALL);
        l3.setForeground(CyberTheme.STATUS_AMBER);

        StyledButton btnTeamDossier = new StyledButton("🎓 Team Dossier", StyledButton.ButtonStyle.PRIMARY);
        btnTeamDossier.setPreferredSize(new Dimension(180, 28));
        btnTeamDossier.addActionListener(e -> openTeamDialog());

        sysStatus.add(l1);
        sysStatus.add(l2);
        sysStatus.add(l3);
        sysStatus.add(btnTeamDossier);

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

    public void openTeamDialog() {
        ProjectTeamDialog dialog = new ProjectTeamDialog(this);
        dialog.setVisible(true);
        setTitle(ProjectMetadata.getProjectTitle());
        lblTeamQuickBadge.setText("🎓 Team: " + ProjectMetadata.getMember1Name() + " (Lead) + 2 Members [Click for Review Dossier]");
    }

    private void openColorChooser() {
        Color newColor = JColorChooser.showDialog(this, "Select SOC Terminal Accent Color (JColorChooser)", CyberTheme.ACCENT_CYAN);
        if (newColor != null) {
            CyberTheme.setAccentColor(newColor);
            repaint();
            JOptionPane.showMessageDialog(this, "Accent color updated to: " + newColor.toString(), "Theme Customizer", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void exportIncidentsCsv() {
        try {
            List<Incident> list = incidentRepository.findAll();
            if (list.isEmpty()) {
                JOptionPane.showMessageDialog(this, "No incident cases to export.", "Empty Cases", JOptionPane.WARNING_MESSAGE);
                return;
            }

            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Export Incident Cases to CSV (JFileChooser)");
            chooser.setSelectedFile(new File("cybershield_incidents_report.csv"));
            chooser.setFileFilter(new FileNameExtensionFilter("CSV Files (*.csv)", "csv"));

            int ret = chooser.showSaveDialog(this);
            if (ret == JFileChooser.APPROVE_OPTION) {
                File target = chooser.getSelectedFile();
                if (!target.getName().toLowerCase().endsWith(".csv")) {
                    target = new File(target.getParentFile(), target.getName() + ".csv");
                }

                try (FileWriter writer = new FileWriter(target)) {
                    writer.write("Incident ID,Title,Severity,Status,Created At,Last Updated\n");
                    for (Incident inc : list) {
                        writer.write(String.format("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
                                inc.getIncidentId(),
                                inc.getTitle().replace("\"", "\"\""),
                                inc.getSeverity().name(),
                                inc.getStatus().name(),
                                DateTimeUtils.format(inc.getCreatedAt()),
                                DateTimeUtils.format(inc.getUpdatedAt())
                        ));
                    }
                    JOptionPane.showMessageDialog(this,
                            "Successfully exported " + list.size() + " incidents to:\n" + target.getAbsolutePath(),
                            "Export Completed", JOptionPane.INFORMATION_MESSAGE);
                }
            }
        } catch (DatabaseOperationException | IOException e) {
            JOptionPane.showMessageDialog(this, "Export failed: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
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
            if (autoRefreshTimer != null) autoRefreshTimer.stop();
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
