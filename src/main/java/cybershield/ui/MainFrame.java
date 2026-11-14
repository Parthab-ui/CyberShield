package cybershield.ui;

import cybershield.model.User;

import javax.swing.*;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * MainFrame — Primary desktop window of the CyberShield application.
 * Demonstrates:
 * - Top-level JFrame window lifecycle.
 * - JMenuBar, JMenu, and JMenuItem for comprehensive application menu navigation.
 * - JToolBar for quick-access operational shortcuts.
 * - JTabbedPane organizing the modular panels (Dashboard, Incidents, Threat Response,
 *   Investigation Center, Account Security, Access Telemetry, Activity Logs, Component Lab, and About).
 * - Live real-time status bar showing active session role, DB status, and system clock.
 * - Clean session logout transitioning back to LoginFrame on the Event Dispatch Thread (EDT).
 */
public class MainFrame extends JFrame {

    private final ApiClient apiClient;

    private JTabbedPane tabbedPane;
    private DashboardPanel dashboardPanel;
    private IncidentPanel incidentPanel;
    private ThreatResponsePanel threatResponsePanel;
    private InvestigationPanel investigationPanel;
    private AccountSecurityPanel accountSecurityPanel;
    private AccessMonitoringPanel accessMonitoringPanel;
    private ActivityHistoryPanel activityHistoryPanel;
    private ComponentLabPanel componentLabPanel;
    private AboutPanel aboutPanel;

    // Status bar labels
    private JLabel userStatusLabel;
    private JLabel dbStatusLabel;
    private JLabel clockLabel;
    private Timer clockTimer;

    public MainFrame() {
        super("CyberShield — Cybersecurity Monitoring and Incident Management System");
        this.apiClient = ApiClient.getInstance();

        initFrameProperties();
        initMenuBar();
        initToolBar();
        initTabs();
        initStatusBar();

        // Start live status clock
        startClock();
    }

    /**
     * Sets standard frame window properties, dimensions, and window listeners.
     */
    private void initFrameProperties() {
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1280, 840);
        setMinimumSize(new Dimension(1024, 700));
        setLocationRelativeTo(null); // Center on primary display
        getContentPane().setBackground(SwingTheme.BG_COLOR);
        setLayout(new BorderLayout());

        // Bring to front and ensure visibility
        setAlwaysOnTop(true);
        SwingUtilities.invokeLater(() -> setAlwaysOnTop(false));
    }

    /**
     * Builds standard desktop application menu bar (JMenuBar, JMenu, JMenuItem).
     */
    private void initMenuBar() {
        JMenuBar menuBar = new JMenuBar();
        menuBar.setBackground(SwingTheme.PANEL_BG);
        menuBar.setBorder(BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR));

        // 1. File Menu
        JMenu fileMenu = new JMenu("File");
        fileMenu.setForeground(SwingTheme.TEXT_PRIMARY);

        JMenuItem refreshAllItem = new JMenuItem("Refresh All Views");
        refreshAllItem.addActionListener(e -> refreshAllPanels());

        JMenuItem logoutItem = new JMenuItem("Sign Out (Logout)");
        logoutItem.addActionListener(e -> handleLogout());

        JMenuItem exitItem = new JMenuItem("Exit Application");
        exitItem.addActionListener(e -> System.exit(0));

        fileMenu.add(refreshAllItem);
        fileMenu.addSeparator();
        fileMenu.add(logoutItem);
        fileMenu.add(exitItem);

        // 2. Navigation Menu
        JMenu navMenu = new JMenu("Navigation");
        navMenu.setForeground(SwingTheme.TEXT_PRIMARY);

        JMenuItem navDash = new JMenuItem("Dashboard");
        navDash.addActionListener(e -> tabbedPane.setSelectedIndex(0));
        JMenuItem navInc = new JMenuItem("Incident Management");
        navInc.addActionListener(e -> tabbedPane.setSelectedIndex(1));
        JMenuItem navThreat = new JMenuItem("Threat Response Center");
        navThreat.addActionListener(e -> tabbedPane.setSelectedIndex(2));
        JMenuItem navInv = new JMenuItem("Investigation Center");
        navInv.addActionListener(e -> tabbedPane.setSelectedIndex(3));
        JMenuItem navAcc = new JMenuItem("Account Security");
        navAcc.addActionListener(e -> tabbedPane.setSelectedIndex(4));
        JMenuItem navAccess = new JMenuItem("Access Telemetry");
        navAccess.addActionListener(e -> tabbedPane.setSelectedIndex(5));
        JMenuItem navActivity = new JMenuItem("Activity History");
        navActivity.addActionListener(e -> tabbedPane.setSelectedIndex(6));
        JMenuItem navLab = new JMenuItem("Swing Component Lab");
        navLab.addActionListener(e -> tabbedPane.setSelectedIndex(7));
        JMenuItem navAbout = new JMenuItem("About System");
        navAbout.addActionListener(e -> tabbedPane.setSelectedIndex(8));

        navMenu.add(navDash);
        navMenu.add(navInc);
        navMenu.add(navThreat);
        navMenu.add(navInv);
        navMenu.add(navAcc);
        navMenu.add(navAccess);
        navMenu.add(navActivity);
        navMenu.addSeparator();
        navMenu.add(navLab);
        navMenu.add(navAbout);

        // 3. Operations Menu
        JMenu opsMenu = new JMenu("Security Operations");
        opsMenu.setForeground(SwingTheme.TEXT_PRIMARY);

        JMenuItem simThreatItem = new JMenuItem("Simulate Threat Intrusion");
        simThreatItem.addActionListener(e -> {
            tabbedPane.setSelectedIndex(5);
            apiClient.simulateThreat();
            accessMonitoringPanel.loadEvents();
            JOptionPane.showMessageDialog(this, "Simulated intrusion threat logged to database.", "Threat Injected", JOptionPane.WARNING_MESSAGE);
        });

        JMenuItem simBruteItem = new JMenuItem("Simulate Brute Force Attack (5 Failed Logins)");
        simBruteItem.addActionListener(e -> {
            apiClient.simulateBruteForceAttack("192.168.1.188");
            refreshAllPanels();
            tabbedPane.setSelectedIndex(2);
            JOptionPane.showMessageDialog(this, "Simulated 5 rapid failed logins. Automated Threat Response triggered.", "IDS Triggered", JOptionPane.WARNING_MESSAGE);
        });

        opsMenu.add(simThreatItem);
        opsMenu.add(simBruteItem);

        // 4. Help Menu
        JMenu helpMenu = new JMenu("Help");
        helpMenu.setForeground(SwingTheme.TEXT_PRIMARY);

        JMenuItem docItem = new JMenuItem("Academic Review Guide");
        docItem.addActionListener(e -> tabbedPane.setSelectedIndex(8));

        JMenuItem aboutItem = new JMenuItem("About CyberShield");
        aboutItem.addActionListener(e -> tabbedPane.setSelectedIndex(8));

        helpMenu.add(docItem);
        helpMenu.add(aboutItem);

        menuBar.add(fileMenu);
        menuBar.add(navMenu);
        menuBar.add(opsMenu);
        menuBar.add(helpMenu);

        setJMenuBar(menuBar);
    }

    /**
     * Builds top action toolbar (JToolBar).
     */
    private void initToolBar() {
        JToolBar toolBar = new JToolBar("CyberShield Quick Access");
        toolBar.setFloatable(false);
        toolBar.setBackground(SwingTheme.PANEL_BG);
        toolBar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, SwingTheme.BORDER_COLOR));

        JButton btnDash = new JButton("Dashboard");
        SwingTheme.styleSecondaryButton(btnDash);
        btnDash.addActionListener(e -> tabbedPane.setSelectedIndex(0));

        JButton btnInc = new JButton("Incidents");
        SwingTheme.styleSecondaryButton(btnInc);
        btnInc.addActionListener(e -> tabbedPane.setSelectedIndex(1));

        JButton btnThreat = new JButton("Threat Response");
        SwingTheme.styleSecondaryButton(btnThreat);
        btnThreat.addActionListener(e -> tabbedPane.setSelectedIndex(2));

        JButton btnInv = new JButton("Investigation");
        SwingTheme.styleSecondaryButton(btnInv);
        btnInv.addActionListener(e -> tabbedPane.setSelectedIndex(3));

        JButton btnAcc = new JButton("Account Security");
        SwingTheme.styleSecondaryButton(btnAcc);
        btnAcc.addActionListener(e -> tabbedPane.setSelectedIndex(4));

        JButton btnAccess = new JButton("Access");
        SwingTheme.styleSecondaryButton(btnAccess);
        btnAccess.addActionListener(e -> tabbedPane.setSelectedIndex(5));

        JButton btnSimThreat = new JButton("Simulate Threat");
        btnSimThreat.setBackground(SwingTheme.SEVERITY_CRITICAL);
        btnSimThreat.setForeground(Color.WHITE);
        btnSimThreat.setFont(SwingTheme.FONT_BOLD);
        btnSimThreat.setFocusPainted(false);
        btnSimThreat.setBorder(BorderFactory.createEmptyBorder(6, 12, 6, 12));
        btnSimThreat.addActionListener(e -> {
            apiClient.simulateThreat();
            accessMonitoringPanel.loadEvents();
            tabbedPane.setSelectedIndex(5);
            JOptionPane.showMessageDialog(this, "Simulated intrusion threat logged and displayed.", "Alert", JOptionPane.WARNING_MESSAGE);
        });

        JButton btnRefresh = new JButton("Refresh");
        SwingTheme.styleSecondaryButton(btnRefresh);
        btnRefresh.addActionListener(e -> refreshAllPanels());

        JButton btnLogout = new JButton("Sign Out");
        SwingTheme.styleSecondaryButton(btnLogout);
        btnLogout.addActionListener(e -> handleLogout());

        toolBar.add(Box.createHorizontalStrut(8));
        toolBar.add(btnDash);
        toolBar.add(Box.createHorizontalStrut(6));
        toolBar.add(btnInc);
        toolBar.add(Box.createHorizontalStrut(6));
        toolBar.add(btnThreat);
        toolBar.add(Box.createHorizontalStrut(6));
        toolBar.add(btnInv);
        toolBar.add(Box.createHorizontalStrut(6));
        toolBar.add(btnAcc);
        toolBar.add(Box.createHorizontalStrut(6));
        toolBar.add(btnAccess);
        toolBar.add(Box.createHorizontalStrut(8));
        toolBar.add(btnSimThreat);
        toolBar.add(Box.createHorizontalStrut(14));
        toolBar.add(btnRefresh);
        toolBar.add(Box.createHorizontalGlue());
        toolBar.add(btnLogout);
        toolBar.add(Box.createHorizontalStrut(8));

        add(toolBar, BorderLayout.NORTH);
    }

    /**
     * Initializes the central JTabbedPane hosting all modular views.
     */
    private void initTabs() {
        tabbedPane = new JTabbedPane(JTabbedPane.TOP);
        tabbedPane.setBackground(SwingTheme.BG_COLOR);
        tabbedPane.setForeground(SwingTheme.TEXT_PRIMARY);
        tabbedPane.setFont(SwingTheme.FONT_BOLD);

        dashboardPanel = new DashboardPanel();
        incidentPanel = new IncidentPanel();
        threatResponsePanel = new ThreatResponsePanel();
        investigationPanel = new InvestigationPanel();
        accountSecurityPanel = new AccountSecurityPanel();
        accessMonitoringPanel = new AccessMonitoringPanel();
        activityHistoryPanel = new ActivityHistoryPanel();
        componentLabPanel = new ComponentLabPanel();
        aboutPanel = new AboutPanel();

        tabbedPane.addTab("Dashboard", dashboardPanel);
        tabbedPane.addTab("Incidents", incidentPanel);
        tabbedPane.addTab("Threat Response", threatResponsePanel);
        tabbedPane.addTab("Investigation Center", investigationPanel);
        tabbedPane.addTab("Account Security", accountSecurityPanel);
        tabbedPane.addTab("Access Telemetry", accessMonitoringPanel);
        tabbedPane.addTab("Activity History", activityHistoryPanel);
        tabbedPane.addTab("Component Lab", componentLabPanel);
        tabbedPane.addTab("About & Review", aboutPanel);

        // When switching tabs, auto-refresh relevant content
        tabbedPane.addChangeListener(e -> {
            int idx = tabbedPane.getSelectedIndex();
            if (idx == 0) dashboardPanel.loadStats();
            else if (idx == 1) incidentPanel.loadIncidents();
            else if (idx == 2) threatResponsePanel.refresh();
            else if (idx == 3) investigationPanel.refresh();
            else if (idx == 4) accountSecurityPanel.refresh();
            else if (idx == 5) accessMonitoringPanel.loadEvents();
            else if (idx == 6) activityHistoryPanel.loadLogs();
        });

        add(tabbedPane, BorderLayout.CENTER);
    }

    /**
     * Builds bottom status bar showing user session role, DB status, and system clock.
     */
    private void initStatusBar() {
        JPanel statusBar = new JPanel(new BorderLayout());
        statusBar.setBackground(SwingTheme.PANEL_BG);
        statusBar.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(1, 0, 0, 0, SwingTheme.BORDER_COLOR),
            BorderFactory.createEmptyBorder(6, 14, 6, 14)
        ));

        User current = apiClient.getCurrentUser();
        String userText = "Active User: " + (current != null ? current.getUsername() : "Guest") +
            " | Role: " + (current != null ? current.getRole() : "ANONYMOUS");
        userStatusLabel = new JLabel(userText);
        userStatusLabel.setFont(SwingTheme.FONT_SMALL);
        userStatusLabel.setForeground(SwingTheme.TEXT_PRIMARY);

        dbStatusLabel = new JLabel("Database: SQLite (data/cybershield.db) • WAL Mode Active");
        dbStatusLabel.setFont(SwingTheme.FONT_SMALL);
        dbStatusLabel.setForeground(SwingTheme.STATUS_RESOLVED);

        clockLabel = new JLabel();
        clockLabel.setFont(SwingTheme.FONT_SMALL);
        clockLabel.setForeground(SwingTheme.TEXT_MUTED);

        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 16, 0));
        leftPanel.setOpaque(false);
        leftPanel.add(userStatusLabel);
        leftPanel.add(dbStatusLabel);

        statusBar.add(leftPanel, BorderLayout.WEST);
        statusBar.add(clockLabel, BorderLayout.EAST);

        add(statusBar, BorderLayout.SOUTH);
    }

    /**
     * Refreshes all active sub-panels from database.
     */
    public void refreshAllPanels() {
        dashboardPanel.loadStats();
        incidentPanel.loadIncidents();
        threatResponsePanel.refresh();
        investigationPanel.refresh();
        accountSecurityPanel.refresh();
        accessMonitoringPanel.loadEvents();
        activityHistoryPanel.loadLogs();
    }

    /**
     * Starts a live 1-second timer to update status bar time.
     */
    private void startClock() {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        clockLabel.setText(sdf.format(new Date()));
        clockTimer = new Timer(1000, e -> clockLabel.setText(sdf.format(new Date())));
        clockTimer.start();
    }

    /**
     * Logs out active session and re-opens LoginFrame on EDT.
     */
    private void handleLogout() {
        int confirm = JOptionPane.showConfirmDialog(this,
            "Are you sure you want to sign out of CyberShield Desktop?",
            "Sign Out", JOptionPane.YES_NO_OPTION);

        if (confirm == JOptionPane.YES_OPTION) {
            if (clockTimer != null) clockTimer.stop();
            apiClient.logout();
            SwingUtilities.invokeLater(() -> {
                LoginFrame loginFrame = new LoginFrame();
                loginFrame.setVisible(true);
                dispose(); // Close main frame
            });
        }
    }
}
