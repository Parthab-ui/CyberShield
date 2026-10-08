package cybershield.gui;

import cybershield.dao.LogDAO;
import cybershield.model.LogEntry;
import cybershield.model.User;
import cybershield.util.Theme;
import cybershield.util.ThemeSettings;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBoxMenuItem;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButtonMenuItem;
import javax.swing.JTabbedPane;
import javax.swing.JToolBar;
import javax.swing.KeyStroke;

/**
 * MainFrame — The primary application window hosting the entire CyberShield suite.
 * Demonstrates INHERITANCE: extends JFrame.
 * Integrates all 3 student modules:
 * - Module A: Authentication, Login flow, and Executive Dashboard.
 * - Module B: Threat Monitor, live detection, and real-time visualization.
 * - Module C: Incident Response, Reporting suite, Settings, and SOC Desktop Monitor.
 * Provides a comprehensive JMenuBar, JToolBar with accelerators and mnemonics,
 * a central JTabbedPane, and a togglable status bar.
 */
public class MainFrame extends JFrame {

    // Central UI components
    private JTabbedPane tabbedPane;
    private JLabel      statusLabel;
    private JPanel      statusBar;

    // Feature tabs across Modules A, B, and C
    private DashboardPanel     dashboardPanel;
    private ThreatMonitorPanel threatMonitorPanel;
    private IncidentPanel      incidentPanel;
    private ReportPanel        reportPanel;
    private SettingsPanel      settingsPanel;

    // Authenticated session user
    private User currentUser;

    // Constructor — initializes the entire main interface
    public MainFrame() {
        setTitle("CyberShield — Threat Monitoring & Incident Response");
        setSize(1240, 780);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);  // Center on screen
        setLayout(new BorderLayout());

        getContentPane().setBackground(Theme.BACKGROUND);

        // Build window anatomy
        setJMenuBar(createMenuBar());
        add(createToolBar(), BorderLayout.NORTH);
        add(createTabbedPane(), BorderLayout.CENTER);
        add(createStatusBar(), BorderLayout.SOUTH);
    }

    // ================================================================
    // MENU BAR
    // ================================================================

    /** Creates the top menu bar with File, View, and Help menus, mnemonics, and accelerators. */
    private JMenuBar createMenuBar() {
        JMenuBar menuBar = new JMenuBar();
        menuBar.setBackground(Theme.PANEL_BG);
        menuBar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Theme.ACCENT));

        // ----------------- FILE MENU -----------------
        JMenu fileMenu = new JMenu("File");
        fileMenu.setMnemonic(KeyEvent.VK_F);
        fileMenu.setForeground(Theme.TEXT_PRIMARY);

        JMenuItem newIncidentItem = new JMenuItem("New Incident...");
        newIncidentItem.setMnemonic(KeyEvent.VK_N);
        newIncidentItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_N, ActionEvent.CTRL_MASK));
        newIncidentItem.addActionListener(e -> openNewIncidentDialog());
        fileMenu.add(newIncidentItem);

        fileMenu.addSeparator();

        JMenuItem logoutItem = new JMenuItem("Logout");
        logoutItem.setMnemonic(KeyEvent.VK_L);
        logoutItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_L, ActionEvent.CTRL_MASK));
        logoutItem.addActionListener(e -> performLogout());
        fileMenu.add(logoutItem);

        fileMenu.addSeparator();

        JMenuItem exitItem = new JMenuItem("Exit");
        exitItem.setMnemonic(KeyEvent.VK_X);
        exitItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_Q, ActionEvent.CTRL_MASK));
        exitItem.addActionListener(e -> System.exit(0));
        fileMenu.add(exitItem);

        // ----------------- VIEW MENU -----------------
        JMenu viewMenu = new JMenu("View");
        viewMenu.setMnemonic(KeyEvent.VK_V);
        viewMenu.setForeground(Theme.TEXT_PRIMARY);

        JMenuItem refreshItem = new JMenuItem("Refresh All Tabs");
        refreshItem.setMnemonic(KeyEvent.VK_R);
        refreshItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_R, ActionEvent.CTRL_MASK));
        refreshItem.addActionListener(e -> refreshAllTabs());
        viewMenu.add(refreshItem);

        JMenuItem liveMonitorItem = new JMenuItem("Live Monitor (SOC Desktop)");
        liveMonitorItem.setMnemonic(KeyEvent.VK_M);
        liveMonitorItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_M, ActionEvent.CTRL_MASK));
        liveMonitorItem.addActionListener(e -> openLiveDesktopMonitor());
        viewMenu.add(liveMonitorItem);

        viewMenu.addSeparator();

        JCheckBoxMenuItem statusBarItem = new JCheckBoxMenuItem("Show Status Bar", true);
        statusBarItem.setMnemonic(KeyEvent.VK_S);
        statusBarItem.addActionListener(e -> {
            if (statusBar != null) {
                statusBar.setVisible(statusBarItem.isSelected());
                MainFrame.this.revalidate();
            }
        });
        viewMenu.add(statusBarItem);

        viewMenu.addSeparator();

        // Theme Mode Radio Items
        JRadioButtonMenuItem darkThemeItem = new JRadioButtonMenuItem("Theme: Dark Mode", ThemeSettings.isDarkMode());
        JRadioButtonMenuItem lightThemeItem = new JRadioButtonMenuItem("Theme: Light Mode", !ThemeSettings.isDarkMode());
        ButtonGroup themeGroup = new ButtonGroup();
        themeGroup.add(darkThemeItem);
        themeGroup.add(lightThemeItem);

        darkThemeItem.addActionListener(e -> {
            ThemeSettings.setDarkMode(true);
            refreshAllTabs();
        });
        lightThemeItem.addActionListener(e -> {
            ThemeSettings.setDarkMode(false);
            refreshAllTabs();
        });

        viewMenu.add(darkThemeItem);
        viewMenu.add(lightThemeItem);

        // ----------------- HELP MENU -----------------
        JMenu helpMenu = new JMenu("Help");
        helpMenu.setMnemonic(KeyEvent.VK_H);
        helpMenu.setForeground(Theme.TEXT_PRIMARY);

        JMenuItem aboutItem = new JMenuItem("About CyberShield");
        aboutItem.setMnemonic(KeyEvent.VK_A);
        aboutItem.addActionListener(e -> showAboutDialog());
        helpMenu.add(aboutItem);

        menuBar.add(fileMenu);
        menuBar.add(viewMenu);
        menuBar.add(helpMenu);

        return menuBar;
    }

    // ================================================================
    // TOOLBAR
    // ================================================================

    /** Creates the quick-action toolbar with mnemonic-enabled buttons. */
    private JToolBar createToolBar() {
        JToolBar toolBar = new JToolBar();
        toolBar.setFloatable(false);
        toolBar.setBackground(Theme.PANEL_BG);
        toolBar.setBorder(BorderFactory.createEmptyBorder(6, 10, 6, 10));

        // Refresh button
        JButton refreshButton = new JButton("⟳ Refresh");
        Theme.styleButton(refreshButton);
        refreshButton.setMnemonic(KeyEvent.VK_R);
        refreshButton.setToolTipText("Refresh all tabs (Alt+R / Ctrl+R)");
        refreshButton.addActionListener(e -> refreshAllTabs());
        toolBar.add(refreshButton);

        toolBar.addSeparator(new Dimension(8, 0));

        // New Incident button
        JButton newIncidentBtn = new JButton("+ New Incident");
        Theme.styleButton(newIncidentBtn);
        newIncidentBtn.setMnemonic(KeyEvent.VK_N);
        newIncidentBtn.setToolTipText("Create an incident ticket (Alt+N / Ctrl+N)");
        newIncidentBtn.addActionListener(e -> openNewIncidentDialog());
        toolBar.add(newIncidentBtn);

        toolBar.addSeparator(new Dimension(8, 0));

        // Live Monitor button
        JButton liveMonitorBtn = new JButton("⧉ Live Monitor");
        Theme.styleButton(liveMonitorBtn);
        liveMonitorBtn.setMnemonic(KeyEvent.VK_M);
        liveMonitorBtn.setToolTipText("Open MDI Security Operations Center (Alt+M / Ctrl+M)");
        liveMonitorBtn.addActionListener(e -> openLiveDesktopMonitor());
        toolBar.add(liveMonitorBtn);

        toolBar.addSeparator(new Dimension(15, 0));

        // Logout button
        JButton logoutButton = new JButton("⏻ Logout");
        Theme.styleButton(logoutButton);
        logoutButton.setBackground(Theme.CRITICAL);
        logoutButton.setForeground(Theme.TEXT_PRIMARY);
        logoutButton.setMnemonic(KeyEvent.VK_L);
        logoutButton.setToolTipText("End current session and return to login");
        logoutButton.addActionListener(e -> performLogout());
        toolBar.add(logoutButton);

        return toolBar;
    }

    // ================================================================
    // TABBED PANE
    // ================================================================

    /** Creates the central tabbed pane connecting all module panels. */
    private JTabbedPane createTabbedPane() {
        tabbedPane = new JTabbedPane();
        tabbedPane.setBackground(Theme.PANEL_BG);
        tabbedPane.setForeground(Theme.TEXT_PRIMARY);
        tabbedPane.setFont(Theme.FONT_BODY);

        // Instantiate panels
        dashboardPanel     = new DashboardPanel();
        threatMonitorPanel = new ThreatMonitorPanel();
        incidentPanel      = new IncidentPanel();
        reportPanel        = new ReportPanel();
        settingsPanel      = new SettingsPanel();

        // Register tabs
        tabbedPane.addTab("Dashboard",      dashboardPanel);
        tabbedPane.addTab("Threat Monitor", threatMonitorPanel);
        tabbedPane.addTab("Incidents",      incidentPanel);
        tabbedPane.addTab("Reports",        reportPanel);
        tabbedPane.addTab("Settings",       settingsPanel);

        return tabbedPane;
    }

    // ================================================================
    // STATUS BAR
    // ================================================================

    /** Creates the bottom status bar displaying active session information. */
    private JPanel createStatusBar() {
        statusBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 4));
        statusBar.setBackground(Theme.BACKGROUND);
        statusBar.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, Theme.PANEL_BG));

        statusLabel = new JLabel("Not logged in");
        statusLabel.setFont(Theme.FONT_SMALL);
        statusLabel.setForeground(Theme.TEXT_SECONDARY);
        statusBar.add(statusLabel);

        return statusBar;
    }

    // ================================================================
    // ACTIONS & DIALOGS
    // ================================================================

    /** Opens the modal IncidentDialog to log a new incident. */
    private void openNewIncidentDialog() {
        int userId = (currentUser != null) ? currentUser.getId() : 1;
        IncidentDialog dialog = new IncidentDialog(this, userId, null);
        dialog.setVisible(true);
        if (dialog.isSaved()) {
            if (incidentPanel != null) {
                incidentPanel.refreshData();
            }
            if (dashboardPanel != null) {
                dashboardPanel.refreshData();
            }
        }
    }

    /** Opens the MDI Desktop SOC Monitor window. */
    private void openLiveDesktopMonitor() {
        DesktopMonitorFrame monitorFrame = new DesktopMonitorFrame();
        monitorFrame.setVisible(true);
    }

    /** Shows the About modal dialog. */
    private void showAboutDialog() {
        JOptionPane.showMessageDialog(
            this,
            "CyberShield v1.0.0 (Production Release)\n"
                + "Cybersecurity Threat Monitoring & Incident Response System\n\n"
                + "Advanced Object-Oriented Programming (AOOP) Course Project\n"
                + "Architecture: Java 17 Swing GUI + Plain JDBC + MySQL\n\n"
                + "Team Allocation:\n"
                + "• Module A: Authentication, Users & Executive Dashboard\n"
                + "• Module B: Threat Monitor, Live Radar & Detection Engine\n"
                + "• Module C: Incident Response, Reporting Suite & Settings",
            "About CyberShield",
            JOptionPane.INFORMATION_MESSAGE
        );
    }

    /**
     * Confirms logout, writes an audit log entry, closes MainFrame, and returns to LoginFrame.
     */
    private void performLogout() {
        int confirm = JOptionPane.showConfirmDialog(
            MainFrame.this,
            "Are you sure you want to logout?",
            "Confirm Logout",
            JOptionPane.YES_NO_OPTION
        );
        if (confirm == JOptionPane.YES_OPTION) {
            if (currentUser != null) {
                LogDAO logDAO = new LogDAO();
                logDAO.add(new LogEntry(currentUser.getId(), "User logged out: " + currentUser.getUsername()));
            }
            dispose();
            LoginFrame loginFrame = new LoginFrame();
            loginFrame.setLoginCallback(new LoginFrame.LoginCallback() {
                @Override
                public void onLoginSuccess(User user) {
                    MainFrame newFrame = new MainFrame();
                    newFrame.setCurrentUser(user);
                    newFrame.setVisible(true);
                }
            });
            loginFrame.setVisible(true);
        }
    }

    // ================================================================
    // PUBLIC METHODS
    // ================================================================

    /**
     * Sets the currently logged-in user, updates the status bar, and cascades user to all tabs.
     */
    public void setCurrentUser(User user) {
        this.currentUser = user;
        if (user != null) {
            statusLabel.setText("Logged in as: " + user.getUsername()
                    + "  |  Role: " + user.getRole()
                    + "  |  System Status: Operational");
            if (dashboardPanel != null) {
                dashboardPanel.refreshData();
            }
            if (threatMonitorPanel != null) {
                threatMonitorPanel.setCurrentUser(user);
                threatMonitorPanel.refreshData();
            }
            if (incidentPanel != null) {
                incidentPanel.setCurrentUser(user);
                incidentPanel.refreshData();
            }
            if (reportPanel != null) {
                reportPanel.setCurrentUser(user);
                reportPanel.refreshData();
            }
            if (settingsPanel != null) {
                settingsPanel.setCurrentUser(user);
                settingsPanel.refreshData();
            }
        } else {
            statusLabel.setText("Not logged in");
        }
    }

    /** Returns the currently logged-in user. */
    public User getCurrentUser() {
        return currentUser;
    }

    /** Calls refreshData() on every tab panel that extends BasePanel. */
    private void refreshAllTabs() {
        int tabCount = tabbedPane.getTabCount();
        for (int i = 0; i < tabCount; i++) {
            Component comp = tabbedPane.getComponentAt(i);
            if (comp instanceof BasePanel) {
                ((BasePanel) comp).refreshData();
            }
        }
        JOptionPane.showMessageDialog(this, "All tabs refreshed.",
                "Refresh", JOptionPane.INFORMATION_MESSAGE);
    }
}
