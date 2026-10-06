package cybershield.gui;

import cybershield.dao.LogDAO;
import cybershield.model.LogEntry;
import cybershield.model.User;
import cybershield.util.Theme;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JToolBar;

/**
 * MainFrame — The main application window.
 * Demonstrates INHERITANCE: extends JFrame.
 * Contains a menu bar, toolbar, tabbed pane with Dashboard and module panels, and a status bar.
 */
public class MainFrame extends JFrame {

    // UI Components
    private JTabbedPane tabbedPane;
    private JLabel statusLabel;

    // Tab panels
    private DashboardPanel dashboardPanel;
    private ThreatMonitorPanel threatMonitorPanel;
    private IncidentsPanel incidentsPanel;
    private ReportsPanel reportsPanel;
    private SettingsPanel settingsPanel;

    // The currently logged-in user
    private User currentUser;

    // Constructor — builds the entire main window
    public MainFrame() {
        // -------- Window settings --------
        setTitle("CyberShield - Threat Monitoring & Incident Response");
        setSize(1200, 750);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);  // Center on screen
        setLayout(new BorderLayout());

        // Apply dark background to the content pane
        getContentPane().setBackground(Theme.BACKGROUND);

        // -------- Build the UI components --------
        setJMenuBar(createMenuBar());
        add(createToolBar(), BorderLayout.NORTH);
        add(createTabbedPane(), BorderLayout.CENTER);
        add(createStatusBar(), BorderLayout.SOUTH);
    }

    // ================================================================
    // MENU BAR
    // ================================================================

    /** Creates the menu bar with File, View, and Help menus. */
    private JMenuBar createMenuBar() {
        JMenuBar menuBar = new JMenuBar();
        menuBar.setBackground(Theme.PANEL_BG);

        // ---- File menu ----
        JMenu fileMenu = new JMenu("File");
        fileMenu.setForeground(Theme.TEXT_PRIMARY);

        JMenuItem logoutItem = new JMenuItem("Logout");
        // Event listener: triggered when user clicks File > Logout
        logoutItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                performLogout();
            }
        });
        fileMenu.add(logoutItem);

        fileMenu.addSeparator();

        JMenuItem exitItem = new JMenuItem("Exit");
        // Event listener: triggered when user clicks File > Exit
        exitItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                System.exit(0);
            }
        });
        fileMenu.add(exitItem);

        // ---- View menu ----
        JMenu viewMenu = new JMenu("View");
        viewMenu.setForeground(Theme.TEXT_PRIMARY);

        JMenuItem refreshItem = new JMenuItem("Refresh All Tabs");
        // Event listener: triggered when user clicks View > Refresh All Tabs
        refreshItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                refreshAllTabs();
            }
        });
        viewMenu.add(refreshItem);

        // ---- Help menu ----
        JMenu helpMenu = new JMenu("Help");
        helpMenu.setForeground(Theme.TEXT_PRIMARY);

        JMenuItem aboutItem = new JMenuItem("About");
        // Event listener: triggered when user clicks Help > About
        aboutItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JOptionPane.showMessageDialog(
                    MainFrame.this,
                    "CyberShield v1.0\n"
                        + "Cybersecurity Threat Monitoring & Incident Response\n\n"
                        + "AOOP College Project\n"
                        + "Built with Java Swing + MySQL",
                    "About CyberShield",
                    JOptionPane.INFORMATION_MESSAGE
                );
            }
        });
        helpMenu.add(aboutItem);

        menuBar.add(fileMenu);
        menuBar.add(viewMenu);
        menuBar.add(helpMenu);

        return menuBar;
    }

    // ================================================================
    // TOOLBAR
    // ================================================================

    /** Creates the toolbar with Refresh and Logout buttons. */
    private JToolBar createToolBar() {
        JToolBar toolBar = new JToolBar();
        toolBar.setFloatable(false);
        toolBar.setBackground(Theme.PANEL_BG);
        toolBar.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

        // Refresh button
        JButton refreshButton = new JButton("⟳ Refresh");
        Theme.styleButton(refreshButton);
        // Event listener: triggered when user clicks the Refresh toolbar button
        refreshButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                refreshAllTabs();
            }
        });
        toolBar.add(refreshButton);

        toolBar.addSeparator(new Dimension(10, 0));

        // Logout button
        JButton logoutButton = new JButton("⏻ Logout");
        Theme.styleButton(logoutButton);
        logoutButton.setBackground(Theme.CRITICAL);
        logoutButton.setForeground(Theme.TEXT_PRIMARY);
        // Event listener: triggered when user clicks the Logout toolbar button
        logoutButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                performLogout();
            }
        });
        toolBar.add(logoutButton);

        return toolBar;
    }

    // ================================================================
    // LOGOUT LOGIC
    // ================================================================

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
    // TABBED PANE
    // ================================================================

    /** Creates the tabbed pane with DashboardPanel and other module panels. */
    private JTabbedPane createTabbedPane() {
        tabbedPane = new JTabbedPane();
        tabbedPane.setBackground(Theme.PANEL_BG);
        tabbedPane.setForeground(Theme.TEXT_PRIMARY);
        tabbedPane.setFont(Theme.FONT_BODY);

        // Create panels (DashboardPanel is fully functional; others are placeholders)
        dashboardPanel      = new DashboardPanel();
        threatMonitorPanel  = new ThreatMonitorPanel();
        incidentsPanel      = new IncidentsPanel();
        reportsPanel        = new ReportsPanel();
        settingsPanel       = new SettingsPanel();

        // Add tabs
        tabbedPane.addTab("Dashboard",      dashboardPanel);
        tabbedPane.addTab("Threat Monitor",  threatMonitorPanel);
        tabbedPane.addTab("Incidents",       incidentsPanel);
        tabbedPane.addTab("Reports",         reportsPanel);
        tabbedPane.addTab("Settings",        settingsPanel);

        return tabbedPane;
    }

    // ================================================================
    // STATUS BAR
    // ================================================================

    /** Creates the status bar at the bottom showing the logged-in user. */
    private JPanel createStatusBar() {
        JPanel statusBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statusBar.setBackground(Theme.BACKGROUND);
        statusBar.setBorder(BorderFactory.createEmptyBorder(4, 10, 4, 10));

        statusLabel = new JLabel("Not logged in");
        statusLabel.setFont(Theme.FONT_SMALL);
        statusLabel.setForeground(Theme.TEXT_SECONDARY);
        statusBar.add(statusLabel);

        return statusBar;
    }

    // ================================================================
    // PUBLIC METHODS
    // ================================================================

    /**
     * Sets the currently logged-in user, updates the status bar, and refreshes the dashboard.
     * Other modules can call this after a successful login.
     */
    public void setCurrentUser(User user) {
        this.currentUser = user;
        if (user != null) {
            statusLabel.setText("Logged in as: " + user.getUsername()
                    + "  |  Role: " + user.getRole());
            if (dashboardPanel != null) {
                dashboardPanel.refreshData();
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
