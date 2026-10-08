package cybershield.gui;

import cybershield.dao.BlockedIPDAO;
import cybershield.dao.IncidentDAO;
import cybershield.dao.ThreatDAO;
import cybershield.model.Incident;
import cybershield.model.Threat;
import cybershield.util.Theme;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JDesktopPane;
import javax.swing.JFrame;
import javax.swing.JInternalFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.Timer;

/**
 * DesktopMonitorFrame — Secondary multi-window monitor screen demonstrating MDI (Multiple Document Interface).
 * Extends JFrame and hosts a JDesktopPane with two JInternalFrames:
 * 1. Live Threat Feed: Real-time JList polling recent threats via a 3-second javax.swing.Timer.
 * 2. System Health: Real-time JProgressBars for CPU, Memory, Blocked IPs, and Active Incidents.
 * Demonstrates JDesktopPane, JInternalFrame, JProgressBar, and Timer for viva evaluation.
 */
public class DesktopMonitorFrame extends JFrame {

    private final JDesktopPane desktopPane;
    private final JInternalFrame threatFrame;
    private final JInternalFrame healthFrame;

    // Live Feed components
    private final DefaultListModel<String> threatListModel;
    private final JList<String> threatList;
    private final JLabel feedStatusLabel;

    // System Health components
    private final JProgressBar cpuBar;
    private final JProgressBar memoryBar;
    private final JProgressBar ipBar;
    private final JProgressBar incidentBar;
    private final JLabel memDetailsLabel;

    // Polling timer
    private final Timer pollingTimer;
    private final SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss");

    // DAOs
    private final ThreatDAO threatDAO;
    private final IncidentDAO incidentDAO;
    private final BlockedIPDAO blockedIPDAO;

    // Simulation counter for subtle CPU variation
    private int cpuTick = 0;

    // Constructor — configures MDI desktop and internal frames
    public DesktopMonitorFrame() {
        super("CyberShield — Live Security Operations Center (MDI Desktop)");
        setSize(960, 620);
        setMinimumSize(new Dimension(800, 500));
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

        this.threatDAO = new ThreatDAO();
        this.incidentDAO = new IncidentDAO();
        this.blockedIPDAO = new BlockedIPDAO();

        // MDI Desktop Pane
        desktopPane = new JDesktopPane();
        desktopPane.setBackground(Theme.BACKGROUND);

        // Toolbar
        JPanel toolBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 8));
        toolBar.setBackground(Theme.PANEL_BG);
        toolBar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Theme.ACCENT));

        JButton tileBtn = new JButton("Tile Windows");
        Theme.styleButton(tileBtn);
        tileBtn.addActionListener(e -> tileWindows());

        JButton cascadeBtn = new JButton("Cascade Windows");
        cascadeBtn.setBackground(new Color(60, 60, 90));
        cascadeBtn.setForeground(Color.WHITE);
        cascadeBtn.setFont(Theme.FONT_BODY);
        cascadeBtn.addActionListener(e -> cascadeWindows());

        JButton refreshBtn = new JButton("Refresh Now");
        refreshBtn.setBackground(new Color(60, 60, 90));
        refreshBtn.setForeground(Color.WHITE);
        refreshBtn.setFont(Theme.FONT_BODY);
        refreshBtn.addActionListener(e -> refreshAllData());

        JLabel liveIndicator = new JLabel("● LIVE SOC TELEMETRY (3s Poll)");
        liveIndicator.setFont(Theme.FONT_SMALL);
        liveIndicator.setForeground(Theme.SUCCESS);
        liveIndicator.setToolTipText("Periodic poll of local database events and telemetry");

        toolBar.add(tileBtn);
        toolBar.add(cascadeBtn);
        toolBar.add(refreshBtn);
        toolBar.add(liveIndicator);

        // ----------------- INTERNAL FRAME 1: Live Threat Feed -----------------
        threatFrame = new JInternalFrame("Live Threat Feed", true, true, true, true);
        threatFrame.setSize(480, 480);
        threatFrame.setLocation(15, 15);
        threatFrame.getContentPane().setBackground(Theme.PANEL_BG);

        JPanel threatContent = new JPanel(new BorderLayout(5, 5));
        threatContent.setBackground(Theme.PANEL_BG);
        threatContent.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        threatListModel = new DefaultListModel<>();
        threatList = new JList<>(threatListModel);
        threatList.setBackground(new Color(20, 20, 45));
        threatList.setForeground(Theme.TEXT_PRIMARY);
        threatList.setFont(Theme.FONT_BODY);

        JScrollPane scrollFeed = new JScrollPane(threatList);
        scrollFeed.setBorder(BorderFactory.createLineBorder(Theme.ACCENT));
        threatContent.add(scrollFeed, BorderLayout.CENTER);

        feedStatusLabel = new JLabel("Connecting to feed...", JLabel.LEFT);
        feedStatusLabel.setFont(Theme.FONT_SMALL);
        feedStatusLabel.setForeground(Theme.TEXT_SECONDARY);
        threatContent.add(feedStatusLabel, BorderLayout.SOUTH);

        threatFrame.getContentPane().add(threatContent);
        threatFrame.setVisible(true);

        // ----------------- INTERNAL FRAME 2: System Health -----------------
        healthFrame = new JInternalFrame("System Health & Resources", true, true, true, true);
        healthFrame.setSize(420, 480);
        healthFrame.setLocation(510, 15);
        healthFrame.getContentPane().setBackground(Theme.PANEL_BG);

        JPanel healthContent = new JPanel(new GridBagLayout());
        healthContent.setBackground(Theme.PANEL_BG);
        healthContent.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 5, 8, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridx = 0; gbc.gridy = 0;

        // CPU Bar
        JLabel cpuLabel = new JLabel("Threat Inspection CPU Load:");
        cpuLabel.setFont(Theme.FONT_BODY);
        cpuLabel.setForeground(Theme.TEXT_PRIMARY);
        healthContent.add(cpuLabel, gbc);

        gbc.gridy = 1;
        cpuBar = new JProgressBar(0, 100);
        cpuBar.setValue(28);
        cpuBar.setStringPainted(true);
        cpuBar.setForeground(Theme.ACCENT);
        cpuBar.setBackground(Theme.BACKGROUND);
        healthContent.add(cpuBar, gbc);

        // Memory Bar
        gbc.gridy = 2;
        JLabel memLabel = new JLabel("JVM Heap Memory Allocation:");
        memLabel.setFont(Theme.FONT_BODY);
        memLabel.setForeground(Theme.TEXT_PRIMARY);
        healthContent.add(memLabel, gbc);

        gbc.gridy = 3;
        memoryBar = new JProgressBar(0, 100);
        memoryBar.setValue(45);
        memoryBar.setStringPainted(true);
        memoryBar.setForeground(Theme.WARNING);
        memoryBar.setBackground(Theme.BACKGROUND);
        healthContent.add(memoryBar, gbc);

        gbc.gridy = 4;
        memDetailsLabel = new JLabel("Memory: 120 MB / 512 MB");
        memDetailsLabel.setFont(Theme.FONT_SMALL);
        memDetailsLabel.setForeground(Theme.TEXT_SECONDARY);
        healthContent.add(memDetailsLabel, gbc);

        // Blocked IP Bar
        gbc.gridy = 5;
        JLabel ipLabel = new JLabel("Firewall Blocked IPs Volume:");
        ipLabel.setFont(Theme.FONT_BODY);
        ipLabel.setForeground(Theme.TEXT_PRIMARY);
        healthContent.add(ipLabel, gbc);

        gbc.gridy = 6;
        ipBar = new JProgressBar(0, 50);
        ipBar.setValue(0);
        ipBar.setStringPainted(true);
        ipBar.setForeground(Theme.CRITICAL);
        ipBar.setBackground(Theme.BACKGROUND);
        healthContent.add(ipBar, gbc);

        // Open Incident Bar
        gbc.gridy = 7;
        JLabel incidentLabel = new JLabel("Active Unresolved Incidents:");
        incidentLabel.setFont(Theme.FONT_BODY);
        incidentLabel.setForeground(Theme.TEXT_PRIMARY);
        healthContent.add(incidentLabel, gbc);

        gbc.gridy = 8;
        incidentBar = new JProgressBar(0, 20);
        incidentBar.setValue(0);
        incidentBar.setStringPainted(true);
        incidentBar.setForeground(Theme.WARNING);
        incidentBar.setBackground(Theme.BACKGROUND);
        healthContent.add(incidentBar, gbc);

        healthFrame.getContentPane().add(healthContent);
        healthFrame.setVisible(true);

        // Add internal frames to MDI Desktop
        desktopPane.add(threatFrame);
        desktopPane.add(healthFrame);

        setLayout(new BorderLayout());
        add(toolBar, BorderLayout.NORTH);
        add(desktopPane, BorderLayout.CENTER);

        // Initialize timer (polls every 3 seconds)
        pollingTimer = new Timer(3000, e -> refreshAllData());
        pollingTimer.start();

        // Clean up timer on window close to avoid thread leaks
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                if (pollingTimer != null && pollingTimer.isRunning()) {
                    pollingTimer.stop();
                }
            }
        });

        // Initial fetch
        refreshAllData();

        // Position windows side-by-side initially
        javax.swing.SwingUtilities.invokeLater(this::tileWindows);
    }

    /** Arranges the two internal frames side-by-side across the desktop pane. */
    public void tileWindows() {
        int width = desktopPane.getWidth();
        int height = desktopPane.getHeight();
        if (width <= 0 || height <= 0) {
            width = getWidth() - 30;
            height = getHeight() - 80;
        }

        int halfWidth = (width - 30) / 2;
        int frameHeight = Math.max(300, height - 20);

        threatFrame.setBounds(10, 10, halfWidth, frameHeight);
        healthFrame.setBounds(halfWidth + 20, 10, halfWidth, frameHeight);
    }

    /** Cascades the internal frames diagonally. */
    public void cascadeWindows() {
        int width = Math.max(400, desktopPane.getWidth() - 100);
        int height = Math.max(300, desktopPane.getHeight() - 100);

        threatFrame.setBounds(20, 20, width, height);
        healthFrame.setBounds(60, 60, width, height);
        healthFrame.toFront();
    }

    /** Polls the database and system metrics to update both internal frames. */
    private void refreshAllData() {
        String timestamp = timeFormat.format(new Date());

        // 1. Refresh Live Threat Feed
        List<Threat> threats = threatDAO.getAll();
        threatListModel.clear();

        if (threats.isEmpty()) {
            threatListModel.addElement("[" + timestamp + "] No security threats currently logged.");
        } else {
            // Display latest threats first (up to 15)
            int count = 0;
            for (int i = threats.size() - 1; i >= 0 && count < 15; i--) {
                Threat t = threats.get(i);
                String item = String.format("[%s] %s | %s (%s -> %s)",
                        timeFormat.format(t.getDetectedAt()),
                        t.getSeverity(),
                        t.getThreatType(),
                        t.getSourceIp(),
                        t.getTargetSystem());
                threatListModel.addElement(item);
                count++;
            }
        }
        feedStatusLabel.setText("Last updated: " + timestamp + " (" + threats.size() + " total threats logged)");

        // 2. Refresh System Health Metrics
        cpuTick++;
        int simulatedCpu = 25 + (int) (15 * Math.sin(cpuTick * 0.5)) + (cpuTick % 7);
        simulatedCpu = Math.max(10, Math.min(simulatedCpu, 95));
        cpuBar.setValue(simulatedCpu);
        cpuBar.setString(simulatedCpu + "% Load");

        // Real JVM Memory calculation
        Runtime rt = Runtime.getRuntime();
        long totalMem = rt.totalMemory() / (1024 * 1024);
        long freeMem = rt.freeMemory() / (1024 * 1024);
        long usedMem = totalMem - freeMem;
        int memPercent = (int) ((usedMem * 100.0) / totalMem);
        memoryBar.setValue(memPercent);
        memoryBar.setString(memPercent + "% Used");
        memDetailsLabel.setText(String.format("JVM Heap: %d MB used of %d MB allocated", usedMem, totalMem));

        // Blocked IPs volume
        int blockedCount = blockedIPDAO.getAll().size();
        ipBar.setValue(Math.min(blockedCount, ipBar.getMaximum()));
        ipBar.setString(blockedCount + " Active IP Blocks");

        // Unresolved Incidents
        List<Incident> openIncidents = incidentDAO.getByStatus("OPEN");
        incidentBar.setValue(Math.min(openIncidents.size(), incidentBar.getMaximum()));
        incidentBar.setString(openIncidents.size() + " Open Incidents");
    }

    /** Cleanly releases timer resources when this frame is disposed. */
    @Override
    public void dispose() {
        if (pollingTimer != null && pollingTimer.isRunning()) {
            pollingTimer.stop();
        }
        super.dispose();
    }
}
