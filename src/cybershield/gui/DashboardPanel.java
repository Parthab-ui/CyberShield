package cybershield.gui;

import cybershield.dao.LogDAO;
import cybershield.dao.StatsDAO;
import cybershield.model.LogEntry;
import cybershield.util.AppSettings;
import cybershield.util.Theme;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSlider;
import javax.swing.JSpinner;
import javax.swing.JTextArea;
import javax.swing.JToggleButton;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingConstants;
import javax.swing.Timer;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

/**
 * DashboardPanel — The main dashboard screen shown after login.
 * Displays live statistics fetched from the database via StatsDAO and LogDAO.
 * Replaces the placeholder DashboardPanel from the foundation.
 * Demonstrates: JProgressBar, JSlider, JSpinner, JToggleButton, Timer, custom graph.
 */
public class DashboardPanel extends BasePanel {

    // DAO objects used to load data
    private StatsDAO statsDAO;
    private LogDAO   logDAO;

    // ---- Stat card labels (top row) ----
    private JLabel totalThreatsValue;
    private JLabel openIncidentsValue;
    private JLabel blockedIPsValue;
    private JLabel criticalThreatsValue;

    // ---- Bar chart ----
    private ThreatGraphPanel threatGraph;

    // ---- Progress bars ----
    private JProgressBar resolvedThreatsBar;
    private JProgressBar closedIncidentsBar;
    private JProgressBar securityScoreBar;

    // ---- Slider, spinner, toggle ----
    private JSlider    sensitivitySlider;
    private JLabel     sensitivityValueLabel;
    private JSpinner   refreshSpinner;
    private JToggleButton liveModeButton;

    // ---- Log list ----
    private DefaultListModel<String> logListModel;
    private JList<String>            logList;

    // ---- Summary text area ----
    private JTextArea summaryArea;

    // ---- Auto-refresh timer ----
    private Timer autoRefreshTimer;

    // Constructor — builds the entire dashboard layout
    public DashboardPanel() {
        statsDAO = new StatsDAO();
        logDAO   = new LogDAO();

        setBackground(Theme.BACKGROUND);
        setLayout(new BorderLayout(8, 8));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        add(createStatCardsPanel(),   BorderLayout.NORTH);
        add(createCentrePanel(),      BorderLayout.CENTER);
        add(createControlsPanel(),    BorderLayout.SOUTH);

        // Load real data for the first time
        refreshData();
    }

    // ================================================================
    // PANEL BUILDERS
    // ================================================================

    /** Creates the top row of four stat cards. */
    private JPanel createStatCardsPanel() {
        JPanel panel = new JPanel(new GridLayout(1, 4, 8, 0));
        panel.setBackground(Theme.BACKGROUND);

        totalThreatsValue   = new JLabel("0", SwingConstants.CENTER);
        openIncidentsValue  = new JLabel("0", SwingConstants.CENTER);
        blockedIPsValue     = new JLabel("0", SwingConstants.CENTER);
        criticalThreatsValue = new JLabel("0", SwingConstants.CENTER);

        panel.add(createStatCard("Total Threats",    totalThreatsValue,    Theme.ACCENT));
        panel.add(createStatCard("Open Incidents",   openIncidentsValue,   Theme.WARNING));
        panel.add(createStatCard("Blocked IPs",      blockedIPsValue,      Theme.SUCCESS));
        panel.add(createStatCard("Critical Threats", criticalThreatsValue, Theme.CRITICAL));

        return panel;
    }

    /** Builds a single coloured stat card with a title and a large value label. */
    private JPanel createStatCard(String title, JLabel valueLabel, Color accentColor) {
        JPanel card = new JPanel(new BorderLayout());
        card.setBackground(Theme.PANEL_BG);
        card.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(accentColor, 1),
            BorderFactory.createEmptyBorder(10, 10, 10, 10)
        ));

        JLabel titleLabel = new JLabel(title, SwingConstants.CENTER);
        titleLabel.setFont(Theme.FONT_SMALL);
        titleLabel.setForeground(Theme.TEXT_SECONDARY);

        valueLabel.setFont(new Font("Segoe UI", Font.BOLD, 32));
        valueLabel.setForeground(accentColor);

        card.add(titleLabel,  BorderLayout.NORTH);
        card.add(valueLabel,  BorderLayout.CENTER);
        return card;
    }

    /** Creates the centre section: bar chart on the left, progress + log on the right. */
    private JPanel createCentrePanel() {
        JPanel centre = new JPanel(new GridLayout(1, 2, 8, 0));
        centre.setBackground(Theme.BACKGROUND);

        centre.add(createGraphPanel());
        centre.add(createRightPanel());

        return centre;
    }

    /** Wraps ThreatGraphPanel in a titled border. */
    private JPanel createGraphPanel() {
        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.setBackground(Theme.PANEL_BG);
        wrapper.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Theme.ACCENT, 1),
            BorderFactory.createEmptyBorder(8, 8, 8, 8)
        ));

        JLabel title = new JLabel("Threat Severity Distribution");
        title.setFont(Theme.FONT_HEADING);
        title.setForeground(Theme.ACCENT);

        threatGraph = new ThreatGraphPanel();
        threatGraph.setPreferredSize(new Dimension(0, 200));

        wrapper.add(title,       BorderLayout.NORTH);
        wrapper.add(threatGraph, BorderLayout.CENTER);
        return wrapper;
    }

    /** Creates the right half: progress bars, recent logs, and summary text. */
    private JPanel createRightPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 8));
        panel.setBackground(Theme.BACKGROUND);

        panel.add(createProgressPanel(), BorderLayout.NORTH);
        panel.add(createLogPanel(),      BorderLayout.CENTER);
        panel.add(createSummaryPanel(),  BorderLayout.SOUTH);

        return panel;
    }

    /** Creates three progress bars for resolved threats, closed incidents, security score. */
    private JPanel createProgressPanel() {
        JPanel panel = new JPanel(new GridLayout(3, 1, 0, 6));
        panel.setBackground(Theme.PANEL_BG);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Theme.ACCENT, 1),
            BorderFactory.createEmptyBorder(8, 8, 8, 8)
        ));

        resolvedThreatsBar = makeProgressBar(Theme.SUCCESS);
        closedIncidentsBar = makeProgressBar(Theme.ACCENT);
        securityScoreBar   = makeProgressBar(Theme.WARNING);

        panel.add(labeledBar("Resolved Threats %",  resolvedThreatsBar));
        panel.add(labeledBar("Closed Incidents %",  closedIncidentsBar));
        panel.add(labeledBar("Security Score",       securityScoreBar));

        return panel;
    }

    /** Creates a single JProgressBar with the given colour and string painting on. */
    private JProgressBar makeProgressBar(Color color) {
        JProgressBar bar = new JProgressBar(0, 100);
        bar.setStringPainted(true);
        bar.setForeground(color);
        bar.setBackground(Theme.BACKGROUND);
        bar.setFont(Theme.FONT_SMALL);
        return bar;
    }

    /** Combines a text label and a progress bar in a single row panel. */
    private JPanel labeledBar(String text, JProgressBar bar) {
        JPanel row = new JPanel(new BorderLayout(6, 0));
        row.setBackground(Theme.PANEL_BG);

        JLabel lbl = new JLabel(text);
        lbl.setFont(Theme.FONT_SMALL);
        lbl.setForeground(Theme.TEXT_SECONDARY);
        lbl.setPreferredSize(new Dimension(140, 20));

        row.add(lbl, BorderLayout.WEST);
        row.add(bar, BorderLayout.CENTER);
        return row;
    }

    /** Creates a scrollable list showing the 10 most recent log entries. */
    private JScrollPane createLogPanel() {
        logListModel = new DefaultListModel<>();
        logList = new JList<>(logListModel);
        logList.setBackground(Theme.PANEL_BG);
        logList.setForeground(Theme.TEXT_PRIMARY);
        logList.setFont(Theme.FONT_SMALL);
        logList.setSelectionBackground(Theme.ACCENT);

        JScrollPane scroll = new JScrollPane(logList);
        scroll.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Theme.ACCENT, 1),
            BorderFactory.createEmptyBorder(4, 4, 4, 4)
        ));
        scroll.setBackground(Theme.PANEL_BG);

        JLabel title = new JLabel("Recent Activity");
        title.setFont(Theme.FONT_SMALL);
        title.setForeground(Theme.TEXT_SECONDARY);
        scroll.setColumnHeaderView(title);

        return scroll;
    }

    /** Creates a read-only text area showing a brief summary sentence. */
    private JScrollPane createSummaryPanel() {
        summaryArea = new JTextArea(2, 20);
        summaryArea.setEditable(false);
        summaryArea.setLineWrap(true);
        summaryArea.setWrapStyleWord(true);
        summaryArea.setBackground(Theme.PANEL_BG);
        summaryArea.setForeground(Theme.TEXT_SECONDARY);
        summaryArea.setFont(Theme.FONT_SMALL);
        summaryArea.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        JScrollPane scroll = new JScrollPane(summaryArea);
        scroll.setBorder(BorderFactory.createLineBorder(Theme.ACCENT, 1));
        return scroll;
    }

    /**
     * Creates the bottom controls row: slider, spinner, live-mode toggle, refresh button.
     */
    private JPanel createControlsPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 4));
        panel.setBackground(Theme.PANEL_BG);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Theme.ACCENT, 1),
            BorderFactory.createEmptyBorder(4, 8, 4, 8)
        ));

        // ---- Alert Sensitivity Slider ----
        JLabel sliderLabel = new JLabel("Alert Sensitivity:");
        sliderLabel.setForeground(Theme.TEXT_SECONDARY);
        sliderLabel.setFont(Theme.FONT_SMALL);

        sensitivitySlider = new JSlider(1, 10, AppSettings.getAlertSensitivity());
        sensitivitySlider.setMajorTickSpacing(3);
        sensitivitySlider.setMinorTickSpacing(1);
        sensitivitySlider.setPaintTicks(true);
        sensitivitySlider.setPaintLabels(true);
        sensitivitySlider.setBackground(Theme.PANEL_BG);
        sensitivitySlider.setForeground(Theme.TEXT_SECONDARY);
        sensitivitySlider.setPreferredSize(new Dimension(160, 50));
        sensitivitySlider.setToolTipText("Drag to set alert sensitivity (1=low, 10=high)");

        sensitivityValueLabel = new JLabel("Level: " + AppSettings.getAlertSensitivity());
        sensitivityValueLabel.setForeground(Theme.ACCENT);
        sensitivityValueLabel.setFont(Theme.FONT_SMALL);

        // Event listener: triggered every time the slider value changes (ChangeListener)
        sensitivitySlider.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent e) {
                int val = sensitivitySlider.getValue();
                sensitivityValueLabel.setText("Level: " + val);
                AppSettings.setAlertSensitivity(val);
            }
        });

        // ---- Auto-Refresh Spinner ----
        JLabel spinnerLabel = new JLabel("Auto-refresh (sec):");
        spinnerLabel.setForeground(Theme.TEXT_SECONDARY);
        spinnerLabel.setFont(Theme.FONT_SMALL);

        // SpinnerNumberModel(initial, min, max, step)
        refreshSpinner = new JSpinner(new SpinnerNumberModel(
            AppSettings.getRefreshIntervalSeconds(), 5, 60, 5
        ));
        refreshSpinner.setPreferredSize(new Dimension(65, 26));
        refreshSpinner.setToolTipText("Set the auto-refresh interval in seconds (5-60)");
        // Style the spinner's text field
        ((JSpinner.DefaultEditor) refreshSpinner.getEditor()).getTextField()
            .setBackground(Theme.PANEL_BG);
        ((JSpinner.DefaultEditor) refreshSpinner.getEditor()).getTextField()
            .setForeground(Theme.TEXT_PRIMARY);

        // Event listener: triggered when the spinner value changes
        refreshSpinner.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent e) {
                int seconds = (Integer) refreshSpinner.getValue();
                AppSettings.setRefreshIntervalSeconds(seconds);
                // If Live Mode is active, restart the timer with the new interval
                if (liveModeButton.isSelected()) {
                    restartAutoRefreshTimer(seconds);
                }
            }
        });

        // ---- Live Mode Toggle Button ----
        liveModeButton = new JToggleButton("Live Mode: OFF");
        liveModeButton.setFont(Theme.FONT_BODY);
        liveModeButton.setFocusPainted(false);
        liveModeButton.setBorderPainted(false);
        liveModeButton.setOpaque(true);
        liveModeButton.setBackground(Theme.PANEL_BG);
        liveModeButton.setForeground(Theme.TEXT_SECONDARY);
        liveModeButton.setToolTipText("Toggle automatic data refresh on/off");

        // Event listener: triggered when the toggle button is clicked (selected/deselected)
        liveModeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (liveModeButton.isSelected()) {
                    // Start the timer
                    int seconds = (Integer) refreshSpinner.getValue();
                    restartAutoRefreshTimer(seconds);
                    liveModeButton.setText("Live Mode: ON");
                    liveModeButton.setBackground(Theme.SUCCESS);
                    liveModeButton.setForeground(Color.BLACK);
                } else {
                    // Stop the timer
                    if (autoRefreshTimer != null) {
                        autoRefreshTimer.stop();
                    }
                    liveModeButton.setText("Live Mode: OFF");
                    liveModeButton.setBackground(Theme.PANEL_BG);
                    liveModeButton.setForeground(Theme.TEXT_SECONDARY);
                }
            }
        });

        // ---- Refresh Now Button ----
        JButton refreshNowButton = new JButton("⟳ Refresh Now");
        Theme.styleButton(refreshNowButton);
        refreshNowButton.setToolTipText("Reload all dashboard data from the database immediately");

        // Event listener: triggered when the Refresh Now button is clicked
        refreshNowButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                refreshData();
            }
        });

        // Add all controls to the panel in order
        panel.add(sliderLabel);
        panel.add(sensitivitySlider);
        panel.add(sensitivityValueLabel);
        panel.add(spinnerLabel);
        panel.add(refreshSpinner);
        panel.add(liveModeButton);
        panel.add(refreshNowButton);

        return panel;
    }

    // ================================================================
    // TIMER HELPER
    // ================================================================

    /**
     * Stops any existing timer and starts a new one with the given interval.
     * javax.swing.Timer fires on the EDT, so it is safe to call refreshData() from it.
     */
    private void restartAutoRefreshTimer(int seconds) {
        if (autoRefreshTimer != null && autoRefreshTimer.isRunning()) {
            autoRefreshTimer.stop();
        }
        int milliseconds = seconds * 1000;
        // Event listener: triggered every time the Timer fires (auto-refresh tick)
        autoRefreshTimer = new Timer(milliseconds, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                refreshData();
            }
        });
        autoRefreshTimer.start();
    }

    // ================================================================
    // REFRESH DATA  (implements BasePanel contract)
    // ================================================================

    /**
     * Reloads all statistics and log entries from the database and updates every widget.
     * Called at startup, on manual refresh, and by the auto-refresh timer.
     */
    @Override
    public void refreshData() {
        // ---- Load counts from database ----
        int totalThreats    = statsDAO.countThreats();
        int criticalThreats = statsDAO.countThreatsBySeverity("CRITICAL");
        int openIncidents   = statsDAO.countOpenIncidents();
        int blockedIPs      = statsDAO.countBlockedIPs();
        int resolvedThreats = statsDAO.countResolvedThreats();
        int closedIncidents = statsDAO.countClosedIncidents();
        int totalIncidents  = statsDAO.countTotalIncidents();

        // ---- Update stat cards ----
        totalThreatsValue.setText(String.valueOf(totalThreats));
        criticalThreatsValue.setText(String.valueOf(criticalThreats));
        openIncidentsValue.setText(String.valueOf(openIncidents));
        blockedIPsValue.setText(String.valueOf(blockedIPs));

        // ---- Update progress bars ----
        int resolvedPct = totalThreats > 0
            ? (resolvedThreats * 100) / totalThreats : 0;
        resolvedThreatsBar.setValue(resolvedPct);
        resolvedThreatsBar.setString(resolvedPct + "%  (" + resolvedThreats + "/" + totalThreats + ")");

        int closedPct = totalIncidents > 0
            ? (closedIncidents * 100) / totalIncidents : 0;
        closedIncidentsBar.setValue(closedPct);
        closedIncidentsBar.setString(closedPct + "%  (" + closedIncidents + "/" + totalIncidents + ")");

        // Security score: 100 - (critical threats * 10), minimum 0, maximum 100
        int securityScore = Math.max(0, Math.min(100, 100 - criticalThreats * 10));
        securityScoreBar.setValue(securityScore);
        securityScoreBar.setString(securityScore + " / 100");

        // ---- Update bar chart ----
        Map<String, Integer> severityMap = statsDAO.countThreatsBySeverityMap();
        threatGraph.setData(severityMap);

        // ---- Update log list ----
        logListModel.clear();
        List<LogEntry> logs = logDAO.getAll();
        int count = 0;
        for (LogEntry entry : logs) {
            if (count >= 10) break; // show only the 10 most recent
            logListModel.addElement("[" + entry.getLogTime() + "] " + entry.getAction());
            count++;
        }

        // ---- Update summary text ----
        summaryArea.setText(criticalThreats + " critical threat(s) detected, "
            + openIncidents + " incident(s) open, "
            + blockedIPs + " IP(s) currently blocked.");
    }
}
