package cybershield.ui;

import cybershield.model.AccessEvent;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import java.awt.*;
import java.util.List;

/**
 * AccessMonitoringPanel — Desktop intrusion and unauthorized access monitoring interface.
 * Demonstrates:
 * - JTable for real-time security telemetry and intrusion detection logs.
 * - Interactive threat simulation triggering database events.
 * - Custom TableCellRenderer highlighting blocked attempts vs allowed logins.
 * - User-friendly event counters and status indicators.
 */
public class AccessMonitoringPanel extends JPanel {

    private final ApiClient apiClient;

    private JTable eventTable;
    private DefaultTableModel tableModel;
    private JLabel eventCountLabel;
    private JButton simulateBtn;
    private JButton refreshBtn;

    public AccessMonitoringPanel() {
        this.apiClient = ApiClient.getInstance();
        setLayout(new BorderLayout(0, 14));
        setBackground(SwingTheme.PANEL_BG);
        setBorder(BorderFactory.createEmptyBorder(18, 20, 18, 20));

        initComponents();
        loadEvents();
    }

    /**
     * Initializes components, layout, table structure, and headers.
     */
    private void initComponents() {
        // TOP: Header title + Threat simulation action bar
        JPanel topContainer = new JPanel(new BorderLayout(0, 12));
        topContainer.setOpaque(false);

        // Header
        JPanel titlePanel = new JPanel(new BorderLayout());
        titlePanel.setOpaque(false);

        JLabel titleLabel = new JLabel("Unauthorized Access & Intrusion Telemetry");
        titleLabel.setFont(SwingTheme.FONT_TITLE);
        titleLabel.setForeground(SwingTheme.TEXT_PRIMARY);

        JLabel subtitleLabel = new JLabel("Monitors failed authentication, brute-force anomalies, and suspicious access attempts");
        subtitleLabel.setFont(SwingTheme.FONT_BODY);
        subtitleLabel.setForeground(SwingTheme.TEXT_MUTED);

        titlePanel.add(titleLabel, BorderLayout.NORTH);
        titlePanel.add(subtitleLabel, BorderLayout.SOUTH);
        topContainer.add(titlePanel, BorderLayout.NORTH);

        // Action bar (FlowLayout)
        JPanel actionBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        actionBar.setOpaque(false);

        simulateBtn = new JButton("Simulate Single Probe");
        simulateBtn.setBackground(SwingTheme.SEVERITY_MEDIUM);
        simulateBtn.setForeground(Color.BLACK);
        simulateBtn.setFont(SwingTheme.FONT_BOLD);
        simulateBtn.setFocusPainted(false);
        simulateBtn.setBorder(BorderFactory.createEmptyBorder(7, 14, 7, 14));
        simulateBtn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        simulateBtn.setToolTipText("Simulates a single unauthorized intrusion attempt");
        simulateBtn.addActionListener(e -> triggerSimulatedThreat());

        JButton simulateBruteBtn = new JButton("🚨 Simulate Brute-Force (5 Failures)");
        simulateBruteBtn.setBackground(SwingTheme.SEVERITY_CRITICAL);
        simulateBruteBtn.setForeground(Color.WHITE);
        simulateBruteBtn.setFont(SwingTheme.FONT_BOLD);
        simulateBruteBtn.setFocusPainted(false);
        simulateBruteBtn.setBorder(BorderFactory.createEmptyBorder(7, 14, 7, 14));
        simulateBruteBtn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        simulateBruteBtn.setToolTipText("Simulates 5 failed logins within 2 minutes from 192.168.1.105 triggering automated incident generation");
        simulateBruteBtn.addActionListener(e -> triggerSimulatedBruteForce());

        refreshBtn = new JButton("Refresh Events");
        SwingTheme.styleSecondaryButton(refreshBtn);
        refreshBtn.addActionListener(e -> loadEvents());

        eventCountLabel = new JLabel("Showing 0 security events");
        eventCountLabel.setFont(SwingTheme.FONT_BODY);
        eventCountLabel.setForeground(SwingTheme.TEXT_MUTED);
        eventCountLabel.setBorder(BorderFactory.createEmptyBorder(0, 15, 0, 0));

        actionBar.add(simulateBtn);
        actionBar.add(simulateBruteBtn);
        actionBar.add(refreshBtn);
        actionBar.add(eventCountLabel);

        topContainer.add(actionBar, BorderLayout.SOUTH);
        add(topContainer, BorderLayout.NORTH);

        // CENTER: JTable inside JScrollPane
        String[] columnNames = {"ID", "Target / Attempted User", "Source Identifier", "Event Category", "Outcome / Reason", "Logged At"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int col) {
                return false;
            }
        };

        eventTable = new JTable(tableModel);
        eventTable.setBackground(SwingTheme.CARD_BG);
        eventTable.setForeground(SwingTheme.TEXT_PRIMARY);
        eventTable.setSelectionBackground(SwingTheme.PRIMARY_COLOR);
        eventTable.setSelectionForeground(Color.WHITE);
        eventTable.setRowHeight(30);
        eventTable.setFont(SwingTheme.FONT_BODY);
        eventTable.setShowGrid(true);
        eventTable.setGridColor(SwingTheme.BORDER_COLOR);
        eventTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // Column widths
        eventTable.getColumnModel().getColumn(0).setPreferredWidth(50);
        eventTable.getColumnModel().getColumn(1).setPreferredWidth(170);
        eventTable.getColumnModel().getColumn(2).setPreferredWidth(160);
        eventTable.getColumnModel().getColumn(3).setPreferredWidth(150);
        eventTable.getColumnModel().getColumn(4).setPreferredWidth(180);
        eventTable.getColumnModel().getColumn(5).setPreferredWidth(160);

        // Center alignment
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(SwingConstants.CENTER);
        eventTable.getColumnModel().getColumn(0).setCellRenderer(centerRenderer);
        eventTable.getColumnModel().getColumn(2).setCellRenderer(centerRenderer);
        eventTable.getColumnModel().getColumn(3).setCellRenderer(centerRenderer);
        eventTable.getColumnModel().getColumn(5).setCellRenderer(centerRenderer);

        // Custom renderer for Outcome / Result column (color coding)
        eventTable.getColumnModel().getColumn(4).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
                setHorizontalAlignment(SwingConstants.CENTER);
                setFont(SwingTheme.FONT_BOLD);
                String val = value != null ? value.toString().toUpperCase() : "";
                if (!isSelected) {
                    c.setBackground(SwingTheme.CARD_BG);
                    if (val.contains("SUCCESS") || val.contains("ALLOWED")) {
                        c.setForeground(SwingTheme.STATUS_RESOLVED);
                    } else if (val.contains("BLOCKED") || val.contains("FAILED") || val.contains("INVALID")) {
                        c.setForeground(SwingTheme.SEVERITY_CRITICAL);
                    } else {
                        c.setForeground(SwingTheme.SEVERITY_MEDIUM);
                    }
                }
                return c;
            }
        });

        // Header style
        JTableHeader header = eventTable.getTableHeader();
        header.setBackground(SwingTheme.BG_COLOR);
        header.setForeground(SwingTheme.TEXT_PRIMARY);
        header.setFont(SwingTheme.FONT_BOLD);
        header.setBorder(BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR));

        JScrollPane scrollPane = new JScrollPane(eventTable);
        scrollPane.setBorder(BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR));
        scrollPane.getViewport().setBackground(SwingTheme.CARD_BG);
        add(scrollPane, BorderLayout.CENTER);
    }

    /**
     * Loads access monitoring events from database and updates table rows.
     */
    public void loadEvents() {
        List<AccessEvent> events = apiClient.getAccessEvents(50);
        tableModel.setRowCount(0);

        for (AccessEvent ev : events) {
            tableModel.addRow(new Object[]{
                ev.getId(),
                ev.getAttemptedUsername(),
                ev.getSource(),
                ev.getEventType(),
                ev.getResult(),
                ev.getCreatedAt()
            });
        }

        eventCountLabel.setText("Showing " + events.size() + " security events (persisted in SQLite database)");
    }

    /**
     * Injects a simulated brute-force threat event into the database and refreshes the view.
     */
    private void triggerSimulatedThreat() {
        AccessEvent simulated = apiClient.simulateThreat();
        JOptionPane.showMessageDialog(this,
            "Simulated Threat Event Generated!\n\n" +
            "Source: " + simulated.getSource() + "\n" +
            "Target: " + simulated.getAttemptedUsername() + "\n" +
            "Type: " + simulated.getEventType() + "\n" +
            "Result: " + simulated.getResult() + "\n\n" +
            "This event was persisted to SQLite and is immediately visible on both Web and Desktop interfaces.",
            "Security Alert Triggered", JOptionPane.WARNING_MESSAGE);
        loadEvents();
    }

    /**
     * Injects a 5-failure brute-force attack from a simulated IP to trigger the IDS engine.
     */
    private void triggerSimulatedBruteForce() {
        var alert = apiClient.simulateBruteForceAttack("192.168.1.105");
        loadEvents();
        if (alert != null) {
            JOptionPane.showMessageDialog(this,
                "Automated Intrusion Detection Triggered!\n\n" +
                "• Attack Classification: " + alert.getAlertType() + "\n" +
                "• Source IP: " + alert.getSourceIp() + "\n" +
                "• Failed Login Attempts: " + alert.getFailedAttempts() + "\n" +
                "• Incident Generated: #" + alert.getIncidentId() + " (Severity: " + alert.getSeverity() + ")\n" +
                "• Investigation Status: " + alert.getStatus() + "\n" +
                "• Cooldown Active: 10 Minutes\n\n" +
                "The incident is now permanently stored in SQLite and visible across all interfaces.",
                "🚨 Brute-Force Attack Detected", JOptionPane.WARNING_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(this,
                "5 Failed login attempts recorded from 192.168.1.105.\n" +
                "Note: Cooldown is currently active for this IP to prevent duplicate incident spam.",
                "Simulation Completed (In Cooldown)", JOptionPane.INFORMATION_MESSAGE);
        }
    }
}
