package com.cybershield.ui.panels;

import com.cybershield.exception.DatabaseOperationException;
import com.cybershield.model.Incident;
import com.cybershield.model.ResponseAction;
import com.cybershield.model.Threat;
import com.cybershield.model.enums.IncidentStatus;
import com.cybershield.model.enums.Severity;
import com.cybershield.model.enums.ThreatType;
import com.cybershield.repository.DatabaseManager;
import com.cybershield.repository.IncidentRepository;
import com.cybershield.repository.ResponseActionRepository;
import com.cybershield.repository.ThreatRepository;
import com.cybershield.ui.CyberTheme;
import com.cybershield.ui.components.CyberTable;
import com.cybershield.ui.components.StyledButton;
import com.cybershield.util.DateTimeUtils;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.table.DefaultTableModel;

/**
 * Analytics Panel showing threat breakdowns, mitigation metrics, and response action audit logs.
 * Demonstrates:
 * - Swing components: JTabbedPane, JProgressBar, JTable, JScrollPane, JTextArea.
 */
public class AnalyticsPanel extends JPanel {

    private final ThreatRepository threatRepository;
    private final IncidentRepository incidentRepository;
    private final ResponseActionRepository responseActionRepository;

    private final JPanel pnlTypeStats;
    private final JPanel pnlSeverityStats;
    private final JPanel pnlIncidentStats;
    private final DefaultTableModel auditTableModel;
    private final CyberTable auditTable;

    public AnalyticsPanel() {
        DatabaseManager db = DatabaseManager.getInstance();
        this.threatRepository = new ThreatRepository(db);
        this.responseActionRepository = new ResponseActionRepository(db);
        this.incidentRepository = new IncidentRepository(db, threatRepository, responseActionRepository);

        setLayout(new BorderLayout(10, 10));
        setBackground(CyberTheme.BG_DARK);
        setBorder(BorderFactory.createEmptyBorder(14, 14, 14, 14));

        // Header
        JPanel topBar = new JPanel(new BorderLayout(8, 8));
        topBar.setOpaque(false);

        JLabel lblTitle = new JLabel("📈 SECURITY ANALYTICS & AUDIT TRAIL");
        lblTitle.setFont(CyberTheme.FONT_TITLE);
        lblTitle.setForeground(CyberTheme.TEXT_PRIMARY);

        StyledButton btnRefresh = new StyledButton("Refresh Metrics", StyledButton.ButtonStyle.SECONDARY);
        btnRefresh.addActionListener(e -> refreshData());

        topBar.add(lblTitle, BorderLayout.WEST);
        topBar.add(btnRefresh, BorderLayout.EAST);
        add(topBar, BorderLayout.NORTH);

        // JTabbedPane for Analytics views
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setBackground(CyberTheme.BG_DARK);
        tabbedPane.setForeground(CyberTheme.TEXT_PRIMARY);
        tabbedPane.setFont(CyberTheme.FONT_BODY_BOLD);

        // Tab 1: Visual Metrics & Progress Bars
        JPanel pnlMetricsTab = new JPanel(new BorderLayout(10, 10));
        pnlMetricsTab.setOpaque(false);

        JPanel metricsContainer = new JPanel(new GridLayout(1, 3, 12, 12));
        metricsContainer.setOpaque(false);
        metricsContainer.setPreferredSize(new Dimension(800, 180));

        pnlTypeStats = createCardPanel("THREATS BY CATEGORY");
        pnlSeverityStats = createCardPanel("THREATS BY SEVERITY");
        pnlIncidentStats = createCardPanel("INCIDENTS BY STATUS");

        metricsContainer.add(pnlTypeStats);
        metricsContainer.add(pnlSeverityStats);
        metricsContainer.add(pnlIncidentStats);
        pnlMetricsTab.add(metricsContainer, BorderLayout.NORTH);

        // Bottom Table: Response Actions Audit Log
        String[] auditCols = {"Action ID", "Incident ID", "Action Dispatched", "Target Entity", "Operator", "Status", "Timestamp"};
        auditTableModel = new DefaultTableModel(auditCols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        auditTable = new CyberTable(auditTableModel);
        JScrollPane auditScroll = CyberTable.wrapInScrollPane(auditTable);
        auditScroll.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                " Incident Response Containment Audit Trail ", 0, 0, CyberTheme.FONT_BODY_BOLD, CyberTheme.ACCENT_CYAN
        ));
        pnlMetricsTab.add(auditScroll, BorderLayout.CENTER);

        tabbedPane.addTab("📊 Visual Progress Metrics & Audit Table", pnlMetricsTab);

        // Tab 2: Java Swing Components Catalog Tab
        tabbedPane.addTab("📋 Swing Components Catalog (Review 1 Checklist)", createComponentsCatalogTab());

        // Tab 3: Code Viva Q&A Guide Tab
        tabbedPane.addTab("💡 Code Viva Defense Cheat Sheet", createVivaGuideTab());

        add(tabbedPane, BorderLayout.CENTER);
        refreshData();
    }

    private JPanel createCardPanel(String title) {
        JPanel card = new JPanel(new BorderLayout(6, 6));
        card.setBackground(CyberTheme.BG_CARD);
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                BorderFactory.createEmptyBorder(10, 12, 10, 12)
        ));

        JLabel lbl = new JLabel(title);
        lbl.setFont(CyberTheme.FONT_HEADER);
        lbl.setForeground(CyberTheme.ACCENT_CYAN);
        card.add(lbl, BorderLayout.NORTH);

        JPanel content = new JPanel();
        content.setLayout(new GridLayout(4, 1, 4, 4));
        content.setOpaque(false);
        card.add(content, BorderLayout.CENTER);

        return card;
    }

    private JPanel createComponentsCatalogTab() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBackground(CyberTheme.BG_DARK);
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        String[] headers = {"#", "Swing Component", "Category", "Demonstrated In", "Event Listener / Feature"};
        Object[][] data = {
            {"1", "JFrame", "Top-level Window", "MainDashboardFrame", "BorderLayout, minimum size, window title"},
            {"2", "JDialog", "Dialog Window", "LoginDialog, ProjectTeamDialog", "Modal blocking, parent centering"},
            {"3", "JPanel", "Containers", "All UI views", "FlowLayout, BorderLayout, GridLayout, CardLayout"},
            {"4", "JLabel", "Text & Metrics", "MetricCard, Headers, Status", "Dynamic counters, HTML formatting"},
            {"5", "JButton", "Action Controls", "StyledButton, Panels", "ActionListener, custom glow hover effect"},
            {"6", "JToggleButton", "Toggle Controls", "MainDashboardFrame Toolbar", "Real-time Telemetry Live Stream toggle"},
            {"7", "JCheckBox", "Selection Controls", "AttackSimulatorPanel, Telemetry", "ItemListener / ActionListener"},
            {"8", "JRadioButton", "Radio Selection", "ThreatMonitorPanel, Simulator", "ButtonGroup mutual exclusion"},
            {"9", "ButtonGroup", "Logical Grouping", "ThreatMonitorPanel, Simulator", "Single selection enforcement"},
            {"10", "JComboBox", "Dropdown List", "TelemetryPanel, UsersPanel", "Item selection filtering"},
            {"11", "JTextField", "Text Input", "TelemetryPanel, LoginDialog", "Search queries, IP input"},
            {"12", "JPasswordField", "Masked Input", "LoginDialog, UsersPanel", "SHA-256 password security"},
            {"13", "JTextArea", "Multi-line Text", "TelemetryPanel, SimulatorPanel", "Monospace logs, packet inspection"},
            {"14", "JTextPane", "Rich HTML Text", "ThreatMonitorPanel", "Polymorphic threat dossier renderer"},
            {"15", "JTable", "Tabular Data", "CyberTable (All Panels)", "DefaultTableModel, column cell renderers"},
            {"16", "JScrollPane", "Scrolling Panes", "CyberTable, Trees, Text Areas", "Themed dark scrollbars"},
            {"17", "JSplitPane", "Master-Detail", "ThreatMonitorPanel, IncidentConsole", "Horizontal & Vertical resizable dividers"},
            {"18", "JTabbedPane", "Tabbed Interface", "AnalyticsPanel, Threats, TeamDialog", "Multi-tab organized navigation"},
            {"19", "JProgressBar", "Progress Meters", "AnalyticsPanel, SimulatorPanel", "Real-time thread animation 0-100%"},
            {"20", "JSlider", "Continuous Slider", "ThreatMonitorPanel, SimulatorPanel", "ChangeListener for sensitivity & delay"},
            {"21", "JSpinner", "Numeric Spinner", "TelemetryPanel, Toolbar", "SpinnerNumberModel for refresh & limits"},
            {"22", "JList", "List View", "BlockedIpsListPanel", "DefaultListModel with add/remove rules"},
            {"23", "JTree", "Hierarchical Tree", "MitreAssetTreePanel", "DefaultMutableTreeNode & TreeSelectionListener"},
            {"24", "JMenuBar", "Application Menu", "MainDashboardFrame", "Top desktop navigation menu"},
            {"25", "JMenu", "Menu Items", "MainDashboardFrame", "File, View, Simulation, Tools, Review menus"},
            {"26", "JMenuItem", "Menu Actions", "MainDashboardFrame", "Export, dialog triggers, refresh actions"},
            {"27", "JCheckBoxMenuItem", "Checkable Menu", "MainDashboardFrame", "Toggle high-contrast / auto-refresh"},
            {"28", "JRadioButtonMenuItem", "Radio Menu", "MainDashboardFrame", "Simulation profiles selector"},
            {"29", "JPopupMenu", "Context Menu", "CyberTable, Threats, Telemetry", "MouseAdapter right-click popup"},
            {"30", "JToolBar", "Quick Toolbar", "MainDashboardFrame", "Floating / docked quick action toolbar"},
            {"31", "JFileChooser", "File Dialog", "TelemetryPanel, MainDashboardFrame", "Export reports directly to .csv file"},
            {"32", "JColorChooser", "Color Palette", "MainDashboardFrame", "Live SOC accent color customizer"},
            {"33", "JSeparator", "Dividers", "Toolbars, Menus, Panels", "Horizontal & Vertical layout separation"},
            {"34", "JToolTip", "Help Tooltips", "Across all interactive buttons", "Hover guidance for examiner"},
            {"35", "JOptionPane", "Popups", "Controllers & Panels", "Confirmation, Warning, Input, and Message dialogs"}
        };

        DefaultTableModel compModel = new DefaultTableModel(data, headers) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        CyberTable compTable = new CyberTable(compModel);
        compTable.getColumnModel().getColumn(0).setPreferredWidth(35);
        compTable.getColumnModel().getColumn(1).setPreferredWidth(120);
        compTable.getColumnModel().getColumn(2).setPreferredWidth(130);
        compTable.getColumnModel().getColumn(3).setPreferredWidth(220);
        compTable.getColumnModel().getColumn(4).setPreferredWidth(280);

        JScrollPane scroll = CyberTable.wrapInScrollPane(compTable);
        panel.add(scroll, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createVivaGuideTab() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBackground(CyberTheme.BG_DARK);
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JTextArea txtViva = new JTextArea();
        txtViva.setEditable(false);
        txtViva.setFont(CyberTheme.FONT_MONO);
        txtViva.setBackground(CyberTheme.BG_CARD);
        txtViva.setForeground(CyberTheme.TEXT_PRIMARY);
        txtViva.setText(
            "========================================================================================\n" +
            "   CYBERSHIELD — FIRST REVIEW (OCT 1ST) CODE VIVA DEFENSE CHEAT SHEET\n" +
            "========================================================================================\n\n" +
            "Q1: 'Which Java Swing components did you use and where are they in your code?'\n" +
            "Answer:\n" +
            "- We incorporated 35 distinct Java Swing components across our front-end architecture:\n" +
            "  * Windows & Containers: JFrame (MainDashboardFrame), JDialog (LoginDialog, ProjectTeamDialog), JPanel.\n" +
            "  * Navigation & Menus: JMenuBar, JMenu, JMenuItem, JCheckBoxMenuItem, JRadioButtonMenuItem, JToolBar.\n" +
            "  * Complex Controls: JTree (MitreAssetTreePanel), JList (BlockedIpsListPanel), JTable (CyberTable),\n" +
            "    JSplitPane (ThreatMonitorPanel & TelemetryPanel), JTabbedPane (AnalyticsPanel & Threats).\n" +
            "  * Inputs & Selectors: JComboBox, JSpinner, JSlider, JRadioButton + ButtonGroup, JCheckBox, JToggleButton.\n" +
            "  * Text Displays: JTextPane (HTML dossier), JTextArea (Payload & traces), JTextField, JPasswordField.\n" +
            "  * Progress & Visuals: JProgressBar (Threat progress & category bars), JSeparator, JToolTip.\n" +
            "  * Dialogs: JFileChooser (CSV export), JColorChooser (Theme color picker), JOptionPane.\n\n" +
            "----------------------------------------------------------------------------------------\n" +
            "Q2: 'How did you handle Event Dispatch Thread (EDT) and Thread Safety in Swing?'\n" +
            "Answer:\n" +
            "- Swing components are single-threaded and not thread-safe. Long tasks (such as attack simulations)\n" +
            "  run in background worker threads (new Thread(() -> ...).start()) to prevent freezing the GUI.\n" +
            "- All UI updates (such as updating JProgressBar or JTable) are dispatched back to the EDT using:\n" +
            "  javax.swing.SwingUtilities.invokeLater(() -> { ... });\n\n" +
            "----------------------------------------------------------------------------------------\n" +
            "Q3: 'How are AOOP principles demonstrated through your GUI and Engine?'\n" +
            "Answer:\n" +
            "- Abstraction: abstract class Threat defines contracts (evaluateSeverity, generateIncidentReport).\n" +
            "  interface ThreatDetector specifies detect() and canDetect().\n" +
            "- Inheritance: BruteForceThreat, PhishingThreat, MalwareThreat, SuspiciousLoginThreat extend Threat.\n" +
            "- Polymorphism: ThreatDetectionEngine loops over List<ThreatDetector> and polymorphically detects threats.\n" +
            "  When selected in JTable, threat.generateIncidentReport() polymorphically renders the specific dossier.\n" +
            "- Composition: Incident HAS-A Threat (associatedThreat) and HAS-MANY ResponseAction (List<ResponseAction>).\n" +
            "- Encapsulation: All model fields are private with validated getters/setters and unmodifiable collections.\n\n" +
            "----------------------------------------------------------------------------------------\n" +
            "Q4: 'How does your GUI connect to SQLite database?'\n" +
            "Answer:\n" +
            "- We use native JDBC with SQLite 3 (Xerial JDBC driver). DatabaseManager is a Singleton pattern.\n" +
            "- Repositories execute parameterized SQL queries via PreparedStatement to prevent SQL Injection.\n" +
            "- Automatic resource de-allocation via Java try-with-resources prevents connection or cursor leaks.\n" +
            "========================================================================================\n"
        );
        txtViva.setCaretPosition(0);

        panel.add(new JScrollPane(txtViva), BorderLayout.CENTER);
        return panel;
    }

    public void refreshData() {
        try {
            // Aggregate Threats
            List<Threat> threats = threatRepository.findAll();
            Map<ThreatType, Integer> typeCounts = new EnumMap<>(ThreatType.class);
            Map<Severity, Integer> sevCounts = new EnumMap<>(Severity.class);

            for (Threat t : threats) {
                typeCounts.put(t.getThreatType(), typeCounts.getOrDefault(t.getThreatType(), 0) + 1);
                sevCounts.put(t.getSeverity(), sevCounts.getOrDefault(t.getSeverity(), 0) + 1);
            }

            int totalThreats = Math.max(1, threats.size());

            // Populate Category Panel
            JPanel typeContent = (JPanel) ((BorderLayout) pnlTypeStats.getLayout()).getLayoutComponent(BorderLayout.CENTER);
            typeContent.removeAll();
            for (ThreatType tt : ThreatType.values()) {
                int count = typeCounts.getOrDefault(tt, 0);
                typeContent.add(createMetricBar(tt.name(), count, totalThreats, CyberTheme.ACCENT_BLUE));
            }
            pnlTypeStats.revalidate();
            pnlTypeStats.repaint();

            // Populate Severity Panel
            JPanel sevContent = (JPanel) ((BorderLayout) pnlSeverityStats.getLayout()).getLayoutComponent(BorderLayout.CENTER);
            sevContent.removeAll();
            for (Severity sv : Severity.values()) {
                int count = sevCounts.getOrDefault(sv, 0);
                Color c = switch (sv) {
                    case CRITICAL -> CyberTheme.STATUS_RED;
                    case HIGH -> new Color(255, 107, 107);
                    case MEDIUM -> CyberTheme.STATUS_AMBER;
                    case LOW -> CyberTheme.ACCENT_CYAN;
                };
                sevContent.add(createMetricBar(sv.name(), count, totalThreats, c));
            }
            pnlSeverityStats.revalidate();
            pnlSeverityStats.repaint();

            // Aggregate Incidents
            List<Incident> incidents = incidentRepository.findAll();
            int totalIncidents = Math.max(1, incidents.size());
            Map<IncidentStatus, Integer> statusCounts = new EnumMap<>(IncidentStatus.class);
            for (Incident inc : incidents) {
                statusCounts.put(inc.getStatus(), statusCounts.getOrDefault(inc.getStatus(), 0) + 1);
            }

            JPanel incContent = (JPanel) ((BorderLayout) pnlIncidentStats.getLayout()).getLayoutComponent(BorderLayout.CENTER);
            incContent.removeAll();
            for (IncidentStatus st : IncidentStatus.values()) {
                int count = statusCounts.getOrDefault(st, 0);
                Color c = switch (st) {
                    case OPEN -> CyberTheme.STATUS_RED;
                    case INVESTIGATING -> CyberTheme.STATUS_AMBER;
                    case RESOLVED -> CyberTheme.STATUS_GREEN;
                    case CLOSED -> CyberTheme.TEXT_MUTED;
                };
                incContent.add(createMetricBar(st.name(), count, totalIncidents, c));
            }
            pnlIncidentStats.revalidate();
            pnlIncidentStats.repaint();

            // Populate Audit Table
            List<ResponseAction> actions = responseActionRepository.findAll();
            auditTableModel.setRowCount(0);
            for (ResponseAction a : actions) {
                auditTableModel.addRow(new Object[]{
                    a.getActionId(),
                    a.getIncidentId(),
                    a.getActionType().getDisplayName(),
                    a.getTarget(),
                    a.getExecutedBy(),
                    a.getStatus(),
                    DateTimeUtils.format(a.getExecutedAt())
                });
            }

        } catch (DatabaseOperationException e) {
            JOptionPane.showMessageDialog(this, "Failed to refresh analytics: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private JPanel createMetricBar(String label, int value, int total, Color color) {
        JPanel barRow = new JPanel(new BorderLayout(6, 0));
        barRow.setOpaque(false);

        JLabel lbl = new JLabel(String.format("%-14s (%d)", label, value));
        lbl.setFont(CyberTheme.FONT_SMALL);
        lbl.setForeground(CyberTheme.TEXT_PRIMARY);
        lbl.setPreferredSize(new Dimension(130, 20));

        JProgressBar progress = new JProgressBar(0, total);
        progress.setValue(value);
        progress.setForeground(color);
        progress.setBackground(CyberTheme.BG_DARK);
        progress.setBorder(BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1));
        progress.setPreferredSize(new Dimension(100, 14));

        barRow.add(lbl, BorderLayout.WEST);
        barRow.add(progress, BorderLayout.CENTER);
        return barRow;
    }
}
