package com.cybershield.ui.panels;

import com.cybershield.exception.DatabaseOperationException;
import com.cybershield.exception.IncidentManagementException;
import com.cybershield.model.Threat;
import com.cybershield.model.enums.Severity;
import com.cybershield.model.enums.ThreatStatus;
import com.cybershield.repository.DatabaseManager;
import com.cybershield.repository.ThreatRepository;
import com.cybershield.service.IncidentService;
import com.cybershield.ui.CyberTheme;
import com.cybershield.ui.components.BlockedIpsListPanel;
import com.cybershield.ui.components.CyberTable;
import com.cybershield.ui.components.MitreAssetTreePanel;
import com.cybershield.ui.components.StyledButton;
import com.cybershield.util.DateTimeUtils;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.datatransfer.StringSelection;
import java.awt.Toolkit;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JSlider;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextPane;
import javax.swing.table.DefaultTableModel;

/**
 * Panel displaying detected threats and enabling 1-click incident escalation.
 * Demonstrates:
 * - Runtime Polymorphic report generation across the Threat hierarchy.
 * - Swing components: JTable, JSplitPane, JTabbedPane, JTextPane, JTextArea,
 *   JRadioButton, ButtonGroup, JSlider, JPopupMenu, JMenuItem, JTree (tab), JList (tab).
 */
public class ThreatMonitorPanel extends JPanel {

    private final ThreatRepository threatRepository;
    private final IncidentService incidentService;
    private final DefaultTableModel tableModel;
    private final CyberTable threatTable;
    private final JTextPane txtHtmlDossier;
    private final JTextArea txtRawReport;
    private final JSlider sliderSeverity;
    private final JLabel lblSliderVal;

    private JRadioButton rbAll;
    private JRadioButton rbCritical;
    private JRadioButton rbHigh;
    private JRadioButton rbMedLow;

    private List<Threat> allThreats = new ArrayList<>();
    private List<Threat> displayedThreats = new ArrayList<>();
    private Threat selectedThreat;
    private Runnable onIncidentCreatedCallback;

    public ThreatMonitorPanel() {
        DatabaseManager db = DatabaseManager.getInstance();
        this.threatRepository = new ThreatRepository(db);
        this.incidentService = new IncidentService();

        setLayout(new BorderLayout(10, 10));
        setBackground(CyberTheme.BG_DARK);
        setBorder(BorderFactory.createEmptyBorder(14, 14, 14, 14));

        // 1. Top Header & Action Controls
        JPanel topContainer = new JPanel(new BorderLayout(8, 8));
        topContainer.setOpaque(false);

        JPanel topBar = new JPanel(new BorderLayout(8, 8));
        topBar.setOpaque(false);

        JLabel lblTitle = new JLabel("⚡ DETECTED THREAT MONITOR & INVESTIGATION");
        lblTitle.setFont(CyberTheme.FONT_TITLE);
        lblTitle.setForeground(CyberTheme.TEXT_PRIMARY);

        JPanel actionControls = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        actionControls.setOpaque(false);

        StyledButton btnEscalate = new StyledButton("▲ Escalate to Incident", StyledButton.ButtonStyle.PRIMARY);
        btnEscalate.setToolTipText("Escalate the selected threat into a formal Incident Case (Demonstrates Composition)");
        btnEscalate.addActionListener(e -> escalateSelectedThreat());

        StyledButton btnDismiss = new StyledButton("Mark False Positive", StyledButton.ButtonStyle.SECONDARY);
        btnDismiss.addActionListener(e -> dismissSelectedThreat());

        StyledButton btnRefresh = new StyledButton("Refresh", StyledButton.ButtonStyle.SECONDARY);
        btnRefresh.addActionListener(e -> refreshData());

        actionControls.add(btnEscalate);
        actionControls.add(btnDismiss);
        actionControls.add(btnRefresh);

        topBar.add(lblTitle, BorderLayout.WEST);
        topBar.add(actionControls, BorderLayout.EAST);
        topContainer.add(topBar, BorderLayout.NORTH);

        // 2. Filter Bar: RadioButtons (JRadioButton + ButtonGroup) and Severity Slider (JSlider)
        JPanel filterBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 4));
        filterBar.setBackground(CyberTheme.BG_CARD);
        filterBar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                BorderFactory.createEmptyBorder(4, 10, 4, 10)
        ));

        JLabel lblFilter = new JLabel("Severity Filter:");
        lblFilter.setFont(CyberTheme.FONT_BODY_BOLD);
        lblFilter.setForeground(CyberTheme.ACCENT_CYAN);
        filterBar.add(lblFilter);

        rbAll = createRadioButton("All", true);
        rbCritical = createRadioButton("Critical Only", false);
        rbHigh = createRadioButton("High+", false);
        rbMedLow = createRadioButton("Medium/Low", false);

        ButtonGroup filterGroup = new ButtonGroup();
        filterGroup.add(rbAll);
        filterGroup.add(rbCritical);
        filterGroup.add(rbHigh);
        filterGroup.add(rbMedLow);

        filterBar.add(rbAll);
        filterBar.add(rbCritical);
        filterBar.add(rbHigh);
        filterBar.add(rbMedLow);

        filterBar.add(new JSeparator(JSeparator.VERTICAL) {{ setPreferredSize(new Dimension(2, 20)); }});

        JLabel lblSlider = new JLabel("Sensitivity Slider:");
        lblSlider.setFont(CyberTheme.FONT_BODY_BOLD);
        lblSlider.setForeground(CyberTheme.STATUS_AMBER);
        filterBar.add(lblSlider);

        sliderSeverity = new JSlider(0, 100, 0);
        sliderSeverity.setOpaque(false);
        sliderSeverity.setPreferredSize(new Dimension(140, 26));
        sliderSeverity.setToolTipText("Filter threats by minimum heuristic risk score (0-100%)");
        lblSliderVal = new JLabel("0%");
        lblSliderVal.setFont(CyberTheme.FONT_MONO);
        lblSliderVal.setForeground(CyberTheme.TEXT_PRIMARY);

        sliderSeverity.addChangeListener(e -> {
            lblSliderVal.setText(sliderSeverity.getValue() + "%");
            applyFilters();
        });

        filterBar.add(sliderSeverity);
        filterBar.add(lblSliderVal);

        topContainer.add(filterBar, BorderLayout.SOUTH);
        add(topContainer, BorderLayout.NORTH);

        // 3. Center Table (CyberTable)
        String[] columns = {"Threat ID", "Attack Category", "Severity", "Status", "Attacker IP", "Target Asset", "Detected At"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        threatTable = new CyberTable(tableModel);

        // Wire Table Selection Listener
        threatTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = threatTable.getSelectedRow();
                if (selectedRow >= 0 && displayedThreats != null && selectedRow < displayedThreats.size()) {
                    selectedThreat = displayedThreats.get(selectedRow);
                    displayThreatDossier(selectedThreat);
                } else {
                    selectedThreat = null;
                }
            }
        });

        // 4. JPopupMenu (Right-Click Context Menu)
        JPopupMenu popupMenu = createTablePopupMenu();
        threatTable.setComponentPopupMenu(popupMenu);
        threatTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) showPopup(e);
            }
            @Override
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) showPopup(e);
            }
            private void showPopup(MouseEvent e) {
                int row = threatTable.rowAtPoint(e.getPoint());
                if (row >= 0 && row < threatTable.getRowCount()) {
                    threatTable.setRowSelectionInterval(row, row);
                }
            }
        });

        JScrollPane tableScroll = CyberTable.wrapInScrollPane(threatTable);
        tableScroll.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                " Identified Threat Queue (Right-Click Row for JPopupMenu Actions) ",
                0, 0, CyberTheme.FONT_BODY_BOLD, CyberTheme.ACCENT_CYAN
        ));

        // 5. Bottom Tabs (JTabbedPane with JTextPane, JTree, JList, JTextArea)
        JTabbedPane bottomTabs = new JTabbedPane();
        bottomTabs.setBackground(CyberTheme.BG_DARK);
        bottomTabs.setForeground(CyberTheme.TEXT_PRIMARY);
        bottomTabs.setFont(CyberTheme.FONT_BODY_BOLD);

        // Tab 1: Rich HTML Dossier (JTextPane)
        txtHtmlDossier = new JTextPane();
        txtHtmlDossier.setContentType("text/html");
        txtHtmlDossier.setEditable(false);
        txtHtmlDossier.setBackground(CyberTheme.BG_CARD);
        txtHtmlDossier.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        txtHtmlDossier.setText("<html><body style='font-family:Segoe UI, sans-serif; color:#e0e6ed; background-color:#161b22; padding:15px;'>" +
                "<h3 style='color:#00e5ff;'>Select a threat from the queue above to inspect the polymorphic investigative report dossier...</h3>" +
                "<p style='color:#8b949e;'>This dossier dynamically renders details via runtime polymorphic dispatch on concrete subclasses of Threat.</p>" +
                "</body></html>");

        JScrollPane htmlScroll = new JScrollPane(txtHtmlDossier);
        htmlScroll.setBorder(BorderFactory.createEmptyBorder());
        bottomTabs.addTab("📋 Formatted Dossier (JTextPane)", htmlScroll);

        // Tab 2: MITRE Asset Tree (JTree)
        MitreAssetTreePanel treePanel = new MitreAssetTreePanel();
        bottomTabs.addTab("🌳 MITRE ATT&CK Matrix (JTree)", treePanel);

        // Tab 3: Active Perimeter Droplist (JList)
        BlockedIpsListPanel listPanel = new BlockedIpsListPanel();
        bottomTabs.addTab("🛡 Perimeter Blocked Droplist (JList)", listPanel);

        // Tab 4: Raw Text Report (JTextArea)
        txtRawReport = new JTextArea("Raw report buffer...");
        txtRawReport.setEditable(false);
        txtRawReport.setFont(CyberTheme.FONT_MONO);
        txtRawReport.setBackground(CyberTheme.BG_CARD);
        txtRawReport.setForeground(CyberTheme.TEXT_PRIMARY);
        txtRawReport.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        bottomTabs.addTab("📄 Plain Monospace Trace (JTextArea)", new JScrollPane(txtRawReport));

        // 6. Resizable JSplitPane
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, bottomTabs);
        splitPane.setResizeWeight(0.50);
        splitPane.setDividerSize(6);
        splitPane.setOpaque(false);
        splitPane.setBorder(null);

        add(splitPane, BorderLayout.CENTER);
        refreshData();
    }

    private JRadioButton createRadioButton(String label, boolean selected) {
        JRadioButton rb = new JRadioButton(label, selected);
        rb.setOpaque(false);
        rb.setForeground(CyberTheme.TEXT_PRIMARY);
        rb.setFont(CyberTheme.FONT_BODY);
        rb.addActionListener(e -> applyFilters());
        return rb;
    }

    private JPopupMenu createTablePopupMenu() {
        JPopupMenu popup = new JPopupMenu();
        popup.setBackground(CyberTheme.BG_CARD);
        popup.setBorder(BorderFactory.createLineBorder(CyberTheme.ACCENT_CYAN, 1));

        JMenuItem miEscalate = new JMenuItem("▲ Escalate to Incident Case");
        miEscalate.setFont(CyberTheme.FONT_BODY_BOLD);
        miEscalate.setForeground(CyberTheme.ACCENT_CYAN);
        miEscalate.addActionListener(e -> escalateSelectedThreat());

        JMenuItem miCopyIp = new JMenuItem("📋 Copy Attacker IP Address");
        miCopyIp.setFont(CyberTheme.FONT_BODY);
        miCopyIp.addActionListener(e -> {
            if (selectedThreat != null) {
                Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(new StringSelection(selectedThreat.getSourceIp()), null);
                JOptionPane.showMessageDialog(this, "Copied IP: " + selectedThreat.getSourceIp(), "Clipboard", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        JMenuItem miBlock = new JMenuItem("🛡 Quick Dispatch Perimeter Firewall Block");
        miBlock.setFont(CyberTheme.FONT_BODY);
        miBlock.addActionListener(e -> {
            if (selectedThreat != null) {
                JOptionPane.showMessageDialog(this,
                        "Firewall instruction sent: BLOCKED IP " + selectedThreat.getSourceIp() + "\nSimulated rule added to ingress policy.",
                        "Perimeter Containment", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        JMenuItem miDismiss = new JMenuItem("✓ Mark as False Positive");
        miDismiss.setFont(CyberTheme.FONT_BODY);
        miDismiss.addActionListener(e -> dismissSelectedThreat());

        popup.add(miEscalate);
        popup.add(miCopyIp);
        popup.add(miBlock);
        popup.addSeparator();
        popup.add(miDismiss);

        return popup;
    }

    private void displayThreatDossier(Threat t) {
        // Raw report (Demonstrates Polymorphism: dynamically calls generateIncidentReport() on concrete Threat subclass)
        String rawReport = t.generateIncidentReport();
        txtRawReport.setText(rawReport);
        txtRawReport.setCaretPosition(0);

        // Rich HTML Dossier in JTextPane
        String sevColor = switch (t.getSeverity()) {
            case CRITICAL -> "#ff3366";
            case HIGH -> "#ff0055";
            case MEDIUM -> "#ffaa00";
            case LOW -> "#00e5ff";
        };

        StringBuilder html = new StringBuilder();
        html.append("<html><body style='font-family:Segoe UI, sans-serif; color:#e0e6ed; background-color:#161b22; padding:12px;'>");
        html.append("<table width='100%' border='0' cellpadding='4' cellspacing='0'>");
        html.append("<tr>");
        html.append("<td><h2 style='color:#00e5ff; margin:0;'>THREAT DOSSIER: ").append(t.getThreatId()).append("</h2></td>");
        html.append("<td align='right'><span style='background-color:").append(sevColor).append("; color:#ffffff; font-weight:bold; padding:4px 10px; border-radius:4px;'>")
                .append(t.getSeverity().name()).append(" SEVERITY</span></td>");
        html.append("</tr>");
        html.append("</table>");
        html.append("<hr style='border:1px solid #30363d; margin:8px 0;'>");

        html.append("<table width='100%' cellpadding='6' cellspacing='2' style='font-size:12px;'>");
        html.append("<tr><td width='25%' style='color:#8b949e;'><b>Attack Category:</b></td><td style='color:#ffffff;'><b>").append(t.getThreatType().getDisplayName()).append("</b></td></tr>");
        html.append("<tr><td style='color:#8b949e;'><b>Target Asset:</b></td><td style='color:#00e5ff;'>").append(t.getTargetAsset()).append("</td></tr>");
        html.append("<tr><td style='color:#8b949e;'><b>Attacking Source IP:</b></td><td style='color:#ff3366; font-family:Consolas;'>").append(t.getSourceIp()).append("</td></tr>");
        html.append("<tr><td style='color:#8b949e;'><b>Detection Time:</b></td><td>").append(DateTimeUtils.format(t.getDetectedAt())).append("</td></tr>");
        html.append("<tr><td style='color:#8b949e;'><b>Operational Status:</b></td><td><span style='color:#00ff88;'>● ").append(t.getStatus().name()).append("</span></td></tr>");
        html.append("<tr><td style='color:#8b949e;'><b>Recommended Action:</b></td><td style='color:#ffaa00;'><b>").append(t.getRecommendedAction().getDisplayName()).append("</b></td></tr>");
        html.append("</table>");

        html.append("<div style='background-color:#0d1117; border-left:4px solid #00e5ff; padding:10px; margin-top:10px;'>");
        html.append("<b style='color:#00e5ff;'>Subsystem Heuristic Description:</b><br>");
        html.append("<span style='font-family:Consolas; color:#c9d1d9;'>").append(t.getDescription().replace("\n", "<br>")).append("</span>");
        html.append("</div>");

        html.append("<p style='color:#8b949e; font-size:10px; margin-top:12px;'>");
        html.append("<b>Viva Talking Point:</b> Invoking <code>threat.generateIncidentReport()</code> executes dynamic runtime method dispatch to the subclass (<code>")
                .append(t.getClass().getSimpleName()).append("</code>).");
        html.append("</p></body></html>");

        txtHtmlDossier.setText(html.toString());
        txtHtmlDossier.setCaretPosition(0);
    }

    private void applyFilters() {
        displayedThreats.clear();
        int minRiskScore = sliderSeverity.getValue();

        for (Threat t : allThreats) {
            // Radio button filter
            boolean matchesRadio = true;
            if (rbCritical.isSelected() && t.getSeverity() != Severity.CRITICAL) matchesRadio = false;
            else if (rbHigh.isSelected() && (t.getSeverity() != Severity.CRITICAL && t.getSeverity() != Severity.HIGH)) matchesRadio = false;
            else if (rbMedLow.isSelected() && (t.getSeverity() != Severity.MEDIUM && t.getSeverity() != Severity.LOW)) matchesRadio = false;

            // Slider heuristic score estimation
            int threatScore = switch (t.getSeverity()) {
                case CRITICAL -> 95;
                case HIGH -> 75;
                case MEDIUM -> 50;
                case LOW -> 25;
            };

            if (matchesRadio && threatScore >= minRiskScore) {
                displayedThreats.add(t);
            }
        }

        tableModel.setRowCount(0);
        for (Threat t : displayedThreats) {
            tableModel.addRow(new Object[]{
                t.getThreatId(),
                t.getThreatType().getDisplayName(),
                t.getSeverity().name(),
                t.getStatus().name(),
                t.getSourceIp(),
                t.getTargetAsset(),
                DateTimeUtils.format(t.getDetectedAt())
            });
        }
    }

    public void setOnIncidentCreatedCallback(Runnable callback) {
        this.onIncidentCreatedCallback = callback;
    }

    public void refreshData() {
        try {
            allThreats = threatRepository.findAll();
            applyFilters();
        } catch (DatabaseOperationException e) {
            JOptionPane.showMessageDialog(this, "Failed to load threats: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void escalateSelectedThreat() {
        if (selectedThreat == null) {
            JOptionPane.showMessageDialog(this, "Please select an active threat from the table first.", "Selection Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        try {
            String title = "Escalated Incident: " + selectedThreat.getThreatType().getDisplayName() + " on " + selectedThreat.getTargetAsset();
            incidentService.escalateThreatToIncident(selectedThreat, title);
            JOptionPane.showMessageDialog(this, "Threat successfully escalated to Incident case!\nCheck the Incident Console to execute containment actions.",
                    "Escalation Successful", JOptionPane.INFORMATION_MESSAGE);

            refreshData();
            if (onIncidentCreatedCallback != null) {
                onIncidentCreatedCallback.run();
            }
        } catch (IncidentManagementException e) {
            JOptionPane.showMessageDialog(this, "Escalation failed: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void dismissSelectedThreat() {
        if (selectedThreat == null) {
            JOptionPane.showMessageDialog(this, "Please select a threat to dismiss.", "Selection Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        try {
            threatRepository.updateStatus(selectedThreat.getThreatId(), ThreatStatus.FALSE_POSITIVE);
            refreshData();
        } catch (DatabaseOperationException e) {
            JOptionPane.showMessageDialog(this, "Failed to dismiss threat: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }
}
