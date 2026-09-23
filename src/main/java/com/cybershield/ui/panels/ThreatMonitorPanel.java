package com.cybershield.ui.panels;

import com.cybershield.exception.DatabaseOperationException;
import com.cybershield.exception.IncidentManagementException;
import com.cybershield.model.Threat;
import com.cybershield.model.enums.ThreatStatus;
import com.cybershield.repository.DatabaseManager;
import com.cybershield.repository.ThreatRepository;
import com.cybershield.service.IncidentService;
import com.cybershield.ui.CyberTheme;
import com.cybershield.ui.components.CyberTable;
import com.cybershield.ui.components.StyledButton;
import com.cybershield.util.DateTimeUtils;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.table.DefaultTableModel;

/**
 * Panel displaying detected threats and enabling 1-click incident escalation.
 * Demonstrates Polymorphic report generation across the Threat hierarchy.
 */
public class ThreatMonitorPanel extends JPanel {

    private final ThreatRepository threatRepository;
    private final IncidentService incidentService;
    private final DefaultTableModel tableModel;
    private final CyberTable threatTable;
    private final JTextArea txtReportPreview;
    private List<Threat> currentThreats;
    private Threat selectedThreat;
    private Runnable onIncidentCreatedCallback;

    public ThreatMonitorPanel() {
        DatabaseManager db = DatabaseManager.getInstance();
        this.threatRepository = new ThreatRepository(db);
        this.incidentService = new IncidentService();

        setLayout(new BorderLayout(10, 10));
        setBackground(CyberTheme.BG_DARK);
        setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        // Top Header & Action Controls
        JPanel topBar = new JPanel(new BorderLayout(8, 8));
        topBar.setOpaque(false);

        JLabel lblTitle = new JLabel("DETECTED THREAT MONITOR");
        lblTitle.setFont(CyberTheme.FONT_TITLE);
        lblTitle.setForeground(CyberTheme.TEXT_PRIMARY);

        JPanel actionControls = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        actionControls.setOpaque(false);

        StyledButton btnEscalate = new StyledButton("▲ Escalate to Incident", StyledButton.ButtonStyle.PRIMARY);
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
        add(topBar, BorderLayout.NORTH);

        // Details Text Area - initialized first so lambda listener can reference it safely
        txtReportPreview = new JTextArea("Select a threat from the queue above to inspect the polymorphic investigative report dossier...");
        txtReportPreview.setEditable(false);
        txtReportPreview.setFont(CyberTheme.FONT_MONO);
        txtReportPreview.setBackground(CyberTheme.BG_CARD);
        txtReportPreview.setForeground(CyberTheme.TEXT_PRIMARY);
        txtReportPreview.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Center SplitPane: Threat Table on Top, Polymorphic Report Dossier on Bottom
        String[] columns = {"Threat ID", "Attack Category", "Severity", "Status", "Attacker IP", "Target Asset", "Detected At"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int col) {
                return false;
            }
        };

        threatTable = new CyberTable(tableModel);
        threatTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = threatTable.getSelectedRow();
                if (selectedRow >= 0 && currentThreats != null && selectedRow < currentThreats.size()) {
                    selectedThreat = currentThreats.get(selectedRow);
                    // Runtime Polymorphism: dynamically calls generateIncidentReport() on concrete Threat subclass!
                    txtReportPreview.setText(selectedThreat.generateIncidentReport());
                } else {
                    selectedThreat = null;
                }
            }
        });

        JScrollPane tableScroll = CyberTable.wrapInScrollPane(threatTable);

        JScrollPane reportScroll = new JScrollPane(txtReportPreview);
        reportScroll.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                " Threat Investigation Dossier (Polymorphic Output) ",
                0, 0, CyberTheme.FONT_BODY_BOLD, CyberTheme.ACCENT_CYAN
        ));

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, reportScroll);
        splitPane.setResizeWeight(0.65);
        splitPane.setDividerSize(4);
        splitPane.setBorder(null);
        splitPane.setBackground(CyberTheme.BG_DARK);

        add(splitPane, BorderLayout.CENTER);

        refreshData();
    }

    public void setOnIncidentCreatedCallback(Runnable callback) {
        this.onIncidentCreatedCallback = callback;
    }

    public void refreshData() {
        try {
            currentThreats = threatRepository.findAll();
            tableModel.setRowCount(0);
            for (Threat t : currentThreats) {
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
