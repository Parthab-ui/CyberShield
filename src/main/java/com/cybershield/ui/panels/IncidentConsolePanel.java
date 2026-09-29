package com.cybershield.ui.panels;

import com.cybershield.exception.DatabaseOperationException;
import com.cybershield.exception.IncidentManagementException;
import com.cybershield.model.Incident;
import com.cybershield.model.ResponseAction;
import com.cybershield.model.enums.ResponseActionType;
import com.cybershield.repository.DatabaseManager;
import com.cybershield.repository.IncidentRepository;
import com.cybershield.repository.ResponseActionRepository;
import com.cybershield.repository.ThreatRepository;
import com.cybershield.service.AuthService;
import com.cybershield.service.IncidentService;
import com.cybershield.ui.CyberTheme;
import com.cybershield.ui.components.CyberTable;
import com.cybershield.ui.components.StyledButton;
import com.cybershield.util.DateTimeUtils;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridLayout;
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
 * Incident Response and Containment Console Panel.
 * Demonstrates Composition: Incident HAS-A Threat and HAS-MANY ResponseAction.
 */
public class IncidentConsolePanel extends JPanel {

    private final IncidentService incidentService;
    private final IncidentRepository incidentRepository;
    private final DefaultTableModel incidentTableModel;
    private final DefaultTableModel actionTableModel;
    private final CyberTable incidentTable;
    private final CyberTable actionTable;
    private final JTextArea txtBriefing;
    private List<Incident> currentIncidents;
    private Incident selectedIncident;
    private Runnable onIncidentUpdatedCallback;

    public IncidentConsolePanel() {
        DatabaseManager db = DatabaseManager.getInstance();
        ThreatRepository threatRepo = new ThreatRepository(db);
        ResponseActionRepository actionRepo = new ResponseActionRepository(db);
        this.incidentRepository = new IncidentRepository(db, threatRepo, actionRepo);
        this.incidentService = new IncidentService(incidentRepository, threatRepo, actionRepo);

        setLayout(new BorderLayout(10, 10));
        setBackground(CyberTheme.BG_DARK);
        setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        // Top Header
        JPanel topBar = new JPanel(new BorderLayout(8, 8));
        topBar.setOpaque(false);

        JLabel lblTitle = new JLabel("INCIDENT RESPONSE & CONTAINMENT CONSOLE");
        lblTitle.setFont(CyberTheme.FONT_TITLE);
        lblTitle.setForeground(CyberTheme.TEXT_PRIMARY);

        StyledButton btnRefresh = new StyledButton("Refresh Incidents", StyledButton.ButtonStyle.SECONDARY);
        btnRefresh.addActionListener(e -> refreshData());

        topBar.add(lblTitle, BorderLayout.WEST);
        topBar.add(btnRefresh, BorderLayout.EAST);
        add(topBar, BorderLayout.NORTH);

        // Initialize details briefing text area first so lambda listener can reference it safely
        txtBriefing = new JTextArea("Select an incident to view briefing notes...");
        txtBriefing.setEditable(false);
        txtBriefing.setFont(CyberTheme.FONT_MONO);
        txtBriefing.setBackground(CyberTheme.BG_CARD);
        txtBriefing.setForeground(CyberTheme.TEXT_PRIMARY);
        txtBriefing.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        String[] actColumns = {"Action ID", "Action Category", "Target Asset", "Executed By", "Status", "Timestamp"};
        actionTableModel = new DefaultTableModel(actColumns, 0) {
            @Override
            public boolean isCellEditable(int r, int c) { return false; }
        };
        actionTable = new CyberTable(actionTableModel);

        // Incidents Table
        String[] incColumns = {"Incident ID", "Title", "Severity", "Status", "Associated Threat", "Created", "Last Updated"};
        incidentTableModel = new DefaultTableModel(incColumns, 0) {
            @Override
            public boolean isCellEditable(int r, int c) { return false; }
        };
        incidentTable = new CyberTable(incidentTableModel);
        incidentTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = incidentTable.getSelectedRow();
                if (row >= 0 && currentIncidents != null && row < currentIncidents.size()) {
                    selectedIncident = currentIncidents.get(row);
                    loadIncidentDetails(selectedIncident);
                } else {
                    selectedIncident = null;
                }
            }
        });

        JScrollPane incidentScroll = CyberTable.wrapInScrollPane(incidentTable);

        // Bottom Pane: Split between Case Briefing/Actions and Composed Response Action History
        JPanel bottomContainer = new JPanel(new BorderLayout(8, 8));
        bottomContainer.setOpaque(false);

        // Action Toolbar
        JPanel actionControls = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        actionControls.setOpaque(false);
        actionControls.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                " Simulated Containment & Mitigation Actions (Click to Dispatch) ",
                0, 0, CyberTheme.FONT_BODY_BOLD, CyberTheme.ACCENT_CYAN
        ));

        StyledButton btnBlockIp = new StyledButton("🛡 Block IP", StyledButton.ButtonStyle.DANGER);
        btnBlockIp.addActionListener(e -> executeAction(ResponseActionType.BLOCK_IP));

        StyledButton btnDisableUser = new StyledButton("👤 Disable User", StyledButton.ButtonStyle.DANGER);
        btnDisableUser.addActionListener(e -> executeAction(ResponseActionType.DISABLE_USER));

        StyledButton btnQuarantine = new StyledButton("☣ Quarantine Simulation", StyledButton.ButtonStyle.DANGER);
        btnQuarantine.addActionListener(e -> executeAction(ResponseActionType.QUARANTINE_SIMULATION));

        StyledButton btnReview = new StyledButton("🔍 Mark for Review", StyledButton.ButtonStyle.SECONDARY);
        btnReview.addActionListener(e -> executeAction(ResponseActionType.MARK_FOR_REVIEW));

        StyledButton btnResolve = new StyledButton("✓ Resolve Incident", StyledButton.ButtonStyle.SUCCESS);
        btnResolve.addActionListener(e -> resolveSelectedIncident());

        actionControls.add(btnBlockIp);
        actionControls.add(btnDisableUser);
        actionControls.add(btnQuarantine);
        actionControls.add(btnReview);
        actionControls.add(btnResolve);

        // Lower Split: Left = Investigation Briefing, Right = Composed Action History Table
        JPanel detailsPanel = new JPanel(new GridLayout(1, 2, 8, 8));
        detailsPanel.setOpaque(false);

        JScrollPane briefScroll = new JScrollPane(txtBriefing);
        briefScroll.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                " Incident Briefing Dossier ", 0, 0, CyberTheme.FONT_BODY_BOLD, CyberTheme.TEXT_MUTED
        ));

        JScrollPane actScroll = CyberTable.wrapInScrollPane(actionTable);
        actScroll.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                " Incident Response Action Audit Log (Composition: HAS-MANY) ", 0, 0, CyberTheme.FONT_BODY_BOLD, CyberTheme.TEXT_MUTED
        ));

        detailsPanel.add(briefScroll);
        detailsPanel.add(actScroll);

        bottomContainer.add(actionControls, BorderLayout.NORTH);
        bottomContainer.add(detailsPanel, BorderLayout.CENTER);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, incidentScroll, bottomContainer);
        mainSplit.setResizeWeight(0.50);
        mainSplit.setDividerSize(4);
        mainSplit.setBorder(null);
        mainSplit.setBackground(CyberTheme.BG_DARK);

        add(mainSplit, BorderLayout.CENTER);

        refreshData();
    }

    public void setOnIncidentUpdatedCallback(Runnable callback) {
        this.onIncidentUpdatedCallback = callback;
    }

    public void refreshData() {
        try {
            currentIncidents = incidentRepository.findAll();
            incidentTableModel.setRowCount(0);
            for (Incident inc : currentIncidents) {
                incidentTableModel.addRow(new Object[]{
                    inc.getIncidentId(),
                    inc.getTitle(),
                    inc.getSeverity().name(),
                    inc.getStatus().name(),
                    inc.getAssociatedThreat() != null ? inc.getAssociatedThreat().getThreatId() : "N/A",
                    DateTimeUtils.format(inc.getCreatedAt()),
                    DateTimeUtils.format(inc.getUpdatedAt())
                });
            }

            if (selectedIncident != null) {
                Incident reloaded = incidentRepository.findById(selectedIncident.getIncidentId());
                if (reloaded != null) {
                    loadIncidentDetails(reloaded);
                }
            }
        } catch (DatabaseOperationException e) {
            JOptionPane.showMessageDialog(this, "Failed to load incidents: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void loadIncidentDetails(Incident inc) {
        selectedIncident = inc;
        txtBriefing.setText(String.format(
            "=== INCIDENT CASE FILE: %s ===\n" +
            "Title: %s\n" +
            "Current Status: %s | Severity: %s\n" +
            "Created: %s | Updated: %s\n" +
            "Associated Threat: %s\n\n" +
            "[Description & Initial Findings]:\n%s",
            inc.getIncidentId(), inc.getTitle(), inc.getStatus(), inc.getSeverity(),
            DateTimeUtils.format(inc.getCreatedAt()), DateTimeUtils.format(inc.getUpdatedAt()),
            inc.getAssociatedThreat() != null ? inc.getAssociatedThreat().getThreatId() : "None",
            inc.getDescription()
        ));

        // Populate composed action history (Composition: HAS-MANY ResponseAction)
        actionTableModel.setRowCount(0);
        List<ResponseAction> actions = inc.getResponseActions();
        for (ResponseAction act : actions) {
            actionTableModel.addRow(new Object[]{
                act.getActionId(),
                act.getActionType().getDisplayName(),
                act.getTarget(),
                act.getExecutedBy(),
                act.getStatus(),
                DateTimeUtils.format(act.getExecutedAt())
            });
        }
    }

    private void executeAction(ResponseActionType actionType) {
        if (selectedIncident == null) {
            JOptionPane.showMessageDialog(this, "Please select an incident from the table above first.", "Selection Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        try {
            String analyst = AuthService.getCurrentUser() != null ? AuthService.getCurrentUser().getUsername() : "analyst";
            ResponseAction action = incidentService.executeResponseAction(selectedIncident.getIncidentId(), actionType, analyst, null);

            JOptionPane.showMessageDialog(this,
                    String.format("Response action '%s' successfully recorded!\nAction ID: %s\nTarget: %s\nStatus: %s",
                            actionType.getDisplayName(), action.getActionId(), action.getTarget(), action.getStatus()),
                    "Action Dispatched (Simulated)", JOptionPane.INFORMATION_MESSAGE);

            refreshData();
            if (onIncidentUpdatedCallback != null) {
                onIncidentUpdatedCallback.run();
            }
        } catch (IncidentManagementException e) {
            JOptionPane.showMessageDialog(this, "Action failed: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void resolveSelectedIncident() {
        if (selectedIncident == null) {
            JOptionPane.showMessageDialog(this, "Please select an incident to resolve.", "Selection Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String notes = JOptionPane.showInputDialog(this, "Enter resolution summary / root-cause notes:", "Incident Resolution", JOptionPane.QUESTION_MESSAGE);
        if (notes != null) {
            try {
                incidentService.resolveIncident(selectedIncident.getIncidentId(), notes);
                JOptionPane.showMessageDialog(this, "Incident marked as RESOLVED and associated threat updated.", "Success", JOptionPane.INFORMATION_MESSAGE);
                refreshData();
                if (onIncidentUpdatedCallback != null) {
                    onIncidentUpdatedCallback.run();
                }
            } catch (IncidentManagementException e) {
                JOptionPane.showMessageDialog(this, "Failed to resolve incident: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
}
