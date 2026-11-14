package cybershield.ui;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import cybershield.model.Incident;
import cybershield.model.InvestigationNote;
import cybershield.model.InvestigationSummary;
import cybershield.model.InvestigationTimelineItem;
import cybershield.model.User;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

/**
 * InvestigationPanel — Desktop SOC Console for Incident Forensics,
 * structured JSON evidence archival, root cause categorization, and resolution workflows.
 */
public class InvestigationPanel extends JPanel {

    private final ApiClient apiClient = ApiClient.getInstance();
    private final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private final Gson prettyGson = new GsonBuilder().setPrettyPrinting().create();

    // Top Controls
    private JComboBox<IncidentItem> cmbIncidents;
    private JButton btnRefresh;

    // Dossier Labels
    private JLabel lblDossierId;
    private JLabel lblDossierTitle;
    private JLabel lblDossierSeverity;
    private JLabel lblDossierStatus;
    private JLabel lblDossierAssigned;
    private JLabel lblDossierRootCause;
    private JLabel lblDossierNotesCount;
    private JLabel lblDossierResolution;

    // Left Side: Notes & Evidence
    private DefaultTableModel notesModel;
    private JTable notesTable;
    private JTextArea txtNoteNarrative;
    private JTextArea txtEvidenceJson;
    private JButton btnSubmitNote;

    // Right Side: Assignment, Root Cause, Resolution & Timeline
    private JComboBox<String> cmbInvestigators;
    private JButton btnAssign;
    private JComboBox<String> cmbRootCauseCategory;
    private JTextField txtRootCauseExplanation;
    private JButton btnSaveRootCause;
    private JTextArea txtResolutionSummary;
    private JButton btnResolve;
    private JButton btnClose;

    // Timeline Table
    private DefaultTableModel timelineModel;
    private JTable timelineTable;

    private Integer currentIncidentId = null;
    private Timer refreshTimer;

    public InvestigationPanel() {
        setBackground(SwingTheme.BG_DARK);
        setLayout(new BorderLayout(0, 10));
        setBorder(BorderFactory.createEmptyBorder(14, 18, 14, 18));

        add(createHeaderBar(), BorderLayout.NORTH);

        JPanel content = new JPanel(new BorderLayout(0, 10));
        content.setOpaque(false);

        content.add(createDossierCard(), BorderLayout.NORTH);

        // Center split: Left = Forensic Notes & Evidence; Right = Workflow & Timeline
        JPanel leftPanel = createNotesAndEvidencePanel();
        JPanel rightPanel = createWorkflowAndTimelinePanel();

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel);
        splitPane.setResizeWeight(0.52);
        splitPane.setDividerSize(6);
        splitPane.setOpaque(false);
        splitPane.setBorder(null);

        content.add(splitPane, BorderLayout.CENTER);
        add(content, BorderLayout.CENTER);

        refreshTimer = new Timer(5000, e -> {
            if (isShowing() && currentIncidentId != null) {
                loadInvestigationData(currentIncidentId, true);
            }
        });
        refreshTimer.start();

        loadIncidentsList();
    }

    private JPanel createHeaderBar() {
        JPanel header = new JPanel(new BorderLayout());
        header.setOpaque(false);

        JPanel left = new JPanel();
        left.setLayout(new BoxLayout(left, BoxLayout.Y_AXIS));
        left.setOpaque(false);

        JLabel title = new JLabel("Investigation & Forensic Triage Center");
        title.setFont(SwingTheme.FONT_TITLE);
        title.setForeground(SwingTheme.TEXT_PRIMARY);

        JLabel sub = new JLabel("Forensic Artifact Archival, Timeline Reconstruction, Root Cause Analysis & Resolution");
        sub.setFont(SwingTheme.FONT_SMALL);
        sub.setForeground(SwingTheme.TEXT_SECONDARY);

        left.add(title);
        left.add(Box.createVerticalStrut(2));
        left.add(sub);

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        right.setOpaque(false);

        JLabel lblSelect = new JLabel("Select Incident:");
        lblSelect.setFont(SwingTheme.FONT_BOLD);
        lblSelect.setForeground(SwingTheme.TEXT_PRIMARY);

        cmbIncidents = new JComboBox<>();
        cmbIncidents.setPreferredSize(new Dimension(320, 28));
        SwingTheme.styleComboBox(cmbIncidents);
        cmbIncidents.addActionListener(e -> {
            IncidentItem item = (IncidentItem) cmbIncidents.getSelectedItem();
            if (item != null) {
                currentIncidentId = item.id;
                loadInvestigationData(item.id, false);
            }
        });

        btnRefresh = new JButton("Refresh");
        SwingTheme.styleSecondaryButton(btnRefresh);
        btnRefresh.addActionListener(e -> {
            loadIncidentsList();
            if (currentIncidentId != null) {
                loadInvestigationData(currentIncidentId, false);
            }
        });

        right.add(lblSelect);
        right.add(cmbIncidents);
        right.add(btnRefresh);

        header.add(left, BorderLayout.WEST);
        header.add(right, BorderLayout.EAST);
        return header;
    }

    private JPanel createDossierCard() {
        JPanel card = new JPanel(new BorderLayout(0, 6));
        card.setBackground(SwingTheme.PANEL_BG);
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR),
                BorderFactory.createEmptyBorder(10, 14, 10, 14)
        ));

        JPanel topRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        topRow.setOpaque(false);

        lblDossierId = new JLabel("#—");
        lblDossierId.setFont(SwingTheme.FONT_HEADER);
        lblDossierId.setForeground(SwingTheme.ACCENT_CYAN);

        lblDossierTitle = new JLabel("Select an incident to view case dossier");
        lblDossierTitle.setFont(SwingTheme.FONT_HEADER);
        lblDossierTitle.setForeground(SwingTheme.TEXT_PRIMARY);

        lblDossierSeverity = new JLabel("SEVERITY: —");
        lblDossierSeverity.setFont(SwingTheme.FONT_BOLD);
        lblDossierSeverity.setForeground(SwingTheme.TEXT_SECONDARY);

        lblDossierStatus = new JLabel("STATUS: —");
        lblDossierStatus.setFont(SwingTheme.FONT_BOLD);
        lblDossierStatus.setForeground(SwingTheme.TEXT_SECONDARY);

        topRow.add(lblDossierId);
        topRow.add(lblDossierTitle);
        topRow.add(lblDossierSeverity);
        topRow.add(lblDossierStatus);

        JPanel bottomRow = new JPanel(new GridLayout(1, 4, 12, 0));
        bottomRow.setOpaque(false);

        lblDossierAssigned = new JLabel("Assigned: Unassigned");
        lblDossierAssigned.setFont(SwingTheme.FONT_SMALL);
        lblDossierAssigned.setForeground(SwingTheme.TEXT_SECONDARY);

        lblDossierRootCause = new JLabel("Root Cause: Pending Analysis");
        lblDossierRootCause.setFont(SwingTheme.FONT_SMALL);
        lblDossierRootCause.setForeground(SwingTheme.TEXT_SECONDARY);

        lblDossierNotesCount = new JLabel("Forensic Notes: 0");
        lblDossierNotesCount.setFont(SwingTheme.FONT_SMALL);
        lblDossierNotesCount.setForeground(SwingTheme.TEXT_SECONDARY);

        lblDossierResolution = new JLabel("Resolution: Active Investigation");
        lblDossierResolution.setFont(SwingTheme.FONT_SMALL);
        lblDossierResolution.setForeground(SwingTheme.TEXT_SECONDARY);

        bottomRow.add(lblDossierAssigned);
        bottomRow.add(lblDossierRootCause);
        bottomRow.add(lblDossierNotesCount);
        bottomRow.add(lblDossierResolution);

        card.add(topRow, BorderLayout.NORTH);
        card.add(bottomRow, BorderLayout.SOUTH);
        return card;
    }

    private JPanel createNotesAndEvidencePanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 8));
        panel.setBackground(SwingTheme.PANEL_BG);
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR),
                BorderFactory.createEmptyBorder(10, 12, 10, 12)
        ));

        // Subheader
        JPanel top = new JPanel(new BorderLayout());
        top.setOpaque(false);
        JLabel lblTitle = new JLabel("Forensic Investigation Notes & Evidence");
        lblTitle.setFont(SwingTheme.FONT_HEADER);
        lblTitle.setForeground(SwingTheme.TEXT_PRIMARY);

        JButton btnViewEvidence = new JButton("Inspect Full Evidence");
        SwingTheme.styleSecondaryButton(btnViewEvidence);
        btnViewEvidence.addActionListener(e -> handleInspectEvidence());

        top.add(lblTitle, BorderLayout.WEST);
        top.add(btnViewEvidence, BorderLayout.EAST);
        panel.add(top, BorderLayout.NORTH);

        // Notes Table
        String[] cols = {"ID", "Analyst", "Timestamp", "Forensic Narrative", "Evidence Attached"};
        notesModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) { return false; }
        };
        notesTable = new JTable(notesModel);
        SwingTheme.styleTable(notesTable);
        notesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        JScrollPane scrollNotes = new JScrollPane(notesTable);
        scrollNotes.getViewport().setBackground(SwingTheme.PANEL_BG);
        scrollNotes.setBorder(BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR));
        scrollNotes.setPreferredSize(new Dimension(400, 180));

        // Form to add new note
        JPanel formPanel = new JPanel();
        formPanel.setLayout(new BoxLayout(formPanel, BoxLayout.Y_AXIS));
        formPanel.setOpaque(false);
        formPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR),
                "Add Investigation Note & Structured Evidence",
                0, 0, SwingTheme.FONT_BOLD, SwingTheme.ACCENT_CYAN
        ));

        JLabel lblNarrative = new JLabel("Analyst Narrative:");
        lblNarrative.setFont(SwingTheme.FONT_BOLD);
        lblNarrative.setForeground(SwingTheme.TEXT_PRIMARY);

        txtNoteNarrative = new JTextArea(2, 20);
        txtNoteNarrative.setBackground(SwingTheme.CARD_BG);
        txtNoteNarrative.setForeground(SwingTheme.TEXT_PRIMARY);
        txtNoteNarrative.setCaretColor(Color.WHITE);
        txtNoteNarrative.setFont(SwingTheme.FONT_REGULAR);
        txtNoteNarrative.setLineWrap(true);
        JScrollPane scrollNarrative = new JScrollPane(txtNoteNarrative);

        // Presets toolbar for evidence JSON
        JPanel presetBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        presetBar.setOpaque(false);

        JLabel lblEvidence = new JLabel("Structured Evidence (JSON):");
        lblEvidence.setFont(SwingTheme.FONT_BOLD);
        lblEvidence.setForeground(SwingTheme.TEXT_PRIMARY);

        JButton btnPreAuth = new JButton("Auth Dump");
        SwingTheme.styleSecondaryButton(btnPreAuth);
        btnPreAuth.addActionListener(e -> txtEvidenceJson.setText("{\n  \"event_type\": \"FAILED_AUTH_BURST\",\n  \"source_ip\": \"198.51.100.42\",\n  \"target_user\": \"admin\",\n  \"failures\": 5,\n  \"user_agent\": \"Hydra/v9.3\"\n}"));

        JButton btnPreIp = new JButton("IP Threat Intel");
        SwingTheme.styleSecondaryButton(btnPreIp);
        btnPreIp.addActionListener(e -> txtEvidenceJson.setText("{\n  \"threat_feed\": \"AbuseIPDB\",\n  \"confidence_score\": 98,\n  \"country\": \"RO\",\n  \"asn\": \"AS9009\",\n  \"prior_reports\": 1420\n}"));

        JButton btnPreIds = new JButton("IDS Trigger");
        SwingTheme.styleSecondaryButton(btnPreIds);
        btnPreIds.addActionListener(e -> txtEvidenceJson.setText("{\n  \"rule_id\": \"IDS-AUTH-BRUTE-001\",\n  \"threshold\": \"5 failures within 120s\",\n  \"auto_containment\": \"IP_BLOCK\"\n}"));

        presetBar.add(lblEvidence);
        presetBar.add(btnPreAuth);
        presetBar.add(btnPreIp);
        presetBar.add(btnPreIds);

        txtEvidenceJson = new JTextArea(4, 20);
        txtEvidenceJson.setBackground(SwingTheme.CARD_BG);
        txtEvidenceJson.setForeground(SwingTheme.ACCENT_CYAN);
        txtEvidenceJson.setCaretColor(Color.WHITE);
        txtEvidenceJson.setFont(SwingTheme.FONT_MONO);
        txtEvidenceJson.setLineWrap(true);
        JScrollPane scrollEvidence = new JScrollPane(txtEvidenceJson);

        btnSubmitNote = new JButton("Submit Forensic Note");
        btnSubmitNote.setBackground(SwingTheme.ACCENT_BLUE);
        btnSubmitNote.setForeground(Color.WHITE);
        btnSubmitNote.setFont(SwingTheme.FONT_BOLD);
        btnSubmitNote.addActionListener(e -> handleSubmitNote());

        formPanel.add(lblNarrative);
        formPanel.add(Box.createVerticalStrut(2));
        formPanel.add(scrollNarrative);
        formPanel.add(Box.createVerticalStrut(4));
        formPanel.add(presetBar);
        formPanel.add(Box.createVerticalStrut(2));
        formPanel.add(scrollEvidence);
        formPanel.add(Box.createVerticalStrut(4));
        formPanel.add(btnSubmitNote);

        JPanel centerSplit = new JPanel(new BorderLayout(0, 6));
        centerSplit.setOpaque(false);
        centerSplit.add(scrollNotes, BorderLayout.CENTER);
        centerSplit.add(formPanel, BorderLayout.SOUTH);

        panel.add(centerSplit, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createWorkflowAndTimelinePanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 8));
        panel.setBackground(SwingTheme.PANEL_BG);
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR),
                BorderFactory.createEmptyBorder(10, 12, 10, 12)
        ));

        // Subheader
        JLabel lblTitle = new JLabel("Forensic Workflow & Chronological Timeline");
        lblTitle.setFont(SwingTheme.FONT_HEADER);
        lblTitle.setForeground(SwingTheme.TEXT_PRIMARY);
        panel.add(lblTitle, BorderLayout.NORTH);

        // Workflow Forms (Assign + Root Cause + Resolution)
        JPanel workflowForms = new JPanel();
        workflowForms.setLayout(new BoxLayout(workflowForms, BoxLayout.Y_AXIS));
        workflowForms.setOpaque(false);

        // 1. Assign Investigator
        JPanel pnlAssign = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        pnlAssign.setOpaque(false);
        JLabel lblAssign = new JLabel("Assign:");
        lblAssign.setFont(SwingTheme.FONT_BOLD);
        lblAssign.setForeground(SwingTheme.TEXT_PRIMARY);
        cmbInvestigators = new JComboBox<>();
        cmbInvestigators.setPreferredSize(new Dimension(140, 24));
        SwingTheme.styleComboBox(cmbInvestigators);

        btnAssign = new JButton("Assign");
        SwingTheme.styleSecondaryButton(btnAssign);
        btnAssign.addActionListener(e -> handleAssignInvestigator());

        pnlAssign.add(lblAssign);
        pnlAssign.add(cmbInvestigators);
        pnlAssign.add(btnAssign);

        // 2. Root Cause
        JPanel pnlRoot = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        pnlRoot.setOpaque(false);
        JLabel lblRoot = new JLabel("Root Cause:");
        lblRoot.setFont(SwingTheme.FONT_BOLD);
        lblRoot.setForeground(SwingTheme.TEXT_PRIMARY);

        cmbRootCauseCategory = new JComboBox<>(new String[]{
                "BRUTE_FORCE", "CREDENTIAL_STUFFING", "MALWARE", "PHISHING",
                "UNAUTHORIZED_ACCESS", "POLICY_VIOLATION", "OTHER"
        });
        cmbRootCauseCategory.setPreferredSize(new Dimension(140, 24));
        SwingTheme.styleComboBox(cmbRootCauseCategory);

        txtRootCauseExplanation = new JTextField(12);
        SwingTheme.styleTextField(txtRootCauseExplanation);

        btnSaveRootCause = new JButton("Save Cause");
        SwingTheme.styleSecondaryButton(btnSaveRootCause);
        btnSaveRootCause.addActionListener(e -> handleSaveRootCause());

        pnlRoot.add(lblRoot);
        pnlRoot.add(cmbRootCauseCategory);
        pnlRoot.add(txtRootCauseExplanation);
        pnlRoot.add(btnSaveRootCause);

        // 3. Resolution
        JPanel pnlResolve = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        pnlResolve.setOpaque(false);
        JLabel lblRes = new JLabel("Resolution:");
        lblRes.setFont(SwingTheme.FONT_BOLD);
        lblRes.setForeground(SwingTheme.TEXT_PRIMARY);

        txtResolutionSummary = new JTextArea(1, 16);
        txtResolutionSummary.setBackground(SwingTheme.CARD_BG);
        txtResolutionSummary.setForeground(SwingTheme.TEXT_PRIMARY);
        txtResolutionSummary.setFont(SwingTheme.FONT_REGULAR);
        JScrollPane scrollRes = new JScrollPane(txtResolutionSummary);
        scrollRes.setPreferredSize(new Dimension(170, 26));

        btnResolve = new JButton("Resolve");
        btnResolve.setBackground(SwingTheme.SEVERITY_LOW);
        btnResolve.setForeground(Color.WHITE);
        btnResolve.setFont(SwingTheme.FONT_BOLD);
        btnResolve.addActionListener(e -> handleResolveCase());

        btnClose = new JButton("Close");
        SwingTheme.styleSecondaryButton(btnClose);
        btnClose.addActionListener(e -> handleCloseCase());

        pnlResolve.add(lblRes);
        pnlResolve.add(scrollRes);
        pnlResolve.add(btnResolve);
        pnlResolve.add(btnClose);

        workflowForms.add(pnlAssign);
        workflowForms.add(pnlRoot);
        workflowForms.add(pnlResolve);

        // Chronological Timeline Table
        String[] timeCols = {"Time", "Event Type", "Event Description"};
        timelineModel = new DefaultTableModel(timeCols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) { return false; }
        };
        timelineTable = new JTable(timelineModel);
        SwingTheme.styleTable(timelineTable);
        timelineTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        JScrollPane scrollTimeline = new JScrollPane(timelineTable);
        scrollTimeline.getViewport().setBackground(SwingTheme.PANEL_BG);
        scrollTimeline.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR),
                "Chronological Case Milestones Timeline",
                0, 0, SwingTheme.FONT_BOLD, SwingTheme.TEXT_PRIMARY
        ));

        JPanel centerPanel = new JPanel(new BorderLayout(0, 6));
        centerPanel.setOpaque(false);
        centerPanel.add(workflowForms, BorderLayout.NORTH);
        centerPanel.add(scrollTimeline, BorderLayout.CENTER);

        panel.add(centerPanel, BorderLayout.CENTER);
        return panel;
    }

    public void refresh() {
        loadIncidentsList();
        if (currentIncidentId != null) {
            loadInvestigationData(currentIncidentId, false);
        }
    }

    private void loadIncidentsList() {
        new SwingWorker<List<Incident>, Void>() {
            @Override
            protected List<Incident> doInBackground() {
                return apiClient.getIncidents(null, null, null);
            }

            @Override
            protected void done() {
                try {
                    List<Incident> list = get();
                    cmbIncidents.removeAllItems();

                    if (list != null) {
                        for (Incident inc : list) {
                            cmbIncidents.addItem(new IncidentItem(inc.getId(), inc.getTitle(), inc.getSeverity(), inc.getStatus()));
                        }
                    }

                    // Also refresh investigators
                    loadInvestigatorsList();
                } catch (Exception ignored) {}
            }
        }.execute();
    }

    private void loadInvestigatorsList() {
        new SwingWorker<List<User>, Void>() {
            @Override
            protected List<User> doInBackground() {
                return apiClient.getAssignableInvestigators();
            }

            @Override
            protected void done() {
                try {
                    List<User> investigators = get();
                    cmbInvestigators.removeAllItems();
                    if (investigators != null) {
                        for (User u : investigators) {
                            cmbInvestigators.addItem(u.getUsername());
                        }
                    }
                } catch (Exception ignored) {}
            }
        }.execute();
    }

    private void loadInvestigationData(int incidentId, boolean isBackground) {
        new SwingWorker<InvestigationPackage, Void>() {
            @Override
            protected InvestigationPackage doInBackground() {
                InvestigationSummary summary = apiClient.getInvestigationSummary(incidentId);
                List<InvestigationNote> notes = apiClient.getInvestigationNotes(incidentId);
                List<InvestigationTimelineItem> timeline = apiClient.getInvestigationTimeline(incidentId);
                return new InvestigationPackage(summary, notes, timeline);
            }

            @Override
            protected void done() {
                try {
                    InvestigationPackage pkg = get();
                    if (pkg.summary != null) {
                        lblDossierId.setText("#" + pkg.summary.getIncidentId());
                        lblDossierTitle.setText(pkg.summary.getTitle());
                        lblDossierSeverity.setText("SEVERITY: " + pkg.summary.getSeverity());
                        lblDossierSeverity.setForeground(SwingTheme.getSeverityColor(pkg.summary.getSeverity()));
                        lblDossierStatus.setText("STATUS: " + pkg.summary.getStatus());
                        lblDossierStatus.setForeground(SwingTheme.getStatusColor(pkg.summary.getStatus()));

                        String assigned = pkg.summary.getAssignedInvestigator();
                        lblDossierAssigned.setText("Assigned: " + (assigned != null ? assigned : "Unassigned"));
                        lblDossierRootCause.setText("Root Cause: " + (pkg.summary.getRootCauseCategory() != null ? pkg.summary.getRootCauseCategory() : "Pending"));
                        lblDossierNotesCount.setText("Forensic Notes: " + pkg.summary.getTotalInvestigationNotes());

                        if (pkg.summary.getResolutionSummary() != null && !pkg.summary.getResolutionSummary().trim().isEmpty()) {
                            lblDossierResolution.setText("Resolution: " + pkg.summary.getResolutionSummary());
                            lblDossierResolution.setForeground(SwingTheme.SEVERITY_LOW);
                        } else {
                            lblDossierResolution.setText("Resolution: Active Investigation");
                            lblDossierResolution.setForeground(SwingTheme.TEXT_SECONDARY);
                        }

                        if (assigned != null) {
                            cmbInvestigators.setSelectedItem(assigned);
                        }
                        if (pkg.summary.getRootCauseCategory() != null) {
                            cmbRootCauseCategory.setSelectedItem(pkg.summary.getRootCauseCategory());
                        }
                    }

                    // Notes
                    notesModel.setRowCount(0);
                    if (pkg.notes != null) {
                        for (InvestigationNote n : pkg.notes) {
                            notesModel.addRow(new Object[]{
                                    n.getId(),
                                    n.getAnalystUsername(),
                                    dateFormat.format(new Date(n.getCreatedAt())),
                                    n.getNotes(),
                                    n.getEvidenceData() != null ? "Yes (" + n.getEvidenceData().length() + " bytes)" : "No"
                            });
                        }
                    }

                    // Timeline
                    timelineModel.setRowCount(0);
                    if (pkg.timeline != null) {
                        for (InvestigationTimelineItem item : pkg.timeline) {
                            timelineModel.addRow(new Object[]{
                                    dateFormat.format(new Date(item.getTimestamp())),
                                    item.getEventType(),
                                    (item.getActor() != null ? "[" + item.getActor() + "] " : "") + item.getDescription() + (item.getDetails() != null ? " (" + item.getDetails() + ")" : "")
                            });
                        }
                    }
                } catch (Exception ex) {
                    if (!isBackground) {
                        JOptionPane.showMessageDialog(InvestigationPanel.this, "Failed to load case data: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                    }
                }
            }
        }.execute();
    }

    private void handleSubmitNote() {
        if (currentIncidentId == null) return;

        String narrative = txtNoteNarrative.getText().trim();
        String evidence = txtEvidenceJson.getText().trim();

        if (narrative.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please write an analyst narrative for this forensic note.", "Validation Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        if (!evidence.isEmpty()) {
            try {
                JsonElement elem = JsonParser.parseString(evidence);
                if (!elem.isJsonObject()) {
                    JOptionPane.showMessageDialog(this, "Structured evidence must be a valid JSON object {...}", "JSON Syntax Error", JOptionPane.WARNING_MESSAGE);
                    return;
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Invalid JSON in evidence box:\n" + ex.getMessage(), "JSON Syntax Error", JOptionPane.WARNING_MESSAGE);
                return;
            }
        }

        try {
            apiClient.addInvestigationNote(currentIncidentId, narrative, evidence.isEmpty() ? null : evidence);
            JOptionPane.showMessageDialog(this, "Forensic note successfully archived to case dossier.", "Note Saved", JOptionPane.INFORMATION_MESSAGE);
            txtNoteNarrative.setText("");
            txtEvidenceJson.setText("");
            loadInvestigationData(currentIncidentId, false);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Failed to save note: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void handleAssignInvestigator() {
        if (currentIncidentId == null) return;
        if (!apiClient.isAdmin()) {
            JOptionPane.showMessageDialog(this, "Permission Denied: Only Administrator role can assign investigators.", "RBAC Gating", JOptionPane.ERROR_MESSAGE);
            return;
        }

        String analyst = (String) cmbInvestigators.getSelectedItem();
        if (analyst == null || analyst.trim().isEmpty()) {
            JOptionPane.showMessageDialog(this, "Select an investigator to assign.", "Notice", JOptionPane.WARNING_MESSAGE);
            return;
        }

        try {
            apiClient.assignInvestigator(currentIncidentId, analyst);
            JOptionPane.showMessageDialog(this, "Case #" + currentIncidentId + " assigned to " + analyst + ".", "Assigned", JOptionPane.INFORMATION_MESSAGE);
            loadInvestigationData(currentIncidentId, false);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Assignment failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void handleSaveRootCause() {
        if (currentIncidentId == null) return;

        String category = (String) cmbRootCauseCategory.getSelectedItem();
        String explanation = txtRootCauseExplanation.getText().trim();

        if (explanation.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please provide an explanation for the root cause determination.", "Validation Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        try {
            apiClient.updateRootCause(currentIncidentId, category, explanation);
            JOptionPane.showMessageDialog(this, "Root cause analysis recorded. Status moved to INVESTIGATING.", "Root Cause Saved", JOptionPane.INFORMATION_MESSAGE);
            loadInvestigationData(currentIncidentId, false);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Failed to save root cause: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void handleResolveCase() {
        if (currentIncidentId == null) return;

        String summary = txtResolutionSummary.getText().trim();
        if (summary.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please write a resolution summary before marking the case resolved.", "Validation Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        try {
            apiClient.resolveIncident(currentIncidentId, summary);
            JOptionPane.showMessageDialog(this, "Incident #" + currentIncidentId + " has been marked RESOLVED.", "Case Resolved", JOptionPane.INFORMATION_MESSAGE);
            txtResolutionSummary.setText("");
            loadInvestigationData(currentIncidentId, false);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Failed to resolve case: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void handleCloseCase() {
        if (currentIncidentId == null) return;

        int confirm = JOptionPane.showConfirmDialog(this, "Mark Incident #" + currentIncidentId + " as CLOSED?", "Confirm Close", JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            try {
                Incident current = apiClient.getIncidentById(currentIncidentId);
                if (current != null) {
                    current.setStatus("CLOSED");
                    apiClient.updateIncident(currentIncidentId, current);
                    JOptionPane.showMessageDialog(this, "Incident #" + currentIncidentId + " is now CLOSED.", "Case Closed", JOptionPane.INFORMATION_MESSAGE);
                    loadInvestigationData(currentIncidentId, false);
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Failed to close incident: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void handleInspectEvidence() {
        int row = notesTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "Please select an investigation note row from the table.", "Selection Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        int noteId = (Integer) notesModel.getValueAt(row, 0);
        if (currentIncidentId != null) {
            List<InvestigationNote> notes = apiClient.getInvestigationNotes(currentIncidentId);
            for (InvestigationNote n : notes) {
                if (n.getId() == noteId) {
                    String ev = n.getEvidenceData();
                    if (ev == null || ev.trim().isEmpty()) {
                        JOptionPane.showMessageDialog(this, "Note #" + noteId + " does not have structured JSON evidence attached.", "Notice", JOptionPane.INFORMATION_MESSAGE);
                        return;
                    }

                    String formatted;
                    try {
                        JsonElement elem = JsonParser.parseString(ev);
                        formatted = prettyGson.toJson(elem);
                    } catch (Exception e) {
                        formatted = ev;
                    }

                    JTextArea ta = new JTextArea(formatted, 16, 45);
                    ta.setEditable(false);
                    ta.setFont(SwingTheme.FONT_MONO);
                    JOptionPane.showMessageDialog(this, new JScrollPane(ta), "Forensic Evidence - Note #" + noteId, JOptionPane.INFORMATION_MESSAGE);
                    return;
                }
            }
        }
    }

    private static class IncidentItem {
        final int id;
        final String title;
        final String severity;
        final String status;

        IncidentItem(int id, String title, String severity, String status) {
            this.id = id;
            this.title = title;
            this.severity = severity;
            this.status = status;
        }

        @Override
        public String toString() {
            return "#" + id + " [" + severity + "] " + title + " (" + status + ")";
        }
    }

    private static class InvestigationPackage {
        final InvestigationSummary summary;
        final List<InvestigationNote> notes;
        final List<InvestigationTimelineItem> timeline;

        InvestigationPackage(InvestigationSummary summary, List<InvestigationNote> notes, List<InvestigationTimelineItem> timeline) {
            this.summary = summary;
            this.notes = notes;
            this.timeline = timeline;
        }
    }
}
