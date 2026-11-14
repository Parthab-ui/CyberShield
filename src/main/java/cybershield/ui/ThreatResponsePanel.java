package cybershield.ui;

import cybershield.model.BlockedIp;
import cybershield.model.ThreatResponse;
import cybershield.model.ThreatResponseStats;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

/**
 * ThreatResponsePanel — SOC Console panel for Automated Threat Response,
 * active application-level IP blocking, and execution audit history.
 */
public class ThreatResponsePanel extends JPanel {

    private final ApiClient apiClient = ApiClient.getInstance();
    private final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    // KPI labels
    private JLabel lblTotalActions;
    private JLabel lblExecuted;
    private JLabel lblSkipped;
    private JLabel lblFailed;
    private JLabel lblActiveBlocks;

    // Blocked IPs table & components
    private JComboBox<String> cmbBlockedStatus;
    private DefaultTableModel blockedIpsModel;
    private JTable blockedIpsTable;
    private JButton btnUnblockSelected;

    // Manual Block Form
    private JTextField txtBlockIp;
    private JTextField txtBlockReason;
    private JSpinner spnrBlockDuration;
    private JButton btnBlockIp;

    // Threat Responses Table & components
    private JTextField txtFilterThreatIp;
    private JComboBox<String> cmbFilterThreatStatus;
    private DefaultTableModel responsesModel;
    private JTable responsesTable;
    private JButton btnViewDetails;

    private Timer refreshTimer;

    public ThreatResponsePanel() {
        setBackground(SwingTheme.BG_DARK);
        setLayout(new BorderLayout(0, 12));
        setBorder(BorderFactory.createEmptyBorder(16, 20, 16, 20));

        add(createHeaderBar(), BorderLayout.NORTH);

        JPanel mainContent = new JPanel();
        mainContent.setLayout(new BoxLayout(mainContent, BoxLayout.Y_AXIS));
        mainContent.setOpaque(false);

        mainContent.add(createKpiPanel());
        mainContent.add(Box.createVerticalStrut(12));

        // Split pane: Top = Firewall Blocks & Manual Block; Bottom = Response History
        JPanel topSection = createFirewallSection();
        JPanel bottomSection = createResponseHistorySection();

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, topSection, bottomSection);
        splitPane.setResizeWeight(0.45);
        splitPane.setDividerSize(6);
        splitPane.setOpaque(false);
        splitPane.setBorder(null);

        mainContent.add(splitPane);
        add(mainContent, BorderLayout.CENTER);

        // Auto-refresh every 5 seconds
        refreshTimer = new Timer(5000, e -> {
            if (isShowing()) {
                refreshData();
            }
        });
        refreshTimer.start();

        // Initial load
        refreshData();
    }

    private JPanel createHeaderBar() {
        JPanel header = new JPanel(new BorderLayout());
        header.setOpaque(false);

        JPanel textPanel = new JPanel();
        textPanel.setLayout(new BoxLayout(textPanel, BoxLayout.Y_AXIS));
        textPanel.setOpaque(false);

        JLabel title = new JLabel("Automated Threat Response Center");
        title.setFont(SwingTheme.FONT_TITLE);
        title.setForeground(SwingTheme.TEXT_PRIMARY);

        JLabel sub = new JLabel("Application Firewall, Automated Containment Actions & Active Threat Mitigation");
        sub.setFont(SwingTheme.FONT_SMALL);
        sub.setForeground(SwingTheme.TEXT_SECONDARY);

        textPanel.add(title);
        textPanel.add(Box.createVerticalStrut(2));
        textPanel.add(sub);

        JButton btnRefresh = new JButton("Refresh Now");
        SwingTheme.styleSecondaryButton(btnRefresh);
        btnRefresh.addActionListener(e -> refreshData());

        header.add(textPanel, BorderLayout.WEST);
        header.add(btnRefresh, BorderLayout.EAST);
        return header;
    }

    private JPanel createKpiPanel() {
        JPanel kpi = new JPanel(new GridLayout(1, 5, 10, 0));
        kpi.setOpaque(false);
        kpi.setMaximumSize(new Dimension(Integer.MAX_VALUE, 65));

        lblTotalActions = new JLabel("0", SwingConstants.CENTER);
        lblExecuted = new JLabel("0", SwingConstants.CENTER);
        lblSkipped = new JLabel("0", SwingConstants.CENTER);
        lblFailed = new JLabel("0", SwingConstants.CENTER);
        lblActiveBlocks = new JLabel("0", SwingConstants.CENTER);

        kpi.add(createMiniCard("TOTAL ACTIONS", lblTotalActions, SwingTheme.TEXT_PRIMARY));
        kpi.add(createMiniCard("EXECUTED", lblExecuted, SwingTheme.SEVERITY_LOW));
        kpi.add(createMiniCard("SKIPPED (WHITELIST)", lblSkipped, SwingTheme.SEVERITY_MEDIUM));
        kpi.add(createMiniCard("FAILED", lblFailed, SwingTheme.SEVERITY_CRITICAL));
        kpi.add(createMiniCard("ACTIVE BLOCKED IPS", lblActiveBlocks, SwingTheme.STATUS_INVESTIGATING));
        return kpi;
    }

    private JPanel createMiniCard(String title, JLabel valLabel, Color valColor) {
        JPanel card = new JPanel(new BorderLayout(0, 2));
        card.setBackground(SwingTheme.PANEL_BG);
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR),
                BorderFactory.createEmptyBorder(6, 8, 6, 8)
        ));

        JLabel lblTitle = new JLabel(title, SwingConstants.CENTER);
        lblTitle.setFont(SwingTheme.FONT_SMALL);
        lblTitle.setForeground(SwingTheme.TEXT_SECONDARY);

        valLabel.setFont(SwingTheme.FONT_HEADER);
        valLabel.setForeground(valColor);

        card.add(lblTitle, BorderLayout.NORTH);
        card.add(valLabel, BorderLayout.CENTER);
        return card;
    }

    private JPanel createFirewallSection() {
        JPanel panel = new JPanel(new BorderLayout(0, 8));
        panel.setBackground(SwingTheme.PANEL_BG);
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR),
                BorderFactory.createEmptyBorder(10, 12, 10, 12)
        ));

        // Subheader + Status filter
        JPanel topBar = new JPanel(new BorderLayout());
        topBar.setOpaque(false);

        JLabel lblTitle = new JLabel("Application Firewall (Blocked IPs)");
        lblTitle.setFont(SwingTheme.FONT_HEADER);
        lblTitle.setForeground(SwingTheme.TEXT_PRIMARY);

        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        filterPanel.setOpaque(false);

        JLabel lblFilter = new JLabel("Status Filter:");
        lblFilter.setFont(SwingTheme.FONT_SMALL);
        lblFilter.setForeground(SwingTheme.TEXT_SECONDARY);

        cmbBlockedStatus = new JComboBox<>(new String[]{"ALL", "ACTIVE", "EXPIRED", "UNBLOCKED"});
        SwingTheme.styleComboBox(cmbBlockedStatus);
        cmbBlockedStatus.setSelectedItem("ACTIVE");
        cmbBlockedStatus.addActionListener(e -> refreshBlockedIps());

        filterPanel.add(lblFilter);
        filterPanel.add(cmbBlockedStatus);

        topBar.add(lblTitle, BorderLayout.WEST);
        topBar.add(filterPanel, BorderLayout.EAST);
        panel.add(topBar, BorderLayout.NORTH);

        // Blocked IPs Table
        String[] cols = {"IP Address", "Block Reason", "Blocked At", "Expires At", "Status", "Blocked By"};
        blockedIpsModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) { return false; }
        };
        blockedIpsTable = new JTable(blockedIpsModel);
        SwingTheme.styleTable(blockedIpsTable);
        blockedIpsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        JScrollPane scroll = new JScrollPane(blockedIpsTable);
        scroll.getViewport().setBackground(SwingTheme.PANEL_BG);
        scroll.setBorder(BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR));
        panel.add(scroll, BorderLayout.CENTER);

        // Manual Block Action Form at Bottom
        JPanel bottomBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        bottomBar.setOpaque(false);

        JLabel lblIp = new JLabel("IP:");
        lblIp.setFont(SwingTheme.FONT_BOLD);
        lblIp.setForeground(SwingTheme.TEXT_PRIMARY);
        txtBlockIp = new JTextField(10);
        SwingTheme.styleTextField(txtBlockIp);

        JLabel lblReason = new JLabel("Reason:");
        lblReason.setFont(SwingTheme.FONT_BOLD);
        lblReason.setForeground(SwingTheme.TEXT_PRIMARY);
        txtBlockReason = new JTextField(14);
        SwingTheme.styleTextField(txtBlockReason);
        txtBlockReason.setText("Manual SOC block");

        JLabel lblDur = new JLabel("Duration (mins):");
        lblDur.setFont(SwingTheme.FONT_BOLD);
        lblDur.setForeground(SwingTheme.TEXT_PRIMARY);
        spnrBlockDuration = new JSpinner(new SpinnerNumberModel(60, 1, 10080, 15));
        spnrBlockDuration.setPreferredSize(new Dimension(65, 26));

        btnBlockIp = new JButton("Block IP");
        btnBlockIp.setBackground(SwingTheme.SEVERITY_CRITICAL);
        btnBlockIp.setForeground(Color.WHITE);
        btnBlockIp.setFont(SwingTheme.FONT_BOLD);
        btnBlockIp.addActionListener(e -> handleManualBlock());

        btnUnblockSelected = new JButton("Unblock Selected");
        SwingTheme.styleSecondaryButton(btnUnblockSelected);
        btnUnblockSelected.addActionListener(e -> handleUnblockSelected());

        bottomBar.add(lblIp);
        bottomBar.add(txtBlockIp);
        bottomBar.add(lblReason);
        bottomBar.add(txtBlockReason);
        bottomBar.add(lblDur);
        bottomBar.add(spnrBlockDuration);
        bottomBar.add(btnBlockIp);
        bottomBar.add(Box.createHorizontalStrut(10));
        bottomBar.add(btnUnblockSelected);

        panel.add(bottomBar, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel createResponseHistorySection() {
        JPanel panel = new JPanel(new BorderLayout(0, 8));
        panel.setBackground(SwingTheme.PANEL_BG);
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR),
                BorderFactory.createEmptyBorder(10, 12, 10, 12)
        ));

        JPanel topBar = new JPanel(new BorderLayout());
        topBar.setOpaque(false);

        JLabel lblTitle = new JLabel("Automated Mitigation & Threat Response Log");
        lblTitle.setFont(SwingTheme.FONT_HEADER);
        lblTitle.setForeground(SwingTheme.TEXT_PRIMARY);

        JPanel filters = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        filters.setOpaque(false);

        JLabel lblFilterIp = new JLabel("IP Search:");
        lblFilterIp.setFont(SwingTheme.FONT_SMALL);
        lblFilterIp.setForeground(SwingTheme.TEXT_SECONDARY);

        txtFilterThreatIp = new JTextField(9);
        SwingTheme.styleTextField(txtFilterThreatIp);
        txtFilterThreatIp.addActionListener(e -> refreshResponses());

        JLabel lblFilterStat = new JLabel("Status:");
        lblFilterStat.setFont(SwingTheme.FONT_SMALL);
        lblFilterStat.setForeground(SwingTheme.TEXT_SECONDARY);

        cmbFilterThreatStatus = new JComboBox<>(new String[]{"ALL", "EXECUTED", "FAILED", "SKIPPED_WHITELIST", "ALREADY_ACTIVE"});
        SwingTheme.styleComboBox(cmbFilterThreatStatus);
        cmbFilterThreatStatus.addActionListener(e -> refreshResponses());

        btnViewDetails = new JButton("View Payload Details");
        SwingTheme.styleSecondaryButton(btnViewDetails);
        btnViewDetails.addActionListener(e -> handleViewResponseDetails());

        filters.add(lblFilterIp);
        filters.add(txtFilterThreatIp);
        filters.add(lblFilterStat);
        filters.add(cmbFilterThreatStatus);
        filters.add(btnViewDetails);

        topBar.add(lblTitle, BorderLayout.WEST);
        topBar.add(filters, BorderLayout.EAST);
        panel.add(topBar, BorderLayout.NORTH);

        String[] cols = {"ID", "Incident #", "Threat Type", "Action Taken", "Target", "Status", "Execution Time", "Details"};
        responsesModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) { return false; }
        };
        responsesTable = new JTable(responsesModel);
        SwingTheme.styleTable(responsesTable);
        responsesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        JScrollPane scroll = new JScrollPane(responsesTable);
        scroll.getViewport().setBackground(SwingTheme.PANEL_BG);
        scroll.setBorder(BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR));
        panel.add(scroll, BorderLayout.CENTER);

        return panel;
    }

    public void refresh() {
        refreshData();
    }

    private void refreshData() {
        refreshStats();
        refreshBlockedIps();
        refreshResponses();
    }

    private void refreshStats() {
        new SwingWorker<ThreatResponseStats, Void>() {
            @Override
            protected ThreatResponseStats doInBackground() {
                return apiClient.getThreatResponseStats();
            }

            @Override
            protected void done() {
                try {
                    ThreatResponseStats stats = get();
                    if (stats != null) {
                        lblTotalActions.setText(String.valueOf(stats.getTotalResponses()));
                        lblExecuted.setText(String.valueOf(stats.getSuccessfulBlocks()));
                        lblSkipped.setText(String.valueOf(stats.getSkippedResponses()));
                        lblFailed.setText(String.valueOf(stats.getFailedResponses()));
                    }
                } catch (Exception ignored) {}
            }
        }.execute();
    }

    private void refreshBlockedIps() {
        final String status = (String) cmbBlockedStatus.getSelectedItem();

        new SwingWorker<List<BlockedIp>, Void>() {
            @Override
            protected List<BlockedIp> doInBackground() {
                return apiClient.getBlockedIps(status);
            }

            @Override
            protected void done() {
                try {
                    List<BlockedIp> list = get();
                    blockedIpsModel.setRowCount(0);
                    int activeCount = 0;

                    if (list != null) {
                        for (BlockedIp b : list) {
                            if ("ACTIVE".equalsIgnoreCase(b.getStatus())) {
                                activeCount++;
                            }
                            blockedIpsModel.addRow(new Object[]{
                                    b.getIpAddress(),
                                    b.getReason(),
                                    b.getBlockedAt() > 0 ? dateFormat.format(new Date(b.getBlockedAt())) : "N/A",
                                    b.getExpiresAt() > 0 ? dateFormat.format(new Date(b.getExpiresAt())) : "Permanent",
                                    b.getStatus(),
                                    b.getBlockedBy() != null ? b.getBlockedBy() : "system"
                            });
                        }
                    }
                    lblActiveBlocks.setText(String.valueOf(activeCount));
                } catch (Exception ignored) {}
            }
        }.execute();
    }

    private void refreshResponses() {
        final String ip = txtFilterThreatIp.getText().trim();
        final String status = (String) cmbFilterThreatStatus.getSelectedItem();

        new SwingWorker<List<ThreatResponse>, Void>() {
            @Override
            protected List<ThreatResponse> doInBackground() {
                String filterStatus = "ALL".equalsIgnoreCase(status) ? null : status;
                String filterIp = ip.isEmpty() ? null : ip;
                return apiClient.getThreatResponses(null, filterIp, filterStatus);
            }

            @Override
            protected void done() {
                try {
                    List<ThreatResponse> list = get();
                    responsesModel.setRowCount(0);
                    if (list != null) {
                        for (ThreatResponse tr : list) {
                            responsesModel.addRow(new Object[]{
                                    tr.getId(),
                                    tr.getIncidentId() != null ? "#" + tr.getIncidentId() : "—",
                                    tr.getThreatType(),
                                    tr.getActionTaken(),
                                    tr.getTargetIdentifier(),
                                    tr.getStatus(),
                                    tr.getExecutedAt() > 0 ? dateFormat.format(new Date(tr.getExecutedAt())) : "N/A",
                                    tr.getDetails() != null ? tr.getDetails() : "Success"
                            });
                        }
                    }
                } catch (Exception ignored) {}
            }
        }.execute();
    }

    private void handleManualBlock() {
        if (!apiClient.isAdmin()) {
            JOptionPane.showMessageDialog(this, "Permission Denied: Only Administrator role can block IP addresses.", "RBAC Gating", JOptionPane.ERROR_MESSAGE);
            return;
        }

        String ip = txtBlockIp.getText().trim();
        String reason = txtBlockReason.getText().trim();
        int duration = (Integer) spnrBlockDuration.getValue();

        if (ip.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter an IP address to block.", "Validation Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        try {
            apiClient.blockIp(ip, reason, duration);
            JOptionPane.showMessageDialog(this, "IP " + ip + " has been successfully blocked for " + duration + " minutes.", "Firewall Rule Activated", JOptionPane.INFORMATION_MESSAGE);
            txtBlockIp.setText("");
            refreshData();
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Failed to block IP: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void handleUnblockSelected() {
        if (!apiClient.isAdmin()) {
            JOptionPane.showMessageDialog(this, "Permission Denied: Only Administrator role can unblock IP addresses.", "RBAC Gating", JOptionPane.ERROR_MESSAGE);
            return;
        }

        int row = blockedIpsTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "Please select an IP row from the table to unblock.", "Selection Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String ip = (String) blockedIpsModel.getValueAt(row, 0);
        int confirm = JOptionPane.showConfirmDialog(this, "Are you sure you want to lift the block on " + ip + "?", "Confirm Unblock", JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            try {
                boolean success = apiClient.unblockIp(ip);
                if (success) {
                    JOptionPane.showMessageDialog(this, "IP " + ip + " has been unblocked.", "Success", JOptionPane.INFORMATION_MESSAGE);
                    refreshData();
                } else {
                    JOptionPane.showMessageDialog(this, "Could not unblock IP (no active block found).", "Notice", JOptionPane.WARNING_MESSAGE);
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Error unblocking IP: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void handleViewResponseDetails() {
        int row = responsesTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "Please select a response row from the table.", "Selection Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        int id = (Integer) responsesModel.getValueAt(row, 0);
        new SwingWorker<ThreatResponse, Void>() {
            @Override
            protected ThreatResponse doInBackground() {
                List<ThreatResponse> list = apiClient.getThreatResponses(null, null, null);
                for (ThreatResponse r : list) {
                    if (r.getId() == id) return r;
                }
                return null;
            }

            @Override
            protected void done() {
                try {
                    ThreatResponse tr = get();
                    if (tr != null) {
                        StringBuilder sb = new StringBuilder();
                        sb.append("Action ID: #").append(tr.getId()).append("\n");
                        sb.append("Incident ID: ").append(tr.getIncidentId() != null ? "#" + tr.getIncidentId() : "None").append("\n");
                        sb.append("Threat Type: ").append(tr.getThreatType()).append("\n");
                        sb.append("Action Taken: ").append(tr.getActionTaken()).append("\n");
                        sb.append("Target: ").append(tr.getTargetIdentifier()).append("\n");
                        sb.append("Status: ").append(tr.getStatus()).append("\n");
                        sb.append("Execution Time: ").append(dateFormat.format(new Date(tr.getExecutedAt()))).append("\n");
                        sb.append("Details / Payload:\n").append(tr.getDetails() != null ? tr.getDetails() : "{}");

                        JTextArea ta = new JTextArea(sb.toString(), 14, 45);
                        ta.setEditable(false);
                        ta.setFont(SwingTheme.FONT_MONO);
                        JOptionPane.showMessageDialog(ThreatResponsePanel.this, new JScrollPane(ta), "Threat Response Details #" + tr.getId(), JOptionPane.INFORMATION_MESSAGE);
                    }
                } catch (Exception ignored) {}
            }
        }.execute();
    }
}
