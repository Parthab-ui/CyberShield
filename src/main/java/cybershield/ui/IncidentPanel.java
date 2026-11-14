package cybershield.ui;

import cybershield.model.Incident;
import cybershield.model.User;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import java.awt.*;
import java.util.List;

/**
 * IncidentPanel — Desktop incident management panel.
 * Demonstrates:
 * - JTable with DefaultTableModel for displaying tabular security records.
 * - Custom TableCellRenderer for color-coded severity & status badges.
 * - Filtering with JTextField search box and JComboBox dropdowns.
 * - Modal JDialog for Create and Update operations.
 * - Role-based authorization enforcement (Admin-only deletion check).
 * - JOptionPane confirmation dialogs before deletion.
 */
public class IncidentPanel extends JPanel {

    private final ApiClient apiClient;

    // Table components
    private JTable incidentTable;
    private DefaultTableModel tableModel;

    // Filter controls
    private JTextField searchField;
    private JComboBox<String> severityCombo;
    private JComboBox<String> statusCombo;
    private JButton refreshButton;

    // Action buttons
    private JButton addButton;
    private JButton editButton;
    private JButton deleteButton;

    // Cached list of loaded incidents
    private List<Incident> currentIncidents;

    public IncidentPanel() {
        this.apiClient = ApiClient.getInstance();
        setLayout(new BorderLayout(0, 14));
        setBackground(SwingTheme.PANEL_BG);
        setBorder(BorderFactory.createEmptyBorder(18, 20, 18, 20));

        initComponents();
        loadIncidents();
    }

    /**
     * Initializes all UI components and arranges them using BorderLayout.
     */
    private void initComponents() {
        // TOP: Header title + Filter toolbar
        JPanel topContainer = new JPanel(new BorderLayout(0, 12));
        topContainer.setOpaque(false);

        // Header title
        JPanel titlePanel = new JPanel(new BorderLayout());
        titlePanel.setOpaque(false);
        JLabel titleLabel = new JLabel("Security Incident Management");
        titleLabel.setFont(SwingTheme.FONT_TITLE);
        titleLabel.setForeground(SwingTheme.TEXT_PRIMARY);

        JLabel subtitleLabel = new JLabel("Log, categorize, track, and triage detected cybersecurity incidents");
        subtitleLabel.setFont(SwingTheme.FONT_BODY);
        subtitleLabel.setForeground(SwingTheme.TEXT_MUTED);

        titlePanel.add(titleLabel, BorderLayout.NORTH);
        titlePanel.add(subtitleLabel, BorderLayout.SOUTH);
        topContainer.add(titlePanel, BorderLayout.NORTH);

        // Filter bar panel (FlowLayout)
        JPanel filterBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        filterBar.setOpaque(false);

        JLabel searchLabel = new JLabel("Search:");
        searchLabel.setFont(SwingTheme.FONT_BOLD);
        searchLabel.setForeground(SwingTheme.TEXT_PRIMARY);

        searchField = new JTextField(14);
        SwingTheme.styleTextField(searchField);
        searchField.setToolTipText("Search incidents by title or description");
        searchField.addActionListener(e -> loadIncidents());

        JLabel sevLabel = new JLabel("Severity:");
        sevLabel.setFont(SwingTheme.FONT_BOLD);
        sevLabel.setForeground(SwingTheme.TEXT_PRIMARY);

        severityCombo = new JComboBox<>(new String[]{"ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"});
        SwingTheme.styleComboBox(severityCombo);
        severityCombo.addActionListener(e -> loadIncidents());

        JLabel statLabel = new JLabel("Status:");
        statLabel.setFont(SwingTheme.FONT_BOLD);
        statLabel.setForeground(SwingTheme.TEXT_PRIMARY);

        statusCombo = new JComboBox<>(new String[]{"ALL", "OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"});
        SwingTheme.styleComboBox(statusCombo);
        statusCombo.addActionListener(e -> loadIncidents());

        refreshButton = new JButton("Filter / Refresh");
        SwingTheme.styleSecondaryButton(refreshButton);
        refreshButton.addActionListener(e -> loadIncidents());

        filterBar.add(searchLabel);
        filterBar.add(searchField);
        filterBar.add(sevLabel);
        filterBar.add(severityCombo);
        filterBar.add(statLabel);
        filterBar.add(statusCombo);
        filterBar.add(refreshButton);

        topContainer.add(filterBar, BorderLayout.SOUTH);
        add(topContainer, BorderLayout.NORTH);

        // CENTER: JTable inside JScrollPane
        String[] columnNames = {"ID", "Title", "Severity", "Status", "Reported By", "Created At"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false; // Make table cells read-only; editing is done via dialog
            }
        };

        incidentTable = new JTable(tableModel);
        incidentTable.setBackground(SwingTheme.CARD_BG);
        incidentTable.setForeground(SwingTheme.TEXT_PRIMARY);
        incidentTable.setSelectionBackground(SwingTheme.PRIMARY_COLOR);
        incidentTable.setSelectionForeground(Color.WHITE);
        incidentTable.setRowHeight(32);
        incidentTable.setFont(SwingTheme.FONT_BODY);
        incidentTable.setShowGrid(true);
        incidentTable.setGridColor(SwingTheme.BORDER_COLOR);
        incidentTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // Column widths
        incidentTable.getColumnModel().getColumn(0).setPreferredWidth(50);
        incidentTable.getColumnModel().getColumn(1).setPreferredWidth(260);
        incidentTable.getColumnModel().getColumn(2).setPreferredWidth(100);
        incidentTable.getColumnModel().getColumn(3).setPreferredWidth(110);
        incidentTable.getColumnModel().getColumn(4).setPreferredWidth(120);
        incidentTable.getColumnModel().getColumn(5).setPreferredWidth(160);

        // Custom cell renderer for centered alignment and badges
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(SwingConstants.CENTER);
        incidentTable.getColumnModel().getColumn(0).setCellRenderer(centerRenderer);
        incidentTable.getColumnModel().getColumn(4).setCellRenderer(centerRenderer);
        incidentTable.getColumnModel().getColumn(5).setCellRenderer(centerRenderer);

        // Custom renderer for Severity column
        incidentTable.getColumnModel().getColumn(2).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
                setHorizontalAlignment(SwingConstants.CENTER);
                setFont(SwingTheme.FONT_BOLD);
                String sev = value != null ? value.toString() : "";
                if (!isSelected) {
                    c.setBackground(SwingTheme.CARD_BG);
                    c.setForeground(SwingTheme.getSeverityColor(sev));
                }
                return c;
            }
        });

        // Custom renderer for Status column
        incidentTable.getColumnModel().getColumn(3).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
                setHorizontalAlignment(SwingConstants.CENTER);
                setFont(SwingTheme.FONT_BOLD);
                String st = value != null ? value.toString() : "";
                if (!isSelected) {
                    c.setBackground(SwingTheme.CARD_BG);
                    c.setForeground(SwingTheme.getStatusColor(st));
                }
                return c;
            }
        });

        // Style table header
        JTableHeader header = incidentTable.getTableHeader();
        header.setBackground(SwingTheme.BG_COLOR);
        header.setForeground(SwingTheme.TEXT_PRIMARY);
        header.setFont(SwingTheme.FONT_BOLD);
        header.setBorder(BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR));

        JScrollPane scrollPane = new JScrollPane(incidentTable);
        scrollPane.setBorder(BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR));
        scrollPane.getViewport().setBackground(SwingTheme.CARD_BG);
        add(scrollPane, BorderLayout.CENTER);

        // BOTTOM: Action buttons panel
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 12, 6));
        bottomPanel.setOpaque(false);

        addButton = new JButton("+ New Incident");
        SwingTheme.stylePrimaryButton(addButton);
        addButton.addActionListener(e -> showAddIncidentDialog());

        editButton = new JButton("Edit Selected");
        SwingTheme.styleSecondaryButton(editButton);
        editButton.addActionListener(e -> showEditIncidentDialog());

        deleteButton = new JButton("Delete Incident");
        deleteButton.setBackground(SwingTheme.SEVERITY_CRITICAL);
        deleteButton.setForeground(Color.WHITE);
        deleteButton.setFont(SwingTheme.FONT_BOLD);
        deleteButton.setFocusPainted(false);
        deleteButton.setBorder(BorderFactory.createEmptyBorder(7, 14, 7, 14));
        deleteButton.setCursor(new Cursor(Cursor.HAND_CURSOR));
        deleteButton.addActionListener(e -> deleteSelectedIncident());

        bottomPanel.add(addButton);
        bottomPanel.add(editButton);
        bottomPanel.add(deleteButton);

        add(bottomPanel, BorderLayout.SOUTH);
    }

    /**
     * Loads incidents from the backend database matching current filter criteria.
     */
    public void loadIncidents() {
        String query = searchField.getText().trim();
        String sev = (String) severityCombo.getSelectedItem();
        String stat = (String) statusCombo.getSelectedItem();

        // Query database via ApiClient
        currentIncidents = apiClient.getIncidents(query, sev, stat);

        // Clear existing rows
        tableModel.setRowCount(0);

        // Populate table rows
        for (Incident inc : currentIncidents) {
            tableModel.addRow(new Object[]{
                inc.getId(),
                inc.getTitle(),
                inc.getSeverity(),
                inc.getStatus(),
                inc.getCreatedBy(),
                inc.getCreatedAt()
            });
        }
    }

    /**
     * Displays a modal JDialog for logging a new security incident.
     */
    private void showAddIncidentDialog() {
        Window parentWindow = SwingUtilities.getWindowAncestor(this);
        JDialog dialog = new JDialog(parentWindow, "Log New Security Incident", Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setSize(480, 420);
        dialog.setLocationRelativeTo(this);
        dialog.getContentPane().setBackground(SwingTheme.PANEL_BG);
        dialog.setLayout(new BorderLayout(10, 10));

        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBackground(SwingTheme.PANEL_BG);
        formPanel.setBorder(BorderFactory.createEmptyBorder(18, 20, 10, 20));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(6, 6, 6, 6);

        // Title
        gbc.gridx = 0; gbc.gridy = 0;
        JLabel lblTitle = new JLabel("Title:");
        lblTitle.setForeground(SwingTheme.TEXT_PRIMARY);
        lblTitle.setFont(SwingTheme.FONT_BOLD);
        formPanel.add(lblTitle, gbc);

        gbc.gridx = 1;
        JTextField txtTitle = new JTextField(20);
        SwingTheme.styleTextField(txtTitle);
        formPanel.add(txtTitle, gbc);

        // Description
        gbc.gridx = 0; gbc.gridy = 1;
        JLabel lblDesc = new JLabel("Description:");
        lblDesc.setForeground(SwingTheme.TEXT_PRIMARY);
        lblDesc.setFont(SwingTheme.FONT_BOLD);
        formPanel.add(lblDesc, gbc);

        gbc.gridx = 1;
        JTextArea txtDesc = new JTextArea(4, 20);
        txtDesc.setBackground(SwingTheme.CARD_BG);
        txtDesc.setForeground(SwingTheme.TEXT_PRIMARY);
        txtDesc.setCaretColor(Color.WHITE);
        txtDesc.setFont(SwingTheme.FONT_BODY);
        txtDesc.setLineWrap(true);
        txtDesc.setWrapStyleWord(true);
        txtDesc.setBorder(BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR));
        formPanel.add(new JScrollPane(txtDesc), gbc);

        // Severity
        gbc.gridx = 0; gbc.gridy = 2;
        JLabel lblSev = new JLabel("Severity:");
        lblSev.setForeground(SwingTheme.TEXT_PRIMARY);
        lblSev.setFont(SwingTheme.FONT_BOLD);
        formPanel.add(lblSev, gbc);

        gbc.gridx = 1;
        JComboBox<String> cmbSev = new JComboBox<>(new String[]{"LOW", "MEDIUM", "HIGH", "CRITICAL"});
        SwingTheme.styleComboBox(cmbSev);
        cmbSev.setSelectedItem("HIGH");
        formPanel.add(cmbSev, gbc);

        // Status
        gbc.gridx = 0; gbc.gridy = 3;
        JLabel lblStat = new JLabel("Status:");
        lblStat.setForeground(SwingTheme.TEXT_PRIMARY);
        lblStat.setFont(SwingTheme.FONT_BOLD);
        formPanel.add(lblStat, gbc);

        gbc.gridx = 1;
        JComboBox<String> cmbStat = new JComboBox<>(new String[]{"OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"});
        SwingTheme.styleComboBox(cmbStat);
        cmbStat.setSelectedItem("OPEN");
        formPanel.add(cmbStat, gbc);

        dialog.add(formPanel, BorderLayout.CENTER);

        // Buttons
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 12));
        btnPanel.setBackground(SwingTheme.PANEL_BG);

        JButton saveBtn = new JButton("Save Incident");
        SwingTheme.stylePrimaryButton(saveBtn);
        saveBtn.addActionListener(e -> {
            String title = txtTitle.getText().trim();
            String desc = txtDesc.getText().trim();
            if (title.isEmpty()) {
                JOptionPane.showMessageDialog(dialog, "Incident title cannot be blank.", "Validation Error", JOptionPane.WARNING_MESSAGE);
                return;
            }
            Incident newInc = new Incident(title, desc, (String) cmbSev.getSelectedItem(), (String) cmbStat.getSelectedItem());
            apiClient.createIncident(newInc);
            dialog.dispose();
            loadIncidents();
        });

        JButton cancelBtn = new JButton("Cancel");
        SwingTheme.styleSecondaryButton(cancelBtn);
        cancelBtn.addActionListener(e -> dialog.dispose());

        btnPanel.add(saveBtn);
        btnPanel.add(cancelBtn);
        dialog.add(btnPanel, BorderLayout.SOUTH);

        dialog.setVisible(true);
    }

    /**
     * Displays a modal JDialog for editing the selected security incident.
     */
    private void showEditIncidentDialog() {
        int selectedRow = incidentTable.getSelectedRow();
        if (selectedRow < 0) {
            JOptionPane.showMessageDialog(this, "Please select an incident from the table first.", "Selection Required", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int incidentId = (int) tableModel.getValueAt(selectedRow, 0);
        Incident selected = currentIncidents.stream()
            .filter(i -> i.getId() == incidentId)
            .findFirst()
            .orElse(null);

        if (selected == null) return;

        Window parentWindow = SwingUtilities.getWindowAncestor(this);
        JDialog dialog = new JDialog(parentWindow, "Update Incident #" + incidentId, Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setSize(480, 420);
        dialog.setLocationRelativeTo(this);
        dialog.getContentPane().setBackground(SwingTheme.PANEL_BG);
        dialog.setLayout(new BorderLayout(10, 10));

        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBackground(SwingTheme.PANEL_BG);
        formPanel.setBorder(BorderFactory.createEmptyBorder(18, 20, 10, 20));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(6, 6, 6, 6);

        // Title
        gbc.gridx = 0; gbc.gridy = 0;
        JLabel lblTitle = new JLabel("Title:");
        lblTitle.setForeground(SwingTheme.TEXT_PRIMARY);
        lblTitle.setFont(SwingTheme.FONT_BOLD);
        formPanel.add(lblTitle, gbc);

        gbc.gridx = 1;
        JTextField txtTitle = new JTextField(selected.getTitle(), 20);
        SwingTheme.styleTextField(txtTitle);
        formPanel.add(txtTitle, gbc);

        // Description
        gbc.gridx = 0; gbc.gridy = 1;
        JLabel lblDesc = new JLabel("Description:");
        lblDesc.setForeground(SwingTheme.TEXT_PRIMARY);
        lblDesc.setFont(SwingTheme.FONT_BOLD);
        formPanel.add(lblDesc, gbc);

        gbc.gridx = 1;
        JTextArea txtDesc = new JTextArea(selected.getDescription() != null ? selected.getDescription() : "", 4, 20);
        txtDesc.setBackground(SwingTheme.CARD_BG);
        txtDesc.setForeground(SwingTheme.TEXT_PRIMARY);
        txtDesc.setCaretColor(Color.WHITE);
        txtDesc.setFont(SwingTheme.FONT_BODY);
        txtDesc.setLineWrap(true);
        txtDesc.setWrapStyleWord(true);
        txtDesc.setBorder(BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR));
        formPanel.add(new JScrollPane(txtDesc), gbc);

        // Severity
        gbc.gridx = 0; gbc.gridy = 2;
        JLabel lblSev = new JLabel("Severity:");
        lblSev.setForeground(SwingTheme.TEXT_PRIMARY);
        lblSev.setFont(SwingTheme.FONT_BOLD);
        formPanel.add(lblSev, gbc);

        gbc.gridx = 1;
        JComboBox<String> cmbSev = new JComboBox<>(new String[]{"LOW", "MEDIUM", "HIGH", "CRITICAL"});
        SwingTheme.styleComboBox(cmbSev);
        cmbSev.setSelectedItem(selected.getSeverity());
        formPanel.add(cmbSev, gbc);

        // Status
        gbc.gridx = 0; gbc.gridy = 3;
        JLabel lblStat = new JLabel("Status:");
        lblStat.setForeground(SwingTheme.TEXT_PRIMARY);
        lblStat.setFont(SwingTheme.FONT_BOLD);
        formPanel.add(lblStat, gbc);

        gbc.gridx = 1;
        JComboBox<String> cmbStat = new JComboBox<>(new String[]{"OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"});
        SwingTheme.styleComboBox(cmbStat);
        cmbStat.setSelectedItem(selected.getStatus());
        formPanel.add(cmbStat, gbc);

        dialog.add(formPanel, BorderLayout.CENTER);

        // Buttons
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 12));
        btnPanel.setBackground(SwingTheme.PANEL_BG);

        JButton updateBtn = new JButton("Update Incident");
        SwingTheme.stylePrimaryButton(updateBtn);
        updateBtn.addActionListener(e -> {
            String title = txtTitle.getText().trim();
            String desc = txtDesc.getText().trim();
            if (title.isEmpty()) {
                JOptionPane.showMessageDialog(dialog, "Incident title cannot be blank.", "Validation Error", JOptionPane.WARNING_MESSAGE);
                return;
            }
            Incident updated = new Incident(title, desc, (String) cmbSev.getSelectedItem(), (String) cmbStat.getSelectedItem());
            apiClient.updateIncident(incidentId, updated);
            dialog.dispose();
            loadIncidents();
        });

        JButton cancelBtn = new JButton("Cancel");
        SwingTheme.styleSecondaryButton(cancelBtn);
        cancelBtn.addActionListener(e -> dialog.dispose());

        btnPanel.add(updateBtn);
        btnPanel.add(cancelBtn);
        dialog.add(btnPanel, BorderLayout.SOUTH);

        dialog.setVisible(true);
    }

    /**
     * Deletes the selected incident after verifying Administrator role and user confirmation.
     */
    private void deleteSelectedIncident() {
        int selectedRow = incidentTable.getSelectedRow();
        if (selectedRow < 0) {
            JOptionPane.showMessageDialog(this, "Please select an incident to delete.", "Selection Required", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        // Verify role authorization on desktop client before proceeding
        User user = apiClient.getCurrentUser();
        if (user == null || !user.isAdmin()) {
            JOptionPane.showMessageDialog(this,
                "Permission Denied: Only users with the ADMINISTRATOR role can delete incidents.\n\nCurrent Role: "
                + (user != null ? user.getRole() : "ANONYMOUS"),
                "Role Authorization Check", JOptionPane.ERROR_MESSAGE);
            return;
        }

        int incidentId = (int) tableModel.getValueAt(selectedRow, 0);
        String title = (String) tableModel.getValueAt(selectedRow, 1);

        int confirm = JOptionPane.showConfirmDialog(this,
            "Are you sure you want to permanently delete Incident #" + incidentId + ":\n\"" + title + "\"?",
            "Confirm Incident Deletion", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);

        if (confirm == JOptionPane.YES_OPTION) {
            try {
                apiClient.deleteIncident(incidentId);
                JOptionPane.showMessageDialog(this, "Incident #" + incidentId + " deleted successfully.", "Deleted", JOptionPane.INFORMATION_MESSAGE);
                loadIncidents();
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Error deleting incident: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
}
