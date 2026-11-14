package cybershield.ui;

import cybershield.model.ActivityLog;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import java.awt.*;
import java.util.List;

/**
 * ActivityHistoryPanel — Displays tamper-evident system audit trail.
 * Demonstrates:
 * - JTable for viewing audit logs of user actions (login, incident updates, deletions).
 * - Clear segregation between security operational telemetry and compliance audit logs.
 * - Simple refresh and display controls.
 */
public class ActivityHistoryPanel extends JPanel {

    private final ApiClient apiClient;

    private JTable logTable;
    private DefaultTableModel tableModel;
    private JLabel countLabel;
    private JButton refreshBtn;

    public ActivityHistoryPanel() {
        this.apiClient = ApiClient.getInstance();
        setLayout(new BorderLayout(0, 14));
        setBackground(SwingTheme.PANEL_BG);
        setBorder(BorderFactory.createEmptyBorder(18, 20, 18, 20));

        initComponents();
        loadLogs();
    }

    private void initComponents() {
        // TOP: Title + Controls
        JPanel topContainer = new JPanel(new BorderLayout(0, 12));
        topContainer.setOpaque(false);

        JPanel titlePanel = new JPanel(new BorderLayout());
        titlePanel.setOpaque(false);

        JLabel titleLabel = new JLabel("System Audit & Activity Trail");
        titleLabel.setFont(SwingTheme.FONT_TITLE);
        titleLabel.setForeground(SwingTheme.TEXT_PRIMARY);

        JLabel subtitleLabel = new JLabel("Chronological log of administrative actions, incident lifecycle changes, and user sessions");
        subtitleLabel.setFont(SwingTheme.FONT_BODY);
        subtitleLabel.setForeground(SwingTheme.TEXT_MUTED);

        titlePanel.add(titleLabel, BorderLayout.NORTH);
        titlePanel.add(subtitleLabel, BorderLayout.SOUTH);
        topContainer.add(titlePanel, BorderLayout.NORTH);

        JPanel actionBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        actionBar.setOpaque(false);

        refreshBtn = new JButton("Refresh Audit Log");
        SwingTheme.styleSecondaryButton(refreshBtn);
        refreshBtn.addActionListener(e -> loadLogs());

        countLabel = new JLabel("Loading audit records...");
        countLabel.setFont(SwingTheme.FONT_BODY);
        countLabel.setForeground(SwingTheme.TEXT_MUTED);
        countLabel.setBorder(BorderFactory.createEmptyBorder(0, 12, 0, 0));

        actionBar.add(refreshBtn);
        actionBar.add(countLabel);

        topContainer.add(actionBar, BorderLayout.SOUTH);
        add(topContainer, BorderLayout.NORTH);

        // CENTER: Table
        String[] columnNames = {"ID", "User / Actor", "Action Type", "Event Details", "Timestamp"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int col) {
                return false;
            }
        };

        logTable = new JTable(tableModel);
        logTable.setBackground(SwingTheme.CARD_BG);
        logTable.setForeground(SwingTheme.TEXT_PRIMARY);
        logTable.setSelectionBackground(SwingTheme.PRIMARY_COLOR);
        logTable.setSelectionForeground(Color.WHITE);
        logTable.setRowHeight(30);
        logTable.setFont(SwingTheme.FONT_BODY);
        logTable.setShowGrid(true);
        logTable.setGridColor(SwingTheme.BORDER_COLOR);
        logTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        logTable.getColumnModel().getColumn(0).setPreferredWidth(50);
        logTable.getColumnModel().getColumn(1).setPreferredWidth(130);
        logTable.getColumnModel().getColumn(2).setPreferredWidth(170);
        logTable.getColumnModel().getColumn(3).setPreferredWidth(340);
        logTable.getColumnModel().getColumn(4).setPreferredWidth(160);

        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(SwingConstants.CENTER);
        logTable.getColumnModel().getColumn(0).setCellRenderer(centerRenderer);
        logTable.getColumnModel().getColumn(1).setCellRenderer(centerRenderer);
        logTable.getColumnModel().getColumn(2).setCellRenderer(centerRenderer);
        logTable.getColumnModel().getColumn(4).setCellRenderer(centerRenderer);

        JTableHeader header = logTable.getTableHeader();
        header.setBackground(SwingTheme.BG_COLOR);
        header.setForeground(SwingTheme.TEXT_PRIMARY);
        header.setFont(SwingTheme.FONT_BOLD);
        header.setBorder(BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR));

        JScrollPane scrollPane = new JScrollPane(logTable);
        scrollPane.setBorder(BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR));
        scrollPane.getViewport().setBackground(SwingTheme.CARD_BG);
        add(scrollPane, BorderLayout.CENTER);
    }

    public void loadLogs() {
        List<ActivityLog> logs = apiClient.getActivity(50);
        tableModel.setRowCount(0);

        for (ActivityLog l : logs) {
            tableModel.addRow(new Object[]{
                l.getId(),
                l.getUsername(),
                l.getAction(),
                l.getDetails(),
                l.getCreatedAt()
            });
        }

        countLabel.setText("Total " + logs.size() + " audit trail records loaded from SQLite");
    }
}
