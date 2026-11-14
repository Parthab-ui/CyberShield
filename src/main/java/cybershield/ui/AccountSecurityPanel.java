package cybershield.ui;

import cybershield.model.AccountLockStatus;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

/**
 * AccountSecurityPanel — Desktop SOC management console for Account Lockout
 * and Credential Security Engine.
 */
public class AccountSecurityPanel extends JPanel {

    private final ApiClient apiClient = ApiClient.getInstance();
    private final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    private JLabel lblLockedCount;
    private JLabel lblThreshold;
    private JLabel lblDuration;

    private DefaultTableModel tableModel;
    private JTable lockedTable;
    private JButton btnUnlock;
    private JButton btnSimulateLock;

    private Timer refreshTimer;

    public AccountSecurityPanel() {
        setBackground(SwingTheme.BG_DARK);
        setLayout(new BorderLayout(0, 14));
        setBorder(BorderFactory.createEmptyBorder(16, 20, 16, 20));

        add(createHeaderBar(), BorderLayout.NORTH);

        JPanel centerPanel = new JPanel(new BorderLayout(0, 12));
        centerPanel.setOpaque(false);

        centerPanel.add(createKpiPanel(), BorderLayout.NORTH);
        centerPanel.add(createTableSection(), BorderLayout.CENTER);

        add(centerPanel, BorderLayout.CENTER);

        refreshTimer = new Timer(5000, e -> {
            if (isShowing()) {
                refreshData();
            }
        });
        refreshTimer.start();

        refreshData();
    }

    private JPanel createHeaderBar() {
        JPanel header = new JPanel(new BorderLayout());
        header.setOpaque(false);

        JPanel textPanel = new JPanel();
        textPanel.setLayout(new BoxLayout(textPanel, BoxLayout.Y_AXIS));
        textPanel.setOpaque(false);

        JLabel title = new JLabel("Account Security & Credential Protection");
        title.setFont(SwingTheme.FONT_TITLE);
        title.setForeground(SwingTheme.TEXT_PRIMARY);

        JLabel sub = new JLabel("Temporary Account Lockout Engine, Password Guessing Prevention & Credential Recovery");
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
        JPanel kpi = new JPanel(new GridLayout(1, 3, 12, 0));
        kpi.setOpaque(false);
        kpi.setMaximumSize(new Dimension(Integer.MAX_VALUE, 70));

        lblLockedCount = new JLabel("0", SwingConstants.CENTER);
        lblThreshold = new JLabel("5 Failed Attempts", SwingConstants.CENTER);
        lblDuration = new JLabel("15 Minutes", SwingConstants.CENTER);

        kpi.add(createMiniCard("CURRENTLY LOCKED ACCOUNTS", lblLockedCount, SwingTheme.SEVERITY_CRITICAL));
        kpi.add(createMiniCard("DETECTION THRESHOLD", lblThreshold, SwingTheme.SEVERITY_MEDIUM));
        kpi.add(createMiniCard("AUTO-LOCKOUT DURATION", lblDuration, SwingTheme.ACCENT_CYAN));
        return kpi;
    }

    private JPanel createMiniCard(String title, JLabel valLabel, Color valColor) {
        JPanel card = new JPanel(new BorderLayout(0, 4));
        card.setBackground(SwingTheme.PANEL_BG);
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR),
                BorderFactory.createEmptyBorder(8, 12, 8, 12)
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

    private JPanel createTableSection() {
        JPanel panel = new JPanel(new BorderLayout(0, 8));
        panel.setBackground(SwingTheme.PANEL_BG);
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR),
                BorderFactory.createEmptyBorder(12, 14, 12, 14)
        ));

        JLabel lblTitle = new JLabel("Locked User Accounts Telemetry");
        lblTitle.setFont(SwingTheme.FONT_HEADER);
        lblTitle.setForeground(SwingTheme.TEXT_PRIMARY);
        panel.add(lblTitle, BorderLayout.NORTH);

        String[] cols = {"Username", "Failed Attempts", "Lock Expiration", "Remaining Duration", "Status"};
        tableModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) { return false; }
        };
        lockedTable = new JTable(tableModel);
        SwingTheme.styleTable(lockedTable);
        lockedTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        JScrollPane scroll = new JScrollPane(lockedTable);
        scroll.getViewport().setBackground(SwingTheme.PANEL_BG);
        scroll.setBorder(BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR));
        panel.add(scroll, BorderLayout.CENTER);

        // Action Toolbar
        JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 6));
        actionPanel.setOpaque(false);

        btnUnlock = new JButton("🔓 Unlock Selected Account");
        btnUnlock.setBackground(SwingTheme.ACCENT_BLUE);
        btnUnlock.setForeground(Color.WHITE);
        btnUnlock.setFont(SwingTheme.FONT_BOLD);
        btnUnlock.addActionListener(e -> handleUnlockAccount());

        btnSimulateLock = new JButton("Simulate Brute Force Lock");
        SwingTheme.styleSecondaryButton(btnSimulateLock);
        btnSimulateLock.addActionListener(e -> handleSimulateLock());

        actionPanel.add(btnUnlock);
        actionPanel.add(btnSimulateLock);
        panel.add(actionPanel, BorderLayout.SOUTH);

        return panel;
    }

    public void refresh() {
        refreshData();
    }

    private void refreshData() {
        new SwingWorker<List<AccountLockStatus>, Void>() {
            @Override
            protected List<AccountLockStatus> doInBackground() {
                return apiClient.getLockedAccounts();
            }

            @Override
            protected void done() {
                try {
                    List<AccountLockStatus> list = get();
                    tableModel.setRowCount(0);
                    int count = 0;

                    if (list != null) {
                        count = list.size();
                        for (AccountLockStatus acc : list) {
                            long remSec = acc.getRemainingSeconds();
                            String remainingText = "Permanent";
                            String statusText = acc.isLocked() ? "LOCKED" : "UNLOCKED";

                            if (acc.getLockedUntil() > 0) {
                                if (remSec > 0) {
                                    long mins = remSec / 60;
                                    long secs = remSec % 60;
                                    remainingText = mins + "m " + secs + "s";
                                } else {
                                    statusText = "EXPIRED";
                                    remainingText = "Expired";
                                }
                            }

                            tableModel.addRow(new Object[]{
                                    acc.getUsername(),
                                    acc.getFailedAttemptCount(),
                                    acc.getLockedUntil() > 0 ? dateFormat.format(new Date(acc.getLockedUntil())) : "Indefinite",
                                    remainingText,
                                    statusText
                            });
                        }
                    }

                    lblLockedCount.setText(String.valueOf(count));
                } catch (Exception ignored) {}
            }
        }.execute();
    }

    private void handleUnlockAccount() {
        if (!apiClient.isAdmin()) {
            JOptionPane.showMessageDialog(this, "Permission Denied: Only Administrator role can unlock user accounts.", "RBAC Gating", JOptionPane.ERROR_MESSAGE);
            return;
        }

        int row = lockedTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "Please select an account row from the table.", "Selection Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String username = (String) tableModel.getValueAt(row, 0);
        int confirm = JOptionPane.showConfirmDialog(this, "Unlock account '" + username + "' and reset failed attempts?", "Confirm Account Unlock", JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            try {
                boolean success = apiClient.unlockAccount(username);
                if (success) {
                    JOptionPane.showMessageDialog(this, "Account '" + username + "' has been unlocked successfully.", "Success", JOptionPane.INFORMATION_MESSAGE);
                    refreshData();
                } else {
                    JOptionPane.showMessageDialog(this, "Account could not be unlocked (was not currently locked).", "Notice", JOptionPane.WARNING_MESSAGE);
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Unlock failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void handleSimulateLock() {
        String username = JOptionPane.showInputDialog(this, "Enter username to target with 5 rapid failed logins:", "user");
        if (username != null && !username.trim().isEmpty()) {
            username = username.trim();
            for (int i = 1; i <= 5; i++) {
                apiClient.login(username, "wrong_password_" + i);
            }
            JOptionPane.showMessageDialog(this, "Simulated 5 failed logins against '" + username + "'. Account should now be locked.", "Simulation Completed", JOptionPane.INFORMATION_MESSAGE);
            refreshData();
        }
    }
}
