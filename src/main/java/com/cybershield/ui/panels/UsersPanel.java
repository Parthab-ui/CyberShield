package com.cybershield.ui.panels;

import com.cybershield.exception.DatabaseOperationException;
import com.cybershield.model.User;
import com.cybershield.model.enums.UserRole;
import com.cybershield.repository.DatabaseManager;
import com.cybershield.repository.UserRepository;
import com.cybershield.service.AuthService;
import com.cybershield.ui.CyberTheme;
import com.cybershield.ui.components.CyberTable;
import com.cybershield.ui.components.StyledButton;
import com.cybershield.util.DateTimeUtils;
import com.cybershield.util.SecurityUtils;
import com.cybershield.util.ValidationUtils;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableModel;

/**
 * Panel managing operators and administrators in CyberShield.
 * Demonstrates CRUD operations, role-based authorization, and input validation.
 */
public class UsersPanel extends JPanel {

    private final UserRepository userRepository;
    private final DefaultTableModel tableModel;
    private final CyberTable userTable;
    private final JLabel lblRestrictionWarning;
    private List<User> currentUsers;

    public UsersPanel() {
        this.userRepository = new UserRepository(DatabaseManager.getInstance());

        setLayout(new BorderLayout(10, 10));
        setBackground(CyberTheme.BG_DARK);
        setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        // Top Header
        JPanel topBar = new JPanel(new BorderLayout(8, 8));
        topBar.setOpaque(false);

        JLabel lblTitle = new JLabel("OPERATOR & USER ACCESS MANAGEMENT");
        lblTitle.setFont(CyberTheme.FONT_TITLE);
        lblTitle.setForeground(CyberTheme.TEXT_PRIMARY);

        JPanel actionControls = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        actionControls.setOpaque(false);

        lblRestrictionWarning = new JLabel("");
        lblRestrictionWarning.setFont(CyberTheme.FONT_SMALL);
        lblRestrictionWarning.setForeground(CyberTheme.STATUS_AMBER);

        StyledButton btnAddUser = new StyledButton("+ Add New User", StyledButton.ButtonStyle.PRIMARY);
        btnAddUser.addActionListener(e -> showAddUserDialog());

        StyledButton btnToggleStatus = new StyledButton("Toggle Active / Inactive", StyledButton.ButtonStyle.SECONDARY);
        btnToggleStatus.addActionListener(e -> toggleUserActiveStatus());

        StyledButton btnRefresh = new StyledButton("Refresh", StyledButton.ButtonStyle.SECONDARY);
        btnRefresh.addActionListener(e -> refreshData());

        actionControls.add(lblRestrictionWarning);
        actionControls.add(btnAddUser);
        actionControls.add(btnToggleStatus);
        actionControls.add(btnRefresh);

        topBar.add(lblTitle, BorderLayout.WEST);
        topBar.add(actionControls, BorderLayout.EAST);
        add(topBar, BorderLayout.NORTH);

        // Center Table
        String[] cols = {"ID", "Username", "Full Name", "Role", "Active Status", "Created At", "Last Login"};
        tableModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) { return false; }
        };

        userTable = new CyberTable(tableModel);
        JScrollPane scroll = CyberTable.wrapInScrollPane(userTable);
        add(scroll, BorderLayout.CENTER);

        refreshData();
    }

    public void refreshData() {
        boolean isAdmin = AuthService.isAdmin();
        if (!isAdmin) {
            lblRestrictionWarning.setText("Role: ANALYST (Read-Only Mode)");
        } else {
            lblRestrictionWarning.setText("Role: ADMIN (Full Control)");
        }

        try {
            currentUsers = userRepository.findAll();
            tableModel.setRowCount(0);
            for (User u : currentUsers) {
                tableModel.addRow(new Object[]{
                    u.getId(),
                    u.getUsername(),
                    u.getFullName(),
                    u.getRole().getDisplayName(),
                    u.isActive() ? "ACTIVE" : "DISABLED",
                    DateTimeUtils.format(u.getCreatedAt()),
                    u.getLastLogin() != null ? DateTimeUtils.format(u.getLastLogin()) : "Never"
                });
            }
        } catch (DatabaseOperationException e) {
            JOptionPane.showMessageDialog(this, "Failed to load users: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void showAddUserDialog() {
        if (!AuthService.isAdmin()) {
            JOptionPane.showMessageDialog(this, "Access Denied: Only users with the ADMIN role can create new users.",
                    "Authorization Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        JPanel form = new JPanel(new GridLayout(4, 2, 8, 8));
        JTextField txtUsername = new JTextField();
        JPasswordField txtPassword = new JPasswordField();
        JTextField txtFullName = new JTextField();
        JComboBox<UserRole> cmbRole = new JComboBox<>(UserRole.values());

        form.add(new JLabel("Username:"));
        form.add(txtUsername);
        form.add(new JLabel("Password:"));
        form.add(txtPassword);
        form.add(new JLabel("Full Name:"));
        form.add(txtFullName);
        form.add(new JLabel("Role:"));
        form.add(cmbRole);

        int result = JOptionPane.showConfirmDialog(this, form, "Create New User Account", JOptionPane.OK_CANCEL_OPTION);
        if (result == JOptionPane.OK_OPTION) {
            String username = txtUsername.getText().trim();
            String password = new String(txtPassword.getPassword()).trim();
            String fullName = txtFullName.getText().trim();
            UserRole role = (UserRole) cmbRole.getSelectedItem();

            if (!ValidationUtils.isValidUsername(username)) {
                JOptionPane.showMessageDialog(this, "Invalid username! Must be at least 3 characters alphanumeric.", "Validation Error", JOptionPane.WARNING_MESSAGE);
                return;
            }
            if (password.length() < 4) {
                JOptionPane.showMessageDialog(this, "Password must be at least 4 characters.", "Validation Error", JOptionPane.WARNING_MESSAGE);
                return;
            }

            try {
                User newUser = new User(0, username, SecurityUtils.hashPassword(password), fullName, role);
                userRepository.save(newUser);
                JOptionPane.showMessageDialog(this, "User created successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
                refreshData();
            } catch (DatabaseOperationException ex) {
                JOptionPane.showMessageDialog(this, "Failed to save user: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void toggleUserActiveStatus() {
        if (!AuthService.isAdmin()) {
            JOptionPane.showMessageDialog(this, "Access Denied: Only ADMIN can toggle user status.",
                    "Authorization Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        int row = userTable.getSelectedRow();
        if (row < 0 || currentUsers == null || row >= currentUsers.size()) {
            JOptionPane.showMessageDialog(this, "Select a user from the table first.", "Selection Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        User selected = currentUsers.get(row);
        if ("admin".equalsIgnoreCase(selected.getUsername())) {
            JOptionPane.showMessageDialog(this, "Cannot deactivate the root admin account.", "Action Blocked", JOptionPane.WARNING_MESSAGE);
            return;
        }

        selected.setActive(!selected.isActive());
        try {
            userRepository.update(selected);
            refreshData();
        } catch (DatabaseOperationException e) {
            JOptionPane.showMessageDialog(this, "Failed to update status: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }
}
