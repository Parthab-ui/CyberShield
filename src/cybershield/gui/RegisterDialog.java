package cybershield.gui;

import cybershield.dao.UserDAO;
import cybershield.model.User;
import cybershield.util.Theme;
import cybershield.util.Validator;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

/**
 * RegisterDialog — A modal dialog that lets a new user create an account.
 * Validates: non-empty fields, unique username, matching passwords, password strength,
 * role selection, and a "I agree" checkbox before allowing registration.
 * Demonstrates: JDialog (modal), JPasswordField, JCheckBox, JComboBox.
 */
public class RegisterDialog extends JDialog {

    private UserDAO userDAO;

    // Form fields
    private JTextField     usernameField;
    private JPasswordField passwordField;
    private JPasswordField confirmField;
    private JComboBox<String> roleCombo;
    private JCheckBox      showPasswordCheck;
    private JCheckBox      agreeCheck;

    // Constructor — builds the modal dialog
    public RegisterDialog(JFrame parent) {
        // modal=true means this dialog must be closed before the parent window is usable
        super(parent, "Create New Account", Dialog.ModalityType.APPLICATION_MODAL);
        userDAO = new UserDAO();

        setSize(420, 420);
        setLocationRelativeTo(parent);
        setResizable(false);
        getContentPane().setBackground(Theme.BACKGROUND);
        setLayout(new BorderLayout());

        add(createTitlePanel(),  BorderLayout.NORTH);
        add(createFormPanel(),   BorderLayout.CENTER);
        add(createButtonPanel(), BorderLayout.SOUTH);
    }

    // ================================================================
    // PANEL BUILDERS
    // ================================================================

    /** Creates the dialog title bar. */
    private JPanel createTitlePanel() {
        JPanel panel = new JPanel();
        panel.setBackground(Theme.PANEL_BG);
        panel.setBorder(BorderFactory.createEmptyBorder(10, 0, 10, 0));

        JLabel title = new JLabel("Register New Account");
        title.setFont(Theme.FONT_HEADING);
        title.setForeground(Theme.ACCENT);
        panel.add(title);

        return panel;
    }

    /** Creates the form with all input fields laid out using GridBagLayout. */
    private JPanel createFormPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBackground(Theme.BACKGROUND);
        panel.setBorder(BorderFactory.createEmptyBorder(10, 30, 10, 30));

        GridBagConstraints labelC = new GridBagConstraints();
        labelC.anchor = GridBagConstraints.WEST;
        labelC.insets = new Insets(6, 0, 2, 10);
        labelC.gridx  = 0;

        GridBagConstraints fieldC = new GridBagConstraints();
        fieldC.fill   = GridBagConstraints.HORIZONTAL;
        fieldC.insets = new Insets(6, 0, 2, 0);
        fieldC.gridx  = 1;
        fieldC.weightx = 1.0;

        // ---- Username ----
        labelC.gridy = 0;
        fieldC.gridy = 0;
        panel.add(makeLabel("Username:"), labelC);
        usernameField = new JTextField(15);
        styleField(usernameField);
        panel.add(usernameField, fieldC);

        // ---- Password ----
        labelC.gridy = 1;
        fieldC.gridy = 1;
        panel.add(makeLabel("Password:"), labelC);
        passwordField = new JPasswordField(15);
        styleField(passwordField);
        panel.add(passwordField, fieldC);

        // ---- Confirm Password ----
        labelC.gridy = 2;
        fieldC.gridy = 2;
        panel.add(makeLabel("Confirm Password:"), labelC);
        confirmField = new JPasswordField(15);
        styleField(confirmField);
        panel.add(confirmField, fieldC);

        // ---- Role Selector ----
        labelC.gridy = 3;
        fieldC.gridy = 3;
        panel.add(makeLabel("Role:"), labelC);
        roleCombo = new JComboBox<>(new String[]{"ANALYST", "ADMIN"});
        roleCombo.setBackground(Theme.PANEL_BG);
        roleCombo.setForeground(Theme.TEXT_PRIMARY);
        roleCombo.setFont(Theme.FONT_BODY);
        panel.add(roleCombo, fieldC);

        // ---- Show Password Checkbox ----
        GridBagConstraints spanC = new GridBagConstraints();
        spanC.gridx = 0; spanC.gridy = 4;
        spanC.gridwidth = 2;
        spanC.anchor = GridBagConstraints.WEST;
        spanC.insets = new Insets(6, 0, 2, 0);

        showPasswordCheck = new JCheckBox("Show password");
        showPasswordCheck.setBackground(Theme.BACKGROUND);
        showPasswordCheck.setForeground(Theme.TEXT_SECONDARY);
        showPasswordCheck.setFont(Theme.FONT_SMALL);

        // Event listener: triggered when the Show Password checkbox is ticked or unticked
        showPasswordCheck.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                if (showPasswordCheck.isSelected()) {
                    // Show characters — use 0 as echo char to reveal text
                    passwordField.setEchoChar((char) 0);
                    confirmField.setEchoChar((char) 0);
                } else {
                    // Hide characters — use bullet point
                    passwordField.setEchoChar('•');
                    confirmField.setEchoChar('•');
                }
            }
        });
        panel.add(showPasswordCheck, spanC);

        // ---- Agree to Policy Checkbox ----
        spanC.gridy = 5;
        agreeCheck = new JCheckBox("I agree to the acceptable-use policy");
        agreeCheck.setBackground(Theme.BACKGROUND);
        agreeCheck.setForeground(Theme.TEXT_SECONDARY);
        agreeCheck.setFont(Theme.FONT_SMALL);
        panel.add(agreeCheck, spanC);

        return panel;
    }

    /** Creates the Register and Cancel buttons at the bottom. */
    private JPanel createButtonPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.CENTER, 16, 10));
        panel.setBackground(Theme.PANEL_BG);

        JButton registerButton = new JButton("Register");
        Theme.styleButton(registerButton);

        JButton cancelButton = new JButton("Cancel");
        Theme.styleButton(cancelButton);
        cancelButton.setBackground(Theme.PANEL_BG);
        cancelButton.setForeground(Theme.TEXT_SECONDARY);

        // Event listener: triggered when the Register button is clicked
        registerButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                attemptRegistration();
            }
        });

        // Event listener: triggered when the Cancel button is clicked
        cancelButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                dispose(); // Close the dialog without doing anything
            }
        });

        panel.add(registerButton);
        panel.add(cancelButton);
        return panel;
    }

    // ================================================================
    // REGISTRATION LOGIC
    // ================================================================

    /** Validates all fields and creates the user account if everything passes. */
    private void attemptRegistration() {
        String username = usernameField.getText().trim();
        String password = new String(passwordField.getPassword());
        String confirm  = new String(confirmField.getPassword());
        String role     = (String) roleCombo.getSelectedItem();

        // Rule 1: No empty fields
        if (Validator.isEmpty(username) || Validator.isEmpty(password) || Validator.isEmpty(confirm)) {
            JOptionPane.showMessageDialog(this,
                "All fields are required. Please fill in every field.",
                "Validation Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Rule 2: Username must not already exist
        if (userDAO.usernameExists(username)) {
            JOptionPane.showMessageDialog(this,
                "The username '" + username + "' is already taken. Please choose another.",
                "Username Taken", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Rule 3: Passwords must match
        if (!password.equals(confirm)) {
            JOptionPane.showMessageDialog(this,
                "Passwords do not match. Please re-enter them.",
                "Password Mismatch", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Rule 4: Password must be at least 6 characters
        if (!Validator.isValidPassword(password)) {
            JOptionPane.showMessageDialog(this,
                "Password must be at least 6 characters long.",
                "Weak Password", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Rule 5: Must tick the agree checkbox
        if (!agreeCheck.isSelected()) {
            JOptionPane.showMessageDialog(this,
                "You must agree to the acceptable-use policy to register.",
                "Policy Not Accepted", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // All validations passed — save the new user
        User newUser = new User(username, password, role);
        userDAO.add(newUser);

        JOptionPane.showMessageDialog(this,
            "Account created successfully!\nYou can now log in as " + username + ".",
            "Registration Successful", JOptionPane.INFORMATION_MESSAGE);

        dispose(); // Close the dialog after successful registration
    }

    // ================================================================
    // STYLE HELPERS
    // ================================================================

    /** Creates a styled form label. */
    private JLabel makeLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(Theme.FONT_BODY);
        label.setForeground(Theme.TEXT_SECONDARY);
        return label;
    }

    /** Applies dark theme colours to a text field. */
    private void styleField(JTextField field) {
        field.setBackground(Theme.PANEL_BG);
        field.setForeground(Theme.TEXT_PRIMARY);
        field.setCaretColor(Theme.ACCENT);
        field.setFont(Theme.FONT_BODY);
        field.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Theme.ACCENT),
            BorderFactory.createEmptyBorder(4, 6, 4, 6)
        ));
    }
}
