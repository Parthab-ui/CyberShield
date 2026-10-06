package cybershield.gui;

import cybershield.dao.LogDAO;
import cybershield.dao.UserDAO;
import cybershield.model.LogEntry;
import cybershield.model.User;
import cybershield.util.Theme;
import cybershield.util.Validator;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.Timer;

/**
 * LoginFrame — The authentication window for CyberShield.
 * Demonstrates: JFrame, JTextField, JPasswordField, JCheckBox, JComboBox,
 * JButton, JLabel, JSeparator, javax.swing.Timer for lockout countdown, and ActionListener/ItemListener.
 */
public class LoginFrame extends JFrame {

    /** Callback interface to notify when login succeeds. */
    public interface LoginCallback {
        void onLoginSuccess(User user);
    }

    private UserDAO userDAO;
    private LogDAO  logDAO;
    private LoginCallback loginCallback;

    // UI Components
    private JTextField         usernameField;
    private JPasswordField     passwordField;
    private JCheckBox          showPasswordCheck;
    private JComboBox<String>  roleCombo;
    private JButton            loginButton;
    private JButton            registerButton;
    private JLabel             errorLabel;

    // Login attempt tracking & lockout timer
    private int   failedAttempts   = 0;
    private int   lockoutSeconds   = 10;
    private Timer lockoutTimer;

    // Constructor — builds the login window
    public LoginFrame() {
        userDAO = new UserDAO();
        logDAO  = new LogDAO();

        setTitle("CyberShield — Authentication");
        setSize(440, 480);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null); // Center on screen
        setResizable(false);
        getContentPane().setBackground(Theme.BACKGROUND);
        setLayout(new BorderLayout());

        add(createHeaderPanel(), BorderLayout.NORTH);
        add(createFormPanel(),   BorderLayout.CENTER);
        add(createFooterPanel(), BorderLayout.SOUTH);
    }

    /** Sets an optional callback to be invoked on successful login. */
    public void setLoginCallback(LoginCallback callback) {
        this.loginCallback = callback;
    }

    // ================================================================
    // PANEL BUILDERS
    // ================================================================

    /** Creates the top banner with the application title and subtitle. */
    private JPanel createHeaderPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 4));
        panel.setBackground(Theme.PANEL_BG);
        panel.setBorder(BorderFactory.createEmptyBorder(18, 20, 14, 20));

        JLabel titleLabel = new JLabel("CYBERSHIELD", SwingConstants.CENTER);
        titleLabel.setFont(Theme.FONT_TITLE);
        titleLabel.setForeground(Theme.ACCENT);

        JLabel subLabel = new JLabel("Threat Monitoring & Incident Response", SwingConstants.CENTER);
        subLabel.setFont(Theme.FONT_SMALL);
        subLabel.setForeground(Theme.TEXT_SECONDARY);

        panel.add(titleLabel, BorderLayout.NORTH);
        panel.add(subLabel,   BorderLayout.CENTER);
        panel.add(new JSeparator(), BorderLayout.SOUTH);

        return panel;
    }

    /** Creates the central credentials form using GridBagLayout. */
    private JPanel createFormPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBackground(Theme.BACKGROUND);
        panel.setBorder(BorderFactory.createEmptyBorder(15, 35, 10, 35));

        GridBagConstraints labelC = new GridBagConstraints();
        labelC.anchor = GridBagConstraints.WEST;
        labelC.insets = new Insets(6, 0, 4, 10);
        labelC.gridx  = 0;

        GridBagConstraints fieldC = new GridBagConstraints();
        fieldC.fill    = GridBagConstraints.HORIZONTAL;
        fieldC.insets  = new Insets(6, 0, 4, 0);
        fieldC.gridx   = 1;
        fieldC.weightx = 1.0;

        // ---- Username field ----
        labelC.gridy = 0;
        fieldC.gridy = 0;
        panel.add(makeLabel("Username:"), labelC);
        usernameField = new JTextField(15);
        styleField(usernameField);
        panel.add(usernameField, fieldC);

        // ---- Password field ----
        labelC.gridy = 1;
        fieldC.gridy = 1;
        panel.add(makeLabel("Password:"), labelC);
        passwordField = new JPasswordField(15);
        styleField(passwordField);
        panel.add(passwordField, fieldC);

        // Enter key in password field triggers login (ActionListener)
        passwordField.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                attemptLogin();
            }
        });

        // Enter key in username field moves focus to password field
        usernameField.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                passwordField.requestFocusInWindow();
            }
        });

        // ---- Show Password checkbox ----
        GridBagConstraints spanC = new GridBagConstraints();
        spanC.gridx     = 0;
        spanC.gridy     = 2;
        spanC.gridwidth = 2;
        spanC.anchor    = GridBagConstraints.WEST;
        spanC.insets    = new Insets(4, 0, 4, 0);

        showPasswordCheck = new JCheckBox("Show password");
        showPasswordCheck.setBackground(Theme.BACKGROUND);
        showPasswordCheck.setForeground(Theme.TEXT_SECONDARY);
        showPasswordCheck.setFont(Theme.FONT_SMALL);

        // Event listener: triggered when show password checkbox changes state (ItemListener)
        showPasswordCheck.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                if (showPasswordCheck.isSelected()) {
                    passwordField.setEchoChar((char) 0); // Show plain text
                } else {
                    passwordField.setEchoChar('•');     // Mask characters
                }
            }
        });
        panel.add(showPasswordCheck, spanC);

        // ---- Role selector dropdown ----
        labelC.gridy = 3;
        fieldC.gridy = 3;
        panel.add(makeLabel("Role:"), labelC);
        roleCombo = new JComboBox<>(new String[]{"ANALYST", "ADMIN"});
        roleCombo.setBackground(Theme.PANEL_BG);
        roleCombo.setForeground(Theme.TEXT_PRIMARY);
        roleCombo.setFont(Theme.FONT_BODY);
        panel.add(roleCombo, fieldC);

        // ---- Error / Countdown label ----
        spanC.gridy = 4;
        spanC.insets = new Insets(10, 0, 4, 0);
        errorLabel = new JLabel(" ", SwingConstants.CENTER);
        errorLabel.setFont(Theme.FONT_SMALL);
        errorLabel.setForeground(Theme.CRITICAL);
        panel.add(errorLabel, spanC);

        return panel;
    }

    /** Creates the bottom button panel with Login and Register buttons. */
    private JPanel createFooterPanel() {
        JPanel footer = new JPanel(new BorderLayout());
        footer.setBackground(Theme.PANEL_BG);
        footer.setBorder(BorderFactory.createEmptyBorder(8, 20, 14, 20));

        footer.add(new JSeparator(), BorderLayout.NORTH);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 16, 10));
        buttonPanel.setBackground(Theme.PANEL_BG);

        loginButton = new JButton("Login");
        Theme.styleButton(loginButton);
        loginButton.setPreferredSize(new Dimension(110, 32));

        registerButton = new JButton("Register");
        Theme.styleButton(registerButton);
        registerButton.setBackground(Theme.PANEL_BG);
        registerButton.setForeground(Theme.TEXT_SECONDARY);
        registerButton.setPreferredSize(new Dimension(110, 32));

        // Event listener: triggered when Login button is clicked (ActionListener)
        loginButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                attemptLogin();
            }
        });

        // Event listener: triggered when Register button is clicked (ActionListener)
        registerButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                openRegisterDialog();
            }
        });

        buttonPanel.add(loginButton);
        buttonPanel.add(registerButton);
        footer.add(buttonPanel, BorderLayout.CENTER);

        return footer;
    }

    // ================================================================
    // AUTHENTICATION LOGIC
    // ================================================================

    /** Validates user input and verifies credentials against the database. */
    private void attemptLogin() {
        // If button is locked out, ignore
        if (!loginButton.isEnabled()) {
            return;
        }

        String username = usernameField.getText().trim();
        String password = new String(passwordField.getPassword());
        String selectedRole = (String) roleCombo.getSelectedItem();

        // 1. Validation using Validator utility
        if (Validator.isEmpty(username) || Validator.isEmpty(password)) {
            errorLabel.setText("Please enter both username and password.");
            JOptionPane.showMessageDialog(this,
                "Username and password cannot be empty.",
                "Validation Error",
                JOptionPane.WARNING_MESSAGE);
            return;
        }

        // 2. Validate credentials via UserDAO
        User user = userDAO.validateLogin(username, password);

        // Check if user exists and role matches selection
        if (user != null && user.getRole().equalsIgnoreCase(selectedRole)) {
            // Success: reset failed attempts
            failedAttempts = 0;
            errorLabel.setText(" ");

            // Write audit log entry
            logDAO.add(new LogEntry(user.getId(), "User logged in: " + user.getUsername()));

            // Launch MainFrame via callback or directly
            if (loginCallback != null) {
                loginCallback.onLoginSuccess(user);
            } else {
                MainFrame mainFrame = new MainFrame();
                mainFrame.setCurrentUser(user);
                mainFrame.setVisible(true);
            }

            // Close this login frame
            dispose();

        } else {
            // Login failed
            failedAttempts++;
            if (user != null && !user.getRole().equalsIgnoreCase(selectedRole)) {
                errorLabel.setText("Role mismatch for user '" + username + "'.");
            } else {
                errorLabel.setText("Invalid username or password.");
            }

            if (failedAttempts >= 3) {
                startLockout();
            } else {
                int remaining = 3 - failedAttempts;
                JOptionPane.showMessageDialog(this,
                    "Invalid login credentials.\nAttempts remaining before lockout: " + remaining,
                    "Login Failed",
                    JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    /** Disables the login button for 10 seconds and displays a countdown timer. */
    private void startLockout() {
        loginButton.setEnabled(false);
        lockoutSeconds = 10;
        errorLabel.setText("Account locked. Try again in " + lockoutSeconds + "s");

        // Event listener: triggered every 1000ms by the lockout timer (ActionListener)
        lockoutTimer = new Timer(1000, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                lockoutSeconds--;
                if (lockoutSeconds > 0) {
                    errorLabel.setText("Account locked. Try again in " + lockoutSeconds + "s");
                } else {
                    lockoutTimer.stop();
                    failedAttempts = 0;
                    loginButton.setEnabled(true);
                    errorLabel.setText(" ");
                }
            }
        });
        lockoutTimer.start();
    }

    /** Opens the modal registration dialog. */
    private void openRegisterDialog() {
        RegisterDialog dialog = new RegisterDialog(this);
        dialog.setVisible(true);
    }

    // ================================================================
    // HELPER METHODS
    // ================================================================

    /** Helper to create a consistent styled form label. */
    private JLabel makeLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(Theme.FONT_BODY);
        label.setForeground(Theme.TEXT_SECONDARY);
        return label;
    }

    /** Applies dark theme styling to an input field. */
    private void styleField(JTextField field) {
        field.setBackground(Theme.PANEL_BG);
        field.setForeground(Theme.TEXT_PRIMARY);
        field.setCaretColor(Theme.ACCENT);
        field.setFont(Theme.FONT_BODY);
        field.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Theme.ACCENT),
            BorderFactory.createEmptyBorder(5, 8, 5, 8)
        ));
    }
}
