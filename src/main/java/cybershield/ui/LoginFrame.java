package cybershield.ui;

import cybershield.model.User;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ItemEvent;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;

/**
 * LoginFrame — The primary authentication window for the CyberShield desktop application.
 * Demonstrates: JFrame anatomy, Event Dispatch Thread (EDT) execution, GridBagLayout form alignment,
 * password masking/unmasking, error feedback labels, and seamless transition to MainFrame.
 */
public class LoginFrame extends JFrame {

    private final ApiClient apiClient = ApiClient.getInstance();

    private JTextField usernameField;
    private JPasswordField passwordField;
    private JCheckBox showPasswordCheck;
    private JLabel errorLabel;
    private JButton loginButton;
    private JButton clearButton;

    public LoginFrame() {
        setTitle("CyberShield — Desktop Authentication");
        setSize(460, 530);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null); // Center on screen
        setResizable(false);
        getContentPane().setBackground(SwingTheme.BG_DARK);
        setLayout(new BorderLayout());

        // Build window panels
        add(createHeaderPanel(), BorderLayout.NORTH);
        add(createFormPanel(),   BorderLayout.CENTER);
        add(createFooterPanel(), BorderLayout.SOUTH);

        // Ensure window is properly realized and brought to foreground on Windows desktop
        ensureVisibility();
    }

    /**
     * Guarantees the frame is brought to the absolute foreground of the Windows desktop,
     * overcoming focus-stealing prevention.
     */
    private void ensureVisibility() {
        setAlwaysOnTop(true);
        toFront();
        requestFocus();
        // Release always-on-top so user can freely interact with other windows
        SwingUtilities.invokeLater(() -> {
            try {
                Thread.sleep(200);
            } catch (InterruptedException ignored) {}
            setAlwaysOnTop(false);
        });
    }

    /** Creates top branding header with title and course edition badge. */
    private JPanel createHeaderPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 6));
        panel.setBackground(SwingTheme.PANEL_BG);
        panel.setBorder(BorderFactory.createEmptyBorder(22, 24, 18, 24));

        JLabel iconLabel = new JLabel("🛡️", SwingConstants.CENTER);
        iconLabel.setFont(iconLabel.getFont().deriveFont(32.0f));

        JLabel titleLabel = new JLabel("CYBERSHIELD", SwingConstants.CENTER);
        titleLabel.setFont(SwingTheme.FONT_TITLE);
        titleLabel.setForeground(SwingTheme.ACCENT_CYAN);

        JLabel subLabel = new JLabel("Cybersecurity Monitoring & Incident Management System", SwingConstants.CENTER);
        subLabel.setFont(SwingTheme.FONT_SMALL);
        subLabel.setForeground(SwingTheme.TEXT_SECONDARY);

        JLabel badgeLabel = new JLabel("Second-Year B.Tech CSE Project Review", SwingConstants.CENTER);
        badgeLabel.setFont(SwingTheme.FONT_SMALL);
        badgeLabel.setForeground(SwingTheme.SEVERITY_LOW);

        JPanel textPanel = new JPanel(new BorderLayout(0, 3));
        textPanel.setOpaque(false);
        textPanel.add(titleLabel, BorderLayout.NORTH);
        textPanel.add(subLabel, BorderLayout.CENTER);
        textPanel.add(badgeLabel, BorderLayout.SOUTH);

        panel.add(iconLabel, BorderLayout.NORTH);
        panel.add(textPanel, BorderLayout.CENTER);

        return panel;
    }

    /** Creates the central form panel using GridBagLayout for clean alignment. */
    private JPanel createFormPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBackground(SwingTheme.BG_DARK);
        panel.setBorder(BorderFactory.createEmptyBorder(15, 36, 10, 36));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(6, 4, 6, 4);

        // Username Label & Field
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0.3;
        JLabel userLabel = new JLabel("Username:");
        userLabel.setForeground(SwingTheme.TEXT_SECONDARY);
        userLabel.setFont(SwingTheme.FONT_BOLD);
        panel.add(userLabel, gbc);

        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 0.7;
        usernameField = new JTextField(15);
        SwingTheme.styleTextField(usernameField);
        panel.add(usernameField, gbc);

        // Password Label & Field
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0.3;
        JLabel passLabel = new JLabel("Password:");
        passLabel.setForeground(SwingTheme.TEXT_SECONDARY);
        passLabel.setFont(SwingTheme.FONT_BOLD);
        panel.add(passLabel, gbc);

        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 0.7;
        passwordField = new JPasswordField(15);
        SwingTheme.styleTextField(passwordField);
        panel.add(passwordField, gbc);

        // Show password checkbox
        gbc.gridx = 1; gbc.gridy = 2;
        showPasswordCheck = new JCheckBox("Show password");
        showPasswordCheck.setOpaque(false);
        showPasswordCheck.setForeground(SwingTheme.TEXT_MUTED);
        showPasswordCheck.setFont(SwingTheme.FONT_SMALL);
        showPasswordCheck.setFocusPainted(false);
        showPasswordCheck.addItemListener(e -> {
            if (e.getStateChange() == ItemEvent.SELECTED) {
                passwordField.setEchoChar((char) 0);
            } else {
                passwordField.setEchoChar('•');
            }
        });
        panel.add(showPasswordCheck, gbc);

        // Error message label
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 2;
        errorLabel = new JLabel(" ", SwingConstants.CENTER);
        errorLabel.setForeground(SwingTheme.SEVERITY_CRITICAL);
        errorLabel.setFont(SwingTheme.FONT_SMALL);
        panel.add(errorLabel, gbc);

        // Sign In & Clear action buttons
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2;
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 12, 0));
        btnPanel.setOpaque(false);

        loginButton = new JButton("Sign In");
        SwingTheme.stylePrimaryButton(loginButton);
        loginButton.setPreferredSize(new Dimension(120, 34));
        loginButton.setCursor(new Cursor(Cursor.HAND_CURSOR));
        loginButton.addActionListener(e -> performLogin());

        clearButton = new JButton("Clear");
        SwingTheme.styleSecondaryButton(clearButton);
        clearButton.setPreferredSize(new Dimension(100, 34));
        clearButton.setCursor(new Cursor(Cursor.HAND_CURSOR));
        clearButton.addActionListener(e -> clearForm());

        btnPanel.add(loginButton);
        btnPanel.add(clearButton);
        panel.add(btnPanel, gbc);

        // Pressing Enter inside password field triggers login
        passwordField.addActionListener(e -> performLogin());
        usernameField.addActionListener(e -> passwordField.requestFocusInWindow());

        return panel;
    }

    /** Creates bottom demo login buttons for faculty presentation. */
    private JPanel createFooterPanel() {
        JPanel footer = new JPanel(new BorderLayout(0, 6));
        footer.setBackground(SwingTheme.PANEL_BG);
        footer.setBorder(BorderFactory.createEmptyBorder(12, 24, 16, 24));

        JLabel demoHint = new JLabel("Quick Demo Credentials for Viva Evaluation:", SwingConstants.CENTER);
        demoHint.setFont(SwingTheme.FONT_SMALL);
        demoHint.setForeground(SwingTheme.TEXT_MUTED);

        JPanel quickPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        quickPanel.setOpaque(false);

        JButton adminQuick = new JButton("Fill Admin");
        SwingTheme.styleSecondaryButton(adminQuick);
        adminQuick.setFont(SwingTheme.FONT_SMALL);
        adminQuick.addActionListener(e -> {
            usernameField.setText("admin");
            passwordField.setText("Admin@123");
            errorLabel.setText(" ");
        });

        JButton analystQuick = new JButton("Fill Analyst");
        SwingTheme.styleSecondaryButton(analystQuick);
        analystQuick.setFont(SwingTheme.FONT_SMALL);
        analystQuick.addActionListener(e -> {
            usernameField.setText("analyst");
            passwordField.setText("Analyst@123");
            errorLabel.setText(" ");
        });

        quickPanel.add(adminQuick);
        quickPanel.add(analystQuick);

        footer.add(demoHint, BorderLayout.NORTH);
        footer.add(quickPanel, BorderLayout.CENTER);

        return footer;
    }

    /** Validates inputs and authenticates through ApiClient. */
    private void performLogin() {
        String username = usernameField.getText().trim();
        String password = new String(passwordField.getPassword());

        if (username.isEmpty() || password.isEmpty()) {
            errorLabel.setText("Please enter both username and password.");
            return;
        }

        loginButton.setEnabled(false);
        errorLabel.setText("Verifying credentials...");

        // Perform login verification
        User user = apiClient.login(username, password);

        if (user != null) {
            errorLabel.setText(" ");
            // Open MainFrame on Event Dispatch Thread (EDT)
            SwingUtilities.invokeLater(() -> {
                MainFrame mainFrame = new MainFrame();
                mainFrame.setVisible(true);
                dispose(); // Close login frame
            });
        } else {
            loginButton.setEnabled(true);
            errorLabel.setText("Invalid username or password. Access recorded.");
            JOptionPane.showMessageDialog(this,
                "Authentication Failed.\n\nFailed login attempt has been recorded in the database audit log.",
                "Login Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void clearForm() {
        usernameField.setText("");
        passwordField.setText("");
        errorLabel.setText(" ");
        usernameField.requestFocusInWindow();
    }
}
