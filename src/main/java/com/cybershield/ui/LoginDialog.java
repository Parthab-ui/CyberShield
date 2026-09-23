package com.cybershield.ui;

import com.cybershield.exception.AuthenticationException;
import com.cybershield.model.User;
import com.cybershield.service.AuthService;
import com.cybershield.ui.components.StyledButton;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import javax.swing.BorderFactory;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.SwingConstants;

/**
 * Modern SOC Analyst Login Dialog.
 */
public class LoginDialog extends JDialog {

    private final AuthService authService;
    private final JTextField txtUsername;
    private final JPasswordField txtPassword;
    private boolean loginSuccessful = false;

    public LoginDialog(JFrame parent) {
        super(parent, "CyberShield SOC Authentication", true);
        this.authService = new AuthService();

        setSize(440, 380);
        setLocationRelativeTo(parent);
        setResizable(false);
        getContentPane().setBackground(CyberTheme.BG_DARK);
        setLayout(new BorderLayout(0, 0));

        // Top Banner / Header
        JPanel headerPanel = new JPanel(new GridLayout(2, 1, 4, 4));
        headerPanel.setBackground(CyberTheme.BG_SIDEBAR);
        headerPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, CyberTheme.BORDER_COLOR),
                BorderFactory.createEmptyBorder(20, 20, 16, 20)
        ));

        JLabel lblTitle = new JLabel("🛡 CYBERSHIELD", SwingConstants.CENTER);
        lblTitle.setFont(new Font("Segoe UI", Font.BOLD, 22));
        lblTitle.setForeground(CyberTheme.ACCENT_CYAN);

        JLabel lblSubtitle = new JLabel("Threat Monitoring & Incident Response System", SwingConstants.CENTER);
        lblSubtitle.setFont(CyberTheme.FONT_BODY);
        lblSubtitle.setForeground(CyberTheme.TEXT_MUTED);

        headerPanel.add(lblTitle);
        headerPanel.add(lblSubtitle);
        add(headerPanel, BorderLayout.NORTH);

        // Center Form
        JPanel formContainer = new JPanel(new GridLayout(4, 1, 8, 8));
        formContainer.setOpaque(false);
        formContainer.setBorder(BorderFactory.createEmptyBorder(20, 36, 10, 36));

        // Username
        JPanel pnlUser = new JPanel(new BorderLayout(4, 4));
        pnlUser.setOpaque(false);
        JLabel lblUser = new JLabel("Username:");
        lblUser.setFont(CyberTheme.FONT_BODY_BOLD);
        lblUser.setForeground(CyberTheme.TEXT_PRIMARY);

        txtUsername = new JTextField("analyst");
        styleInput(txtUsername);
        pnlUser.add(lblUser, BorderLayout.NORTH);
        pnlUser.add(txtUsername, BorderLayout.CENTER);

        // Password
        JPanel pnlPass = new JPanel(new BorderLayout(4, 4));
        pnlPass.setOpaque(false);
        JLabel lblPass = new JLabel("Password:");
        lblPass.setFont(CyberTheme.FONT_BODY_BOLD);
        lblPass.setForeground(CyberTheme.TEXT_PRIMARY);

        txtPassword = new JPasswordField("cyber123");
        styleInput(txtPassword);
        pnlPass.add(lblPass, BorderLayout.NORTH);
        pnlPass.add(txtPassword, BorderLayout.CENTER);

        // Hint Label
        JLabel lblHint = new JLabel("<html><center>Demo Credentials: <b>analyst / cyber123</b><br>Admin Account: <b>admin / admin123</b></center></html>", SwingConstants.CENTER);
        lblHint.setFont(CyberTheme.FONT_SMALL);
        lblHint.setForeground(CyberTheme.ACCENT_BLUE);

        formContainer.add(pnlUser);
        formContainer.add(pnlPass);
        formContainer.add(lblHint);

        add(formContainer, BorderLayout.CENTER);

        // Bottom Action Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 14, 16));
        buttonPanel.setOpaque(false);

        StyledButton btnLogin = new StyledButton("Login to SOC", StyledButton.ButtonStyle.PRIMARY);
        btnLogin.setPreferredSize(new Dimension(140, 38));
        btnLogin.addActionListener(e -> attemptLogin());

        StyledButton btnExit = new StyledButton("Exit", StyledButton.ButtonStyle.SECONDARY);
        btnExit.setPreferredSize(new Dimension(100, 38));
        btnExit.addActionListener(e -> System.exit(0));

        // Press Enter to submit
        txtPassword.addActionListener(e -> attemptLogin());
        txtUsername.addActionListener(e -> attemptLogin());

        buttonPanel.add(btnLogin);
        buttonPanel.add(btnExit);
        add(buttonPanel, BorderLayout.SOUTH);
    }

    private void styleInput(JTextField field) {
        field.setBackground(CyberTheme.BG_CARD);
        field.setForeground(CyberTheme.TEXT_PRIMARY);
        field.setCaretColor(CyberTheme.ACCENT_CYAN);
        field.setFont(CyberTheme.FONT_BODY);
        field.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                BorderFactory.createEmptyBorder(6, 10, 6, 10)
        ));
    }

    private void attemptLogin() {
        String username = txtUsername.getText().trim();
        String password = new String(txtPassword.getPassword()).trim();

        try {
            User user = authService.login(username, password);
            loginSuccessful = true;
            dispose();
        } catch (AuthenticationException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "Authentication Failed", JOptionPane.ERROR_MESSAGE);
        }
    }

    public boolean isLoginSuccessful() {
        return loginSuccessful;
    }
}
