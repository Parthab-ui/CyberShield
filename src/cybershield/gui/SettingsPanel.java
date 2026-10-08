package cybershield.gui;

import cybershield.dao.LogDAO;
import cybershield.dao.UserDAO;
import cybershield.model.LogEntry;
import cybershield.model.User;
import cybershield.util.Theme;
import cybershield.util.ThemeSettings;
import cybershield.util.Validator;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JColorChooser;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JLayeredPane;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.JSlider;
import javax.swing.JTabbedPane;
import javax.swing.SwingConstants;

/**
 * SettingsPanel — Manages application configuration, user preferences, security, and metadata.
 * Extends BasePanel (INHERITANCE) and implements refreshData() (POLYMORPHISM).
 * Features 4 organized tabs:
 * 1. Appearance: Theme colors, font sizing, and a live JLayeredPane preview card.
 * 2. System & Alerts: Audio notification toggles, auto-refresh, and inactivity slider.
 * 3. Security: Password change form for the active authenticated user with validation.
 * 4. About: College AOOP project overview, version info, and team division.
 */
public class SettingsPanel extends BasePanel {

    // Active session user
    private User currentUser;

    // DAOs
    private final UserDAO userDAO;
    private final LogDAO logDAO;

    // Appearance components
    private JPanel previewBgPanel;
    private JPanel previewCardPanel;
    private JLabel previewTitleLabel;
    private JLabel previewBadgeLabel;
    private JButton previewSampleButton;
    private JPanel colorSampleBox;
    private JComboBox<String> fontSizeCombo;
    private JRadioButton darkRadio;
    private JRadioButton lightRadio;

    // System components
    private JCheckBox soundAlertsCheck;
    private JCheckBox autoRefreshCheck;
    private JCheckBox desktopNotificationsCheck;
    private JSlider timeoutSlider;
    private JLabel timeoutValueLabel;

    // Security components
    private JLabel securityUserLabel;
    private JPasswordField currentPasswordField;
    private JPasswordField newPasswordField;
    private JPasswordField confirmPasswordField;

    // Constructor — initializes tabs and layouts
    public SettingsPanel() {
        this.userDAO = new UserDAO();
        this.logDAO = new LogDAO();

        setLayout(new BorderLayout(0, 10));
        Theme.stylePanel(this);

        // Header
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setOpaque(false);
        JLabel titleLabel = new JLabel("System Settings & Preferences");
        titleLabel.setFont(Theme.FONT_TITLE);
        titleLabel.setForeground(Theme.TEXT_PRIMARY);

        JLabel subtitleLabel = new JLabel("Customize visual styling, notification triggers, and user credentials");
        subtitleLabel.setFont(Theme.FONT_SMALL);
        subtitleLabel.setForeground(Theme.TEXT_SECONDARY);

        headerPanel.add(titleLabel, BorderLayout.NORTH);
        headerPanel.add(subtitleLabel, BorderLayout.SOUTH);
        add(headerPanel, BorderLayout.NORTH);

        // Tabbed pane
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setBackground(Theme.PANEL_BG);
        tabbedPane.setForeground(Theme.TEXT_PRIMARY);
        tabbedPane.setFont(Theme.FONT_BODY);

        tabbedPane.addTab("Appearance", buildAppearanceTab());
        tabbedPane.addTab("System & Alerts", buildSystemTab());
        tabbedPane.addTab("Security", buildSecurityTab());
        tabbedPane.addTab("About & Info", buildAboutTab());

        add(tabbedPane, BorderLayout.CENTER);
    }

    /** Sets the current authenticated user for profile management. */
    public void setCurrentUser(User user) {
        this.currentUser = user;
        updateSecurityUserInfo();
    }

    /** Builds Tab 1: Appearance with JLayeredPane live preview. */
    private JPanel buildAppearanceTab() {
        JPanel panel = new JPanel(new BorderLayout(15, 15));
        panel.setOpaque(false);
        panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        // Left Side: Live Preview with JLayeredPane
        JPanel previewContainer = new JPanel(new BorderLayout(5, 5));
        previewContainer.setOpaque(false);
        previewContainer.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(Theme.ACCENT), "Live Theme Preview (JLayeredPane)",
                0, 0, Theme.FONT_HEADING, Theme.ACCENT));

        JLayeredPane layeredPane = new JLayeredPane();
        layeredPane.setPreferredSize(new Dimension(360, 200));

        // Layer 0: Background Canvas
        previewBgPanel = new JPanel();
        previewBgPanel.setBounds(10, 10, 340, 180);
        previewBgPanel.setBackground(ThemeSettings.isDarkMode() ? Theme.BACKGROUND : new Color(240, 243, 246));
        previewBgPanel.setBorder(BorderFactory.createLineBorder(Color.GRAY));
        previewBgPanel.setLayout(null);

        // Layer 1: Foreground Card
        previewCardPanel = new JPanel(new BorderLayout(5, 5));
        previewCardPanel.setBounds(30, 25, 300, 150);
        previewCardPanel.setBackground(ThemeSettings.isDarkMode() ? Theme.PANEL_BG : Color.WHITE);
        previewCardPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(ThemeSettings.getAccentColor(), 2),
                BorderFactory.createEmptyBorder(10, 10, 10, 10)));

        previewTitleLabel = new JLabel("CyberShield Active Radar");
        previewTitleLabel.setFont(Theme.FONT_HEADING);
        previewTitleLabel.setForeground(ThemeSettings.isDarkMode() ? Theme.TEXT_PRIMARY : Color.DARK_GRAY);

        previewBadgeLabel = new JLabel(" CRITICAL SEVERITY ", SwingConstants.CENTER);
        previewBadgeLabel.setFont(Theme.FONT_SMALL);
        previewBadgeLabel.setOpaque(true);
        previewBadgeLabel.setBackground(Theme.CRITICAL);
        previewBadgeLabel.setForeground(Color.WHITE);

        previewSampleButton = new JButton("Investigate Threat");
        previewSampleButton.setBackground(ThemeSettings.getAccentColor());
        previewSampleButton.setForeground(Color.BLACK);
        previewSampleButton.setFont(Theme.FONT_BODY);
        previewSampleButton.setFocusPainted(false);

        JPanel cardContent = new JPanel(new BorderLayout(5, 5));
        cardContent.setOpaque(false);
        cardContent.add(previewTitleLabel, BorderLayout.NORTH);
        cardContent.add(previewBadgeLabel, BorderLayout.CENTER);

        previewCardPanel.add(cardContent, BorderLayout.NORTH);
        previewCardPanel.add(previewSampleButton, BorderLayout.SOUTH);

        // Add layers (Layer 0 = background, Layer 1 = foreground)
        layeredPane.add(previewBgPanel, Integer.valueOf(0));
        layeredPane.add(previewCardPanel, Integer.valueOf(1));
        previewContainer.add(layeredPane, BorderLayout.CENTER);

        // Right Side: Settings Controls
        JPanel controlsPanel = new JPanel(new GridBagLayout());
        controlsPanel.setOpaque(false);
        controlsPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(Theme.ACCENT), "Theme Configuration",
                0, 0, Theme.FONT_HEADING, Theme.ACCENT));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 10, 8, 10);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Accent Color Row
        gbc.gridx = 0; gbc.gridy = 0;
        JLabel colorLabel = new JLabel("Accent Color:");
        colorLabel.setFont(Theme.FONT_BODY);
        colorLabel.setForeground(Theme.TEXT_PRIMARY);
        controlsPanel.add(colorLabel, gbc);

        gbc.gridx = 1;
        JPanel colorPickerRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        colorPickerRow.setOpaque(false);
        colorSampleBox = new JPanel();
        colorSampleBox.setPreferredSize(new Dimension(28, 28));
        colorSampleBox.setBackground(ThemeSettings.getAccentColor());
        colorSampleBox.setBorder(BorderFactory.createLineBorder(Color.WHITE, 1));

        JButton chooseColorBtn = new JButton("Select Color...");
        Theme.styleButton(chooseColorBtn);
        chooseColorBtn.addActionListener(e -> {
            Color chosen = JColorChooser.showDialog(this, "Select UI Accent Color", ThemeSettings.getAccentColor());
            if (chosen != null) {
                ThemeSettings.setAccentColor(chosen);
                colorSampleBox.setBackground(chosen);
                updateLivePreview();
            }
        });
        colorPickerRow.add(colorSampleBox);
        colorPickerRow.add(chooseColorBtn);
        controlsPanel.add(colorPickerRow, gbc);

        // Font Size Row
        gbc.gridx = 0; gbc.gridy = 1;
        JLabel fontLabel = new JLabel("Font Scaling:");
        fontLabel.setFont(Theme.FONT_BODY);
        fontLabel.setForeground(Theme.TEXT_PRIMARY);
        controlsPanel.add(fontLabel, gbc);

        gbc.gridx = 1;
        fontSizeCombo = new JComboBox<>(new String[]{"Small", "Medium", "Large"});
        fontSizeCombo.setSelectedItem(ThemeSettings.getFontSize());
        fontSizeCombo.addActionListener(e -> {
            String selected = (String) fontSizeCombo.getSelectedItem();
            ThemeSettings.setFontSize(selected);
            updateLivePreview();
        });
        controlsPanel.add(fontSizeCombo, gbc);

        // Dark / Light Mode Radio Buttons
        gbc.gridx = 0; gbc.gridy = 2;
        JLabel modeLabel = new JLabel("Display Mode:");
        modeLabel.setFont(Theme.FONT_BODY);
        modeLabel.setForeground(Theme.TEXT_PRIMARY);
        controlsPanel.add(modeLabel, gbc);

        gbc.gridx = 1;
        JPanel radioRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        radioRow.setOpaque(false);
        darkRadio = new JRadioButton("Dark Mode", ThemeSettings.isDarkMode());
        darkRadio.setOpaque(false);
        darkRadio.setForeground(Theme.TEXT_PRIMARY);
        darkRadio.setFont(Theme.FONT_BODY);

        lightRadio = new JRadioButton("Light Mode", !ThemeSettings.isDarkMode());
        lightRadio.setOpaque(false);
        lightRadio.setForeground(Theme.TEXT_PRIMARY);
        lightRadio.setFont(Theme.FONT_BODY);

        ButtonGroup modeGroup = new ButtonGroup();
        modeGroup.add(darkRadio);
        modeGroup.add(lightRadio);

        darkRadio.addActionListener(e -> {
            ThemeSettings.setDarkMode(true);
            updateLivePreview();
        });
        lightRadio.addActionListener(e -> {
            ThemeSettings.setDarkMode(false);
            updateLivePreview();
        });

        radioRow.add(darkRadio);
        radioRow.add(lightRadio);
        controlsPanel.add(radioRow, gbc);

        // Buttons Row
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 2;
        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 10));
        actionRow.setOpaque(false);

        JButton resetBtn = new JButton("Reset to Defaults");
        resetBtn.setBackground(new Color(60, 60, 90));
        resetBtn.setForeground(Color.WHITE);
        resetBtn.setFont(Theme.FONT_BODY);
        resetBtn.addActionListener(e -> {
            ThemeSettings.resetToDefaults();
            colorSampleBox.setBackground(ThemeSettings.getAccentColor());
            fontSizeCombo.setSelectedItem(ThemeSettings.getFontSize());
            darkRadio.setSelected(ThemeSettings.isDarkMode());
            updateLivePreview();
            JOptionPane.showMessageDialog(this, "Appearance preferences reset to default values.", "Appearance", JOptionPane.INFORMATION_MESSAGE);
        });

        JButton saveBtn = new JButton("Save Appearance");
        Theme.styleButton(saveBtn);
        saveBtn.addActionListener(e -> {
            JOptionPane.showMessageDialog(this, "Appearance preferences saved successfully!", "Appearance", JOptionPane.INFORMATION_MESSAGE);
        });

        actionRow.add(resetBtn);
        actionRow.add(saveBtn);
        controlsPanel.add(actionRow, gbc);

        panel.add(previewContainer, BorderLayout.WEST);
        panel.add(controlsPanel, BorderLayout.CENTER);
        return panel;
    }

    /** Updates the JLayeredPane live preview card in real time. */
    private void updateLivePreview() {
        boolean dark = ThemeSettings.isDarkMode();
        Color accent = ThemeSettings.getAccentColor();
        int baseSize = ThemeSettings.getBaseFontSize();

        previewBgPanel.setBackground(dark ? Theme.BACKGROUND : new Color(240, 243, 246));
        previewCardPanel.setBackground(dark ? Theme.PANEL_BG : Color.WHITE);
        previewCardPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(accent, 2),
                BorderFactory.createEmptyBorder(10, 10, 10, 10)));

        previewTitleLabel.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, baseSize + 2));
        previewTitleLabel.setForeground(dark ? Theme.TEXT_PRIMARY : Color.DARK_GRAY);

        previewSampleButton.setBackground(accent);
        previewSampleButton.setFont(new java.awt.Font("Segoe UI", java.awt.Font.PLAIN, baseSize));

        colorSampleBox.setBackground(accent);
        previewCardPanel.revalidate();
        previewCardPanel.repaint();
    }

    /** Builds Tab 2: System & Alerts with JCheckBoxes and JSlider. */
    private JPanel buildSystemTab() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setOpaque(false);
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridx = 0; gbc.gridy = 0;

        // Alerts group
        JPanel alertsGroup = new JPanel(new GridBagLayout());
        alertsGroup.setOpaque(false);
        alertsGroup.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(Theme.ACCENT), "Notification & Audio Triggers",
                0, 0, Theme.FONT_HEADING, Theme.ACCENT));

        GridBagConstraints agbc = new GridBagConstraints();
        agbc.insets = new Insets(8, 10, 8, 10);
        agbc.anchor = GridBagConstraints.WEST;
        agbc.gridx = 0; agbc.gridy = 0;

        soundAlertsCheck = new JCheckBox("Enable audible alert chime on CRITICAL threats", ThemeSettings.isSoundAlertsEnabled());
        soundAlertsCheck.setOpaque(false);
        soundAlertsCheck.setFont(Theme.FONT_BODY);
        soundAlertsCheck.setForeground(Theme.TEXT_PRIMARY);
        alertsGroup.add(soundAlertsCheck, agbc);

        agbc.gridy = 1;
        autoRefreshCheck = new JCheckBox("Enable automatic background refresh for Dashboard & Live Feeds", ThemeSettings.isAutoRefreshDashboard());
        autoRefreshCheck.setOpaque(false);
        autoRefreshCheck.setFont(Theme.FONT_BODY);
        autoRefreshCheck.setForeground(Theme.TEXT_PRIMARY);
        alertsGroup.add(autoRefreshCheck, agbc);

        agbc.gridy = 2;
        desktopNotificationsCheck = new JCheckBox("Show desktop toast notifications for high-priority incidents", true);
        desktopNotificationsCheck.setOpaque(false);
        desktopNotificationsCheck.setFont(Theme.FONT_BODY);
        desktopNotificationsCheck.setForeground(Theme.TEXT_PRIMARY);
        alertsGroup.add(desktopNotificationsCheck, agbc);

        panel.add(alertsGroup, gbc);

        // Timeout slider group
        gbc.gridy = 1;
        JPanel timeoutGroup = new JPanel(new BorderLayout(10, 10));
        timeoutGroup.setOpaque(false);
        timeoutGroup.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(Theme.ACCENT), "Security Inactivity Timeout (JSlider)",
                0, 0, Theme.FONT_HEADING, Theme.ACCENT));

        timeoutSlider = new JSlider(5, 120, ThemeSettings.getSessionTimeoutMinutes());
        timeoutSlider.setOpaque(false);
        timeoutSlider.setForeground(Theme.TEXT_PRIMARY);
        timeoutSlider.setMajorTickSpacing(15);
        timeoutSlider.setMinorTickSpacing(5);
        timeoutSlider.setPaintTicks(true);
        timeoutSlider.setPaintLabels(true);

        timeoutValueLabel = new JLabel("Inactivity Timeout: " + timeoutSlider.getValue() + " minutes", SwingConstants.CENTER);
        timeoutValueLabel.setFont(Theme.FONT_BODY);
        timeoutValueLabel.setForeground(Theme.ACCENT);

        timeoutSlider.addChangeListener(e -> {
            timeoutValueLabel.setText("Inactivity Timeout: " + timeoutSlider.getValue() + " minutes");
        });

        timeoutGroup.add(timeoutSlider, BorderLayout.CENTER);
        timeoutGroup.add(timeoutValueLabel, BorderLayout.SOUTH);
        panel.add(timeoutGroup, gbc);

        // Save button
        gbc.gridy = 2;
        gbc.anchor = GridBagConstraints.EAST;
        JButton saveSystemBtn = new JButton("Save System Settings");
        Theme.styleButton(saveSystemBtn);
        saveSystemBtn.addActionListener(e -> {
            ThemeSettings.setSoundAlertsEnabled(soundAlertsCheck.isSelected());
            ThemeSettings.setAutoRefreshDashboard(autoRefreshCheck.isSelected());
            ThemeSettings.setSessionTimeoutMinutes(timeoutSlider.getValue());
            JOptionPane.showMessageDialog(this, "System preferences applied successfully!", "System Settings", JOptionPane.INFORMATION_MESSAGE);
        });
        panel.add(saveSystemBtn, gbc);

        return panel;
    }

    /** Builds Tab 3: Security with password modification form. */
    private JPanel buildSecurityTab() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setOpaque(false);
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 10, 8, 10);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.WEST;

        // Active user info
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        securityUserLabel = new JLabel("Logged-in Account: admin (Role: Administrator)");
        securityUserLabel.setFont(Theme.FONT_HEADING);
        securityUserLabel.setForeground(Theme.ACCENT);
        panel.add(securityUserLabel, gbc);

        gbc.gridy = 1;
        JLabel hintLabel = new JLabel("Passwords must contain at least 6 characters.");
        hintLabel.setFont(Theme.FONT_SMALL);
        hintLabel.setForeground(Theme.TEXT_SECONDARY);
        panel.add(hintLabel, gbc);

        // Current Password
        gbc.gridy = 2; gbc.gridwidth = 1;
        JLabel curLabel = new JLabel("Current Password:");
        curLabel.setFont(Theme.FONT_BODY);
        curLabel.setForeground(Theme.TEXT_PRIMARY);
        panel.add(curLabel, gbc);

        gbc.gridx = 1;
        currentPasswordField = new JPasswordField(20);
        panel.add(currentPasswordField, gbc);

        // New Password
        gbc.gridx = 0; gbc.gridy = 3;
        JLabel newLabel = new JLabel("New Password:");
        newLabel.setFont(Theme.FONT_BODY);
        newLabel.setForeground(Theme.TEXT_PRIMARY);
        panel.add(newLabel, gbc);

        gbc.gridx = 1;
        newPasswordField = new JPasswordField(20);
        panel.add(newPasswordField, gbc);

        // Confirm Password
        gbc.gridx = 0; gbc.gridy = 4;
        JLabel confLabel = new JLabel("Confirm New Password:");
        confLabel.setFont(Theme.FONT_BODY);
        confLabel.setForeground(Theme.TEXT_PRIMARY);
        panel.add(confLabel, gbc);

        gbc.gridx = 1;
        confirmPasswordField = new JPasswordField(20);
        panel.add(confirmPasswordField, gbc);

        // Action Button
        gbc.gridx = 0; gbc.gridy = 5; gbc.gridwidth = 2;
        gbc.anchor = GridBagConstraints.EAST;
        JButton updatePassBtn = new JButton("Update Password");
        Theme.styleButton(updatePassBtn);
        updatePassBtn.addActionListener(e -> handleChangePassword());
        panel.add(updatePassBtn, gbc);

        return panel;
    }

    /** Handles password update logic with database verification and audit logging. */
    private void handleChangePassword() {
        if (currentUser == null) {
            JOptionPane.showMessageDialog(this, "No active user session detected. Please log in first.", "Security Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        String currentPass = new String(currentPasswordField.getPassword()).trim();
        String newPass = new String(newPasswordField.getPassword()).trim();
        String confirmPass = new String(confirmPasswordField.getPassword()).trim();

        if (Validator.isEmpty(currentPass) || Validator.isEmpty(newPass) || Validator.isEmpty(confirmPass)) {
            JOptionPane.showMessageDialog(this, "Please fill in all password fields.", "Validation Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Verify current password matches database records
        User verifiedUser = userDAO.validateLogin(currentUser.getUsername(), currentPass);
        if (verifiedUser == null) {
            JOptionPane.showMessageDialog(this, "Incorrect current password. Please try again.", "Authentication Failed", JOptionPane.ERROR_MESSAGE);
            return;
        }

        if (!Validator.isValidPassword(newPass)) {
            JOptionPane.showMessageDialog(this, "New password must be at least 6 characters long.", "Validation Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        if (!newPass.equals(confirmPass)) {
            JOptionPane.showMessageDialog(this, "New password and confirmation do not match.", "Validation Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Update database
        boolean success = userDAO.updatePassword(currentUser.getId(), newPass);
        if (success) {
            logDAO.add(new LogEntry(currentUser.getId(), "Password changed for user: " + currentUser.getUsername()));
            JOptionPane.showMessageDialog(this, "Password updated successfully!", "Security Success", JOptionPane.INFORMATION_MESSAGE);
            currentPasswordField.setText("");
            newPasswordField.setText("");
            confirmPasswordField.setText("");
        } else {
            JOptionPane.showMessageDialog(this, "Failed to update password in database.", "Database Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    /** Builds Tab 4: About & System Info metadata page. */
    private JPanel buildAboutTab() {
        JPanel panel = new JPanel(new BorderLayout(15, 15));
        panel.setOpaque(false);
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        JPanel contentPanel = new JPanel(new GridBagLayout());
        contentPanel.setOpaque(false);

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 10, 8, 10);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridx = 0; gbc.gridy = 0;

        JLabel appTitle = new JLabel("CYBERSHIELD DEFENSE SUITE");
        appTitle.setFont(Theme.FONT_TITLE);
        appTitle.setForeground(Theme.ACCENT);
        contentPanel.add(appTitle, gbc);

        gbc.gridy = 1;
        JLabel subTitle = new JLabel("Cybersecurity Threat Monitoring & Incident Response System");
        subTitle.setFont(Theme.FONT_HEADING);
        subTitle.setForeground(Theme.TEXT_PRIMARY);
        contentPanel.add(subTitle, gbc);

        gbc.gridy = 2;
        JLabel courseLabel = new JLabel("Course: Advanced Object-Oriented Programming (AOOP) — Final Capstone Project");
        courseLabel.setFont(Theme.FONT_BODY);
        courseLabel.setForeground(Theme.TEXT_SECONDARY);
        contentPanel.add(courseLabel, gbc);

        gbc.gridy = 3;
        JLabel verLabel = new JLabel("Release: Version 1.0.0 (Production Viva Build) | Java 17 | Pure Swing & JDBC");
        verLabel.setFont(Theme.FONT_BODY);
        verLabel.setForeground(Theme.TEXT_SECONDARY);
        contentPanel.add(verLabel, gbc);

        // Team division breakdown
        gbc.gridy = 4;
        JPanel teamPanel = new JPanel(new GridBagLayout());
        teamPanel.setOpaque(false);
        teamPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(Theme.ACCENT), "Student Team Modules & Architecture",
                0, 0, Theme.FONT_HEADING, Theme.ACCENT));

        GridBagConstraints tgbc = new GridBagConstraints();
        tgbc.insets = new Insets(6, 10, 6, 10);
        tgbc.anchor = GridBagConstraints.WEST;
        tgbc.gridx = 0; tgbc.gridy = 0;

        JLabel m1 = new JLabel("• Module A (Student 1): Authentication, User Management & Executive Dashboard");
        m1.setFont(Theme.FONT_BODY);
        m1.setForeground(Theme.TEXT_PRIMARY);
        teamPanel.add(m1, tgbc);

        tgbc.gridy = 1;
        JLabel m2 = new JLabel("• Module B (Student 2): Threat Monitoring, Live Detection, Filtering & Severity Charts");
        m2.setFont(Theme.FONT_BODY);
        m2.setForeground(Theme.TEXT_PRIMARY);
        teamPanel.add(m2, tgbc);

        tgbc.gridy = 2;
        JLabel m3 = new JLabel("• Module C (Student 3): Incident Response, Investigation Dialogs, Reports & System Settings");
        m3.setFont(Theme.FONT_BODY);
        m3.setForeground(Theme.TEXT_PRIMARY);
        teamPanel.add(m3, tgbc);

        contentPanel.add(teamPanel, gbc);
        panel.add(contentPanel, BorderLayout.NORTH);
        return panel;
    }

    /** Updates the security tab user display. */
    private void updateSecurityUserInfo() {
        if (currentUser != null && securityUserLabel != null) {
            securityUserLabel.setText("Logged-in Account: " + currentUser.getUsername() + " (Role: " + currentUser.getRole() + ")");
        }
    }

    /** Refreshes settings data when tab is selected. */
    @Override
    public void refreshData() {
        updateSecurityUserInfo();
        updateLivePreview();
    }
}
