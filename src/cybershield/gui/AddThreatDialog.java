package cybershield.gui;

import cybershield.dao.LogDAO;
import cybershield.dao.ThreatDAO;
import cybershield.model.LogEntry;
import cybershield.model.Threat;
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
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;

/**
 * AddThreatDialog — Modal dialog allowing security analysts to manually record a new threat.
 * Demonstrates JDialog, Form Input, Field Validation (IPv4 format), and DAO delegation.
 */
public class AddThreatDialog extends JDialog {

    private ThreatDAO threatDAO;
    private LogDAO    logDAO;
    private int       userId;
    private boolean   saved = false;

    // Form inputs
    private JTextField        sourceIpField;
    private JComboBox<String> typeCombo;
    private JComboBox<String> severityCombo;
    private JTextField        targetSystemField;
    private JComboBox<String> statusCombo;

    // Constructor — builds the modal dialog
    public AddThreatDialog(JFrame parent, int userId) {
        super(parent, "Add New Cybersecurity Threat", Dialog.ModalityType.APPLICATION_MODAL);
        this.threatDAO = new ThreatDAO();
        this.logDAO    = new LogDAO();
        this.userId    = (userId > 0) ? userId : 1;

        setSize(420, 380);
        setLocationRelativeTo(parent);
        setResizable(false);
        getContentPane().setBackground(Theme.BACKGROUND);
        setLayout(new BorderLayout());

        add(createTitlePanel(),  BorderLayout.NORTH);
        add(createFormPanel(),   BorderLayout.CENTER);
        add(createButtonPanel(), BorderLayout.SOUTH);
    }

    /** Returns true if a threat was successfully saved to the database. */
    public boolean isSaved() {
        return saved;
    }

    // ================================================================
    // PANEL BUILDERS
    // ================================================================

    /** Creates the dialog header. */
    private JPanel createTitlePanel() {
        JPanel panel = new JPanel();
        panel.setBackground(Theme.PANEL_BG);
        panel.setBorder(BorderFactory.createEmptyBorder(12, 0, 12, 0));

        JLabel title = new JLabel("Log New Threat Record");
        title.setFont(Theme.FONT_HEADING);
        title.setForeground(Theme.ACCENT);
        panel.add(title);

        return panel;
    }

    /** Creates the form panel with labels and input controls. */
    private JPanel createFormPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBackground(Theme.BACKGROUND);
        panel.setBorder(BorderFactory.createEmptyBorder(15, 25, 10, 25));

        GridBagConstraints labelC = new GridBagConstraints();
        labelC.anchor  = GridBagConstraints.WEST;
        labelC.insets  = new Insets(6, 0, 4, 12);
        labelC.gridx   = 0;

        GridBagConstraints fieldC = new GridBagConstraints();
        fieldC.fill    = GridBagConstraints.HORIZONTAL;
        fieldC.insets  = new Insets(6, 0, 4, 0);
        fieldC.gridx   = 1;
        fieldC.weightx = 1.0;

        // ---- Threat Type ----
        labelC.gridy = 0; fieldC.gridy = 0;
        panel.add(makeLabel("Threat Type:"), labelC);
        typeCombo = new JComboBox<>(new String[]{
            "Phishing", "Malware", "DDoS", "SQL Injection",
            "Brute Force", "Ransomware", "Port Scan", "Zero-Day Exploit"
        });
        styleCombo(typeCombo);
        panel.add(typeCombo, fieldC);

        // ---- Source IP ----
        labelC.gridy = 1; fieldC.gridy = 1;
        panel.add(makeLabel("Source IP:"), labelC);
        sourceIpField = new JTextField(15);
        sourceIpField.setText("192.168.1.50");
        styleField(sourceIpField);
        panel.add(sourceIpField, fieldC);

        // ---- Target System ----
        labelC.gridy = 2; fieldC.gridy = 2;
        panel.add(makeLabel("Target System:"), labelC);
        targetSystemField = new JTextField(15);
        targetSystemField.setText("Web Server");
        styleField(targetSystemField);
        panel.add(targetSystemField, fieldC);

        // ---- Severity ----
        labelC.gridy = 3; fieldC.gridy = 3;
        panel.add(makeLabel("Severity:"), labelC);
        severityCombo = new JComboBox<>(new String[]{"LOW", "MEDIUM", "HIGH", "CRITICAL"});
        severityCombo.setSelectedItem("HIGH");
        styleCombo(severityCombo);
        panel.add(severityCombo, fieldC);

        // ---- Initial Status ----
        labelC.gridy = 4; fieldC.gridy = 4;
        panel.add(makeLabel("Initial Status:"), labelC);
        statusCombo = new JComboBox<>(new String[]{"DETECTED", "INVESTIGATING", "RESOLVED"});
        styleCombo(statusCombo);
        panel.add(statusCombo, fieldC);

        return panel;
    }

    /** Creates the Save and Cancel buttons. */
    private JPanel createButtonPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.CENTER, 16, 12));
        panel.setBackground(Theme.PANEL_BG);

        JButton saveButton = new JButton("Save Threat");
        Theme.styleButton(saveButton);

        JButton cancelButton = new JButton("Cancel");
        Theme.styleButton(cancelButton);
        cancelButton.setBackground(Theme.PANEL_BG);
        cancelButton.setForeground(Theme.TEXT_SECONDARY);

        // Event listener: triggered when Save Threat button is clicked (ActionListener)
        saveButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                saveThreat();
            }
        });

        // Event listener: triggered when Cancel button is clicked (ActionListener)
        cancelButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                dispose(); // Close without saving
            }
        });

        panel.add(saveButton);
        panel.add(cancelButton);
        return panel;
    }

    // ================================================================
    // LOGIC & VALIDATION
    // ================================================================

    /** Validates user input and inserts the new threat into MySQL. */
    private void saveThreat() {
        String type     = (String) typeCombo.getSelectedItem();
        String sourceIp = sourceIpField.getText().trim();
        String target   = targetSystemField.getText().trim();
        String severity = (String) severityCombo.getSelectedItem();
        String status   = (String) statusCombo.getSelectedItem();

        // 1. Check for empty fields
        if (Validator.isEmpty(sourceIp) || Validator.isEmpty(target)) {
            JOptionPane.showMessageDialog(this,
                "Source IP and Target System cannot be empty.",
                "Validation Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // 2. Validate IPv4 address format
        if (!Validator.isValidIP(sourceIp)) {
            JOptionPane.showMessageDialog(this,
                "Please enter a valid IPv4 address (e.g. 192.168.1.100).",
                "Invalid IP Address", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // 3. Insert into database
        Threat newThreat = new Threat(type, sourceIp, target, severity, status);
        threatDAO.add(newThreat);

        // 4. Log the action
        logDAO.add(new LogEntry(userId, "Manual threat logged: " + type + " against " + target));

        saved = true;
        JOptionPane.showMessageDialog(this,
            "Threat recorded successfully!\nType: " + type + "\nTarget: " + target,
            "Threat Logged", JOptionPane.INFORMATION_MESSAGE);

        dispose(); // Close the dialog
    }

    // ================================================================
    // STYLING HELPERS
    // ================================================================

    /** Creates a styled form label. */
    private JLabel makeLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(Theme.FONT_BODY);
        label.setForeground(Theme.TEXT_SECONDARY);
        return label;
    }

    /** Applies dark theme styling to a text field. */
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

    /** Applies dark theme styling to a combo box. */
    private void styleCombo(JComboBox<String> combo) {
        combo.setBackground(Theme.PANEL_BG);
        combo.setForeground(Theme.TEXT_PRIMARY);
        combo.setFont(Theme.FONT_BODY);
    }
}
