package cybershield.gui;

import cybershield.dao.IncidentDAO;
import cybershield.dao.LogDAO;
import cybershield.dao.ThreatDAO;
import cybershield.dao.UserDAO;
import cybershield.model.Incident;
import cybershield.model.LogEntry;
import cybershield.model.Threat;
import cybershield.util.Theme;
import cybershield.util.Validator;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFormattedTextField;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JToggleButton;

/**
 * IncidentDialog — Modal dialog for creating and editing incident reports.
 * Demonstrates: GridBagLayout, JFormattedTextField, ButtonGroup with JRadioButtons,
 * JToggleButton, JCheckBox, JComboBox data population, and validation.
 */
public class IncidentDialog extends JDialog {

    private IncidentDAO incidentDAO;
    private ThreatDAO   threatDAO;
    private UserDAO     userDAO;
    private LogDAO      logDAO;

    private int currentUserId;
    private Incident existingIncident; // null if creating a new incident
    private boolean saved = false;

    // Form inputs
    private JTextField          titleField;
    private JTextArea           descArea;
    private JFormattedTextField dateField;
    private JComboBox<String>   threatCombo;
    private JComboBox<String>   assignCombo;
    private JRadioButton        rbLow;
    private JRadioButton        rbMedium;
    private JRadioButton        rbHigh;
    private JRadioButton        rbCritical;
    private ButtonGroup         priorityGroup;
    private JToggleButton       escalateToggle;
    private JCheckBox           notifyCheck;
    private JComboBox<String>   statusCombo;

    // Mapping combo label -> threat ID
    private Map<String, Integer> threatMap;

    // Convenience constructor defaulting user ID to 1
    public IncidentDialog(JFrame parent, Incident incidentToEdit) {
        this(parent, 1, incidentToEdit);
    }

    // Constructor for New or Edit mode
    public IncidentDialog(JFrame parent, int currentUserId, Incident incidentToEdit) {
        super(parent, incidentToEdit == null ? "Create New Incident" : "Edit Incident #" + incidentToEdit.getId(),
              Dialog.ModalityType.APPLICATION_MODAL);

        this.incidentDAO      = new IncidentDAO();
        this.threatDAO        = new ThreatDAO();
        this.userDAO          = new UserDAO();
        this.logDAO           = new LogDAO();
        this.currentUserId    = (currentUserId > 0) ? currentUserId : 1;
        this.existingIncident = incidentToEdit;
        this.threatMap        = new HashMap<>();

        setSize(520, 560);
        setLocationRelativeTo(parent);
        setResizable(false);
        getContentPane().setBackground(Theme.BACKGROUND);
        setLayout(new BorderLayout());

        add(createTitlePanel(),  BorderLayout.NORTH);
        add(createFormPanel(),   BorderLayout.CENTER);
        add(createButtonPanel(), BorderLayout.SOUTH);

        if (existingIncident != null) {
            prefillForm(existingIncident);
        }
    }

    /** Returns true if changes were saved to the database. */
    public boolean isSaved() {
        return saved;
    }

    // ================================================================
    // PANEL BUILDERS
    // ================================================================

    /** Creates top header label. */
    private JPanel createTitlePanel() {
        JPanel panel = new JPanel();
        panel.setBackground(Theme.PANEL_BG);
        panel.setBorder(BorderFactory.createEmptyBorder(12, 0, 12, 0));

        JLabel title = new JLabel(existingIncident == null ? "Log Security Incident" : "Update Incident Details");
        title.setFont(Theme.FONT_HEADING);
        title.setForeground(Theme.ACCENT);
        panel.add(title);

        return panel;
    }

    /** Creates form controls laid out via GridBagLayout. */
    private JPanel createFormPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBackground(Theme.BACKGROUND);
        panel.setBorder(BorderFactory.createEmptyBorder(12, 20, 12, 20));

        GridBagConstraints lc = new GridBagConstraints();
        lc.anchor = GridBagConstraints.WEST;
        lc.insets = new Insets(5, 0, 3, 10);
        lc.gridx  = 0;

        GridBagConstraints fc = new GridBagConstraints();
        fc.fill    = GridBagConstraints.HORIZONTAL;
        fc.insets  = new Insets(5, 0, 3, 0);
        fc.gridx   = 1;
        fc.weightx = 1.0;

        // 1. Title
        lc.gridy = 0; fc.gridy = 0;
        panel.add(makeLabel("Title:"), lc);
        titleField = new JTextField(20);
        styleField(titleField);
        panel.add(titleField, fc);

        // 2. Description in JScrollPane
        lc.gridy = 1; fc.gridy = 1;
        panel.add(makeLabel("Description:"), lc);
        descArea = new JTextArea(3, 20);
        descArea.setLineWrap(true);
        descArea.setWrapStyleWord(true);
        descArea.setBackground(Theme.PANEL_BG);
        descArea.setForeground(Theme.TEXT_PRIMARY);
        descArea.setCaretColor(Theme.ACCENT);
        descArea.setFont(Theme.FONT_BODY);
        JScrollPane descScroll = new JScrollPane(descArea);
        descScroll.setBorder(BorderFactory.createLineBorder(Theme.ACCENT));
        panel.add(descScroll, fc);

        // 3. Date field with SimpleDateFormat
        lc.gridy = 2; fc.gridy = 2;
        panel.add(makeLabel("Report Date:"), lc);
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        dateField = new JFormattedTextField(sdf);
        dateField.setValue(new Date());
        styleField(dateField);
        dateField.setToolTipText("Format: yyyy-MM-dd");
        panel.add(dateField, fc);

        // 4. Linked Threat ComboBox
        lc.gridy = 3; fc.gridy = 3;
        panel.add(makeLabel("Linked Threat:"), lc);
        threatCombo = new JComboBox<>();
        styleCombo(threatCombo);
        loadThreatsIntoCombo();
        panel.add(threatCombo, fc);

        // 5. Assigned To ComboBox
        lc.gridy = 4; fc.gridy = 4;
        panel.add(makeLabel("Assign To:"), lc);
        assignCombo = new JComboBox<>();
        styleCombo(assignCombo);
        loadUsersIntoCombo();
        panel.add(assignCombo, fc);

        // 6. Priority Radio Buttons
        lc.gridy = 5; fc.gridy = 5;
        panel.add(makeLabel("Priority:"), lc);
        JPanel priorityPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        priorityPanel.setBackground(Theme.BACKGROUND);

        rbLow      = new JRadioButton("LOW");
        rbMedium   = new JRadioButton("MED");
        rbHigh     = new JRadioButton("HIGH");
        rbCritical = new JRadioButton("CRIT");

        styleRadio(rbLow);
        styleRadio(rbMedium);
        styleRadio(rbHigh);
        styleRadio(rbCritical);
        rbMedium.setSelected(true);

        priorityGroup = new ButtonGroup();
        priorityGroup.add(rbLow);
        priorityGroup.add(rbMedium);
        priorityGroup.add(rbHigh);
        priorityGroup.add(rbCritical);

        priorityPanel.add(rbLow);
        priorityPanel.add(rbMedium);
        priorityPanel.add(rbHigh);
        priorityPanel.add(rbCritical);
        panel.add(priorityPanel, fc);

        // 7. Status dropdown (for Edit mode or default OPEN)
        lc.gridy = 6; fc.gridy = 6;
        panel.add(makeLabel("Status:"), lc);
        statusCombo = new JComboBox<>(new String[]{"OPEN", "IN_PROGRESS", "CLOSED"});
        styleCombo(statusCombo);
        panel.add(statusCombo, fc);

        // 8. Escalate Toggle & Notify Checkbox
        lc.gridy = 7; fc.gridy = 7;
        panel.add(makeLabel("Actions:"), lc);
        JPanel togglePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        togglePanel.setBackground(Theme.BACKGROUND);

        escalateToggle = new JToggleButton("⚡ Escalate");
        escalateToggle.setFont(Theme.FONT_SMALL);
        escalateToggle.setBackground(Theme.PANEL_BG);
        escalateToggle.setForeground(Theme.WARNING);

        // Event listener: Escalate toggle automatically checks CRITICAL priority
        escalateToggle.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (escalateToggle.isSelected()) {
                    rbCritical.setSelected(true);
                    escalateToggle.setBackground(Theme.CRITICAL);
                    escalateToggle.setForeground(Theme.TEXT_PRIMARY);
                } else {
                    escalateToggle.setBackground(Theme.PANEL_BG);
                    escalateToggle.setForeground(Theme.WARNING);
                }
            }
        });

        notifyCheck = new JCheckBox("Notify team via alert");
        notifyCheck.setBackground(Theme.BACKGROUND);
        notifyCheck.setForeground(Theme.TEXT_SECONDARY);
        notifyCheck.setFont(Theme.FONT_SMALL);
        notifyCheck.setSelected(true);

        togglePanel.add(escalateToggle);
        togglePanel.add(notifyCheck);
        panel.add(togglePanel, fc);

        return panel;
    }

    /** Creates Save and Cancel buttons. */
    private JPanel createButtonPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.CENTER, 16, 12));
        panel.setBackground(Theme.PANEL_BG);

        JButton saveBtn = new JButton("Save Incident");
        Theme.styleButton(saveBtn);

        JButton cancelBtn = new JButton("Cancel");
        Theme.styleButton(cancelBtn);
        cancelBtn.setBackground(Theme.PANEL_BG);
        cancelBtn.setForeground(Theme.TEXT_SECONDARY);

        // Event listener: Save clicked
        saveBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                saveIncident();
            }
        });

        // Event listener: Cancel clicked
        cancelBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                dispose();
            }
        });

        panel.add(saveBtn);
        panel.add(cancelBtn);
        return panel;
    }

    // ================================================================
    // LOGIC & DATA HANDLING
    // ================================================================

    /** Loads threats into the combo box. */
    private void loadThreatsIntoCombo() {
        threatCombo.removeAllItems();
        threatMap.clear();

        List<Threat> threats = threatDAO.getAll();
        for (Threat t : threats) {
            String label = "Threat #" + t.getId() + " — " + t.getThreatType() + " (" + t.getSourceIp() + ")";
            threatMap.put(label, t.getId());
            threatCombo.addItem(label);
        }
    }

    /** Loads usernames into the assign dropdown. */
    private void loadUsersIntoCombo() {
        assignCombo.removeAllItems();
        List<String> users = userDAO.getAllUsernames();
        for (String u : users) {
            assignCombo.addItem(u);
        }
    }

    /** Pre-fills fields if editing an existing incident. */
    private void prefillForm(Incident inc) {
        titleField.setText(inc.getTitle());
        descArea.setText(inc.getDescription());
        statusCombo.setSelectedItem(inc.getStatus());

        // Set linked threat
        for (Map.Entry<String, Integer> entry : threatMap.entrySet()) {
            if (entry.getValue() == inc.getThreatId()) {
                threatCombo.setSelectedItem(entry.getKey());
                break;
            }
        }

        // Set assigned username
        String username = userDAO.getUsernameById(inc.getAssignedTo());
        assignCombo.setSelectedItem(username);

        // Set priority radio button
        String p = inc.getPriority();
        if ("LOW".equalsIgnoreCase(p)) rbLow.setSelected(true);
        else if ("MEDIUM".equalsIgnoreCase(p)) rbMedium.setSelected(true);
        else if ("HIGH".equalsIgnoreCase(p)) rbHigh.setSelected(true);
        else if ("CRITICAL".equalsIgnoreCase(p)) {
            rbCritical.setSelected(true);
            escalateToggle.setSelected(true);
        }
    }

    /** Validates and saves the incident to MySQL. */
    private void saveIncident() {
        String title = titleField.getText().trim();
        String desc  = descArea.getText().trim();

        // Rule 1: Title required
        if (Validator.isEmpty(title)) {
            JOptionPane.showMessageDialog(this,
                "Title is required. Please provide a brief title.",
                "Validation Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Rule 2: Description must be at least 10 characters
        if (desc.length() < 10) {
            JOptionPane.showMessageDialog(this,
                "Description must be at least 10 characters long.",
                "Validation Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Selected threat
        String threatLabel = (String) threatCombo.getSelectedItem();
        int threatId = (threatLabel != null && threatMap.containsKey(threatLabel)) ? threatMap.get(threatLabel) : 1;

        // Selected user
        String assignedUser = (String) assignCombo.getSelectedItem();
        int assignedToId = (assignedUser != null) ? userDAO.getUserIdByUsername(assignedUser) : currentUserId;

        // Selected priority
        String priority = "MEDIUM";
        if (rbLow.isSelected()) priority = "LOW";
        else if (rbHigh.isSelected()) priority = "HIGH";
        else if (rbCritical.isSelected()) priority = "CRITICAL";

        String status = (String) statusCombo.getSelectedItem();

        if (existingIncident == null) {
            // New incident
            Incident newInc = new Incident(threatId, title, desc, assignedToId, priority, status);
            incidentDAO.add(newInc);
            logDAO.add(new LogEntry(currentUserId, "Created Incident: " + title));
        } else {
            // Update incident
            existingIncident.setThreatId(threatId);
            existingIncident.setTitle(title);
            existingIncident.setDescription(desc);
            existingIncident.setAssignedTo(assignedToId);
            existingIncident.setPriority(priority);
            existingIncident.setStatus(status);
            incidentDAO.update(existingIncident);
            logDAO.add(new LogEntry(currentUserId, "Updated Incident #" + existingIncident.getId() + ": " + title));
        }

        saved = true;
        JOptionPane.showMessageDialog(this,
            "Incident saved successfully!",
            "Incident Saved", JOptionPane.INFORMATION_MESSAGE);

        dispose();
    }

    // ================================================================
    // STYLING HELPERS
    // ================================================================

    private JLabel makeLabel(String text) {
        JLabel l = new JLabel(text);
        l.setFont(Theme.FONT_BODY);
        l.setForeground(Theme.TEXT_SECONDARY);
        return l;
    }

    private void styleField(JTextField f) {
        f.setBackground(Theme.PANEL_BG);
        f.setForeground(Theme.TEXT_PRIMARY);
        f.setCaretColor(Theme.ACCENT);
        f.setFont(Theme.FONT_BODY);
        f.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Theme.ACCENT),
            BorderFactory.createEmptyBorder(4, 6, 4, 6)
        ));
    }

    private void styleCombo(JComboBox<String> c) {
        c.setBackground(Theme.PANEL_BG);
        c.setForeground(Theme.TEXT_PRIMARY);
        c.setFont(Theme.FONT_BODY);
    }

    private void styleRadio(JRadioButton rb) {
        rb.setBackground(Theme.BACKGROUND);
        rb.setForeground(Theme.TEXT_PRIMARY);
        rb.setFont(Theme.FONT_SMALL);
    }
}
