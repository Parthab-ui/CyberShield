package com.cybershield.ui.dialogs;

import com.cybershield.ui.CyberTheme;
import com.cybershield.ui.components.CyberTable;
import com.cybershield.ui.components.StyledButton;
import com.cybershield.util.ProjectMetadata;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import javax.swing.BorderFactory;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableModel;

/**
 * Interactive Dialog showcasing Project Title, Team Members Details,
 * and the complete Java Swing Component Checklist for the October 1st First Review.
 */
public class ProjectTeamDialog extends JDialog {

    private JTextField txtTitle;
    private JTextField txtCourse;
    private JTextField txtDept;
    private JTextField txtM1Name, txtM1Roll, txtM1Role;
    private JTextField txtM2Name, txtM2Roll, txtM2Role;
    private JTextField txtM3Name, txtM3Roll, txtM3Role;

    private JLabel lblCardTitle, lblCardCourse, lblCardReview, lblCardDept;
    private JLabel lblM1Name, lblM1Roll, lblM1Role;
    private JLabel lblM2Name, lblM2Roll, lblM2Role;
    private JLabel lblM3Name, lblM3Roll, lblM3Role;

    public ProjectTeamDialog(Frame owner) {
        super(owner, "CYBERSHIELD — Project Team & Evaluation Details (Review 1)", true);
        setSize(950, 680);
        setMinimumSize(new Dimension(850, 550));
        setLocationRelativeTo(owner);
        getContentPane().setBackground(CyberTheme.BG_DARK);
        setLayout(new BorderLayout(10, 10));

        initUi();
    }

    private void initUi() {
        // Header
        JPanel headerPanel = new JPanel(new BorderLayout(8, 8));
        headerPanel.setBackground(CyberTheme.BG_SIDEBAR);
        headerPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, CyberTheme.BORDER_COLOR),
                BorderFactory.createEmptyBorder(14, 20, 14, 20)
        ));

        JLabel lblHeaderTitle = new JLabel("🎓 FIRST REVIEW DOSSIER — OCT 1ST EVALUATION");
        lblHeaderTitle.setFont(CyberTheme.FONT_TITLE);
        lblHeaderTitle.setForeground(CyberTheme.ACCENT_CYAN);

        JLabel lblSub = new JLabel("Project Title, Team Member Subsystems & Java Swing GUI Front-End Component Audit");
        lblSub.setFont(CyberTheme.FONT_BODY);
        lblSub.setForeground(CyberTheme.TEXT_MUTED);

        headerPanel.add(lblHeaderTitle, BorderLayout.NORTH);
        headerPanel.add(lblSub, BorderLayout.SOUTH);
        add(headerPanel, BorderLayout.NORTH);

        // Center: Tabbed Pane (JTabbedPane)
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setBackground(CyberTheme.BG_DARK);
        tabbedPane.setForeground(CyberTheme.TEXT_PRIMARY);
        tabbedPane.setFont(CyberTheme.FONT_BODY_BOLD);

        tabbedPane.addTab("👥 Team Members & Subsystems", createViewTeamPanel());
        tabbedPane.addTab("✏️ Edit Project & Team Details", createEditTeamPanel());
        tabbedPane.addTab("📋 Swing Components Audit (28+ Used)", createComponentAuditPanel());

        add(tabbedPane, BorderLayout.CENTER);

        // Bottom Action Bar
        JPanel bottomBar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 12, 12));
        bottomBar.setBackground(CyberTheme.BG_SIDEBAR);
        bottomBar.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, CyberTheme.BORDER_COLOR));

        StyledButton btnClose = new StyledButton("Close Dossier", StyledButton.ButtonStyle.SECONDARY);
        btnClose.addActionListener(e -> dispose());
        bottomBar.add(btnClose);

        add(bottomBar, BorderLayout.SOUTH);
    }

    private JPanel createViewTeamPanel() {
        JPanel panel = new JPanel(new BorderLayout(12, 12));
        panel.setBackground(CyberTheme.BG_DARK);
        panel.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        // Project Information Card
        JPanel projectInfoCard = new JPanel(new GridLayout(4, 1, 4, 4));
        projectInfoCard.setBackground(CyberTheme.BG_CARD);
        projectInfoCard.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(CyberTheme.ACCENT_CYAN, 1),
                BorderFactory.createEmptyBorder(12, 16, 12, 16)
        ));

        lblCardTitle = new JLabel("Project Title: " + ProjectMetadata.getProjectTitle());
        lblCardTitle.setFont(new Font("Segoe UI", Font.BOLD, 15));
        lblCardTitle.setForeground(CyberTheme.ACCENT_CYAN);

        lblCardCourse = new JLabel("Course / Subject: " + ProjectMetadata.getCourseName());
        lblCardCourse.setFont(CyberTheme.FONT_BODY);
        lblCardCourse.setForeground(CyberTheme.TEXT_PRIMARY);

        lblCardReview = new JLabel("Review Phase: " + ProjectMetadata.getReviewDate());
        lblCardReview.setFont(CyberTheme.FONT_BODY_BOLD);
        lblCardReview.setForeground(CyberTheme.STATUS_GREEN);

        lblCardDept = new JLabel("Department: " + ProjectMetadata.getDepartment());
        lblCardDept.setFont(CyberTheme.FONT_SMALL);
        lblCardDept.setForeground(CyberTheme.TEXT_MUTED);

        projectInfoCard.add(lblCardTitle);
        projectInfoCard.add(lblCardCourse);
        projectInfoCard.add(lblCardReview);
        projectInfoCard.add(lblCardDept);

        panel.add(projectInfoCard, BorderLayout.NORTH);

        // 3 Team Member Cards
        JPanel membersGrid = new JPanel(new GridLayout(3, 1, 10, 10));
        membersGrid.setOpaque(false);

        // Member 1
        JPanel m1Card = createMemberCard("MEMBER 1 — TEAM LEAD & ARCHITECTURE",
                lblM1Name = new JLabel("Name: " + ProjectMetadata.getMember1Name()),
                lblM1Roll = new JLabel("Roll / Register No: " + ProjectMetadata.getMember1Roll()),
                lblM1Role = new JLabel("Subsystem & Viva Deliverables: " + ProjectMetadata.getMember1Role()),
                CyberTheme.ACCENT_CYAN);

        // Member 2
        JPanel m2Card = createMemberCard("MEMBER 2 — DETECTION & HEURISTIC ENGINE LEAD",
                lblM2Name = new JLabel("Name: " + ProjectMetadata.getMember2Name()),
                lblM2Roll = new JLabel("Roll / Register No: " + ProjectMetadata.getMember2Roll()),
                lblM2Role = new JLabel("Subsystem & Viva Deliverables: " + ProjectMetadata.getMember2Role()),
                CyberTheme.STATUS_AMBER);

        // Member 3
        JPanel m3Card = createMemberCard("MEMBER 3 — JAVA SWING GUI & INCIDENT RESPONSE LEAD",
                lblM3Name = new JLabel("Name: " + ProjectMetadata.getMember3Name()),
                lblM3Roll = new JLabel("Roll / Register No: " + ProjectMetadata.getMember3Roll()),
                lblM3Role = new JLabel("Subsystem & Viva Deliverables: " + ProjectMetadata.getMember3Role()),
                CyberTheme.STATUS_GREEN);

        membersGrid.add(m1Card);
        membersGrid.add(m2Card);
        membersGrid.add(m3Card);

        panel.add(membersGrid, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createMemberCard(String header, JLabel lblName, JLabel lblRoll, JLabel lblRole, java.awt.Color accent) {
        JPanel card = new JPanel(new BorderLayout(6, 6));
        card.setBackground(CyberTheme.BG_CARD);
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 4, 0, 0, accent),
                BorderFactory.createCompoundBorder(
                        BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                        BorderFactory.createEmptyBorder(8, 12, 8, 12)
                )
        ));

        JLabel title = new JLabel(header);
        title.setFont(CyberTheme.FONT_BODY_BOLD);
        title.setForeground(accent);

        JPanel details = new JPanel(new GridLayout(3, 1, 2, 2));
        details.setOpaque(false);

        lblName.setFont(CyberTheme.FONT_BODY_BOLD);
        lblName.setForeground(CyberTheme.TEXT_PRIMARY);

        lblRoll.setFont(CyberTheme.FONT_MONO);
        lblRoll.setForeground(CyberTheme.ACCENT_CYAN);

        lblRole.setFont(CyberTheme.FONT_SMALL);
        lblRole.setForeground(CyberTheme.TEXT_MUTED);

        details.add(lblName);
        details.add(lblRoll);
        details.add(lblRole);

        card.add(title, BorderLayout.NORTH);
        card.add(details, BorderLayout.CENTER);
        return card;
    }

    private JPanel createEditTeamPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBackground(CyberTheme.BG_DARK);
        panel.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        JPanel form = new JPanel(new GridBagLayout());
        form.setOpaque(false);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 6, 4, 6);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        int row = 0;

        // Project Info
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 1;
        form.add(createFormLabel("Project Title:"), gbc);
        gbc.gridx = 1; gbc.gridwidth = 3; gbc.weightx = 1.0;
        txtTitle = createFormField(ProjectMetadata.getProjectTitle());
        form.add(txtTitle, gbc);
        row++;

        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 1; gbc.weightx = 0;
        form.add(createFormLabel("Course:"), gbc);
        gbc.gridx = 1; gbc.gridwidth = 1; gbc.weightx = 0.5;
        txtCourse = createFormField(ProjectMetadata.getCourseName());
        form.add(txtCourse, gbc);

        gbc.gridx = 2; gbc.gridwidth = 1; gbc.weightx = 0;
        form.add(createFormLabel("Department:"), gbc);
        gbc.gridx = 3; gbc.gridwidth = 1; gbc.weightx = 0.5;
        txtDept = createFormField(ProjectMetadata.getDepartment());
        form.add(txtDept, gbc);
        row++;

        // Separator
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 4;
        form.add(new JSeparator(), gbc);
        row++;

        // Member 1
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 4;
        JLabel lblM1Section = new JLabel("Member 1 (Team Lead & Database Layer)");
        lblM1Section.setFont(CyberTheme.FONT_BODY_BOLD);
        lblM1Section.setForeground(CyberTheme.ACCENT_CYAN);
        form.add(lblM1Section, gbc);
        row++;

        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 1;
        form.add(createFormLabel("Name:"), gbc);
        gbc.gridx = 1; gbc.gridwidth = 1;
        txtM1Name = createFormField(ProjectMetadata.getMember1Name());
        form.add(txtM1Name, gbc);

        gbc.gridx = 2; gbc.gridwidth = 1;
        form.add(createFormLabel("Roll / Reg No:"), gbc);
        gbc.gridx = 3; gbc.gridwidth = 1;
        txtM1Roll = createFormField(ProjectMetadata.getMember1Roll());
        form.add(txtM1Roll, gbc);
        row++;

        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 1;
        form.add(createFormLabel("Role:"), gbc);
        gbc.gridx = 1; gbc.gridwidth = 3;
        txtM1Role = createFormField(ProjectMetadata.getMember1Role());
        form.add(txtM1Role, gbc);
        row++;

        // Member 2
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 4;
        JLabel lblM2Section = new JLabel("Member 2 (Detection & Heuristic Simulation Lead)");
        lblM2Section.setFont(CyberTheme.FONT_BODY_BOLD);
        lblM2Section.setForeground(CyberTheme.STATUS_AMBER);
        form.add(lblM2Section, gbc);
        row++;

        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 1;
        form.add(createFormLabel("Name:"), gbc);
        gbc.gridx = 1; gbc.gridwidth = 1;
        txtM2Name = createFormField(ProjectMetadata.getMember2Name());
        form.add(txtM2Name, gbc);

        gbc.gridx = 2; gbc.gridwidth = 1;
        form.add(createFormLabel("Roll / Reg No:"), gbc);
        gbc.gridx = 3; gbc.gridwidth = 1;
        txtM2Roll = createFormField(ProjectMetadata.getMember2Roll());
        form.add(txtM2Roll, gbc);
        row++;

        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 1;
        form.add(createFormLabel("Role:"), gbc);
        gbc.gridx = 1; gbc.gridwidth = 3;
        txtM2Role = createFormField(ProjectMetadata.getMember2Role());
        form.add(txtM2Role, gbc);
        row++;

        // Member 3
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 4;
        JLabel lblM3Section = new JLabel("Member 3 (Java Swing GUI & Incident Response Lead)");
        lblM3Section.setFont(CyberTheme.FONT_BODY_BOLD);
        lblM3Section.setForeground(CyberTheme.STATUS_GREEN);
        form.add(lblM3Section, gbc);
        row++;

        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 1;
        form.add(createFormLabel("Name:"), gbc);
        gbc.gridx = 1; gbc.gridwidth = 1;
        txtM3Name = createFormField(ProjectMetadata.getMember3Name());
        form.add(txtM3Name, gbc);

        gbc.gridx = 2; gbc.gridwidth = 1;
        form.add(createFormLabel("Roll / Reg No:"), gbc);
        gbc.gridx = 3; gbc.gridwidth = 1;
        txtM3Roll = createFormField(ProjectMetadata.getMember3Roll());
        form.add(txtM3Roll, gbc);
        row++;

        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 1;
        form.add(createFormLabel("Role:"), gbc);
        gbc.gridx = 1; gbc.gridwidth = 3;
        txtM3Role = createFormField(ProjectMetadata.getMember3Role());
        form.add(txtM3Role, gbc);
        row++;

        JScrollPane scrollForm = new JScrollPane(form);
        scrollForm.setOpaque(false);
        scrollForm.getViewport().setOpaque(false);
        scrollForm.setBorder(BorderFactory.createEmptyBorder());
        panel.add(scrollForm, BorderLayout.CENTER);

        // Save Button
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        btnPanel.setOpaque(false);
        StyledButton btnSave = new StyledButton("💾 Save Details to Disk", StyledButton.ButtonStyle.PRIMARY);
        btnSave.addActionListener(e -> saveDetails());
        btnPanel.add(btnSave);
        panel.add(btnPanel, BorderLayout.SOUTH);

        return panel;
    }

    private void saveDetails() {
        ProjectMetadata.updateDetails(
                txtTitle.getText().trim(),
                txtCourse.getText().trim(),
                txtDept.getText().trim(),
                txtM1Name.getText().trim(),
                txtM1Roll.getText().trim(),
                txtM1Role.getText().trim(),
                txtM2Name.getText().trim(),
                txtM2Roll.getText().trim(),
                txtM2Role.getText().trim(),
                txtM3Name.getText().trim(),
                txtM3Roll.getText().trim(),
                txtM3Role.getText().trim()
        );

        // Update View Labels
        lblCardTitle.setText("Project Title: " + ProjectMetadata.getProjectTitle());
        lblCardCourse.setText("Course / Subject: " + ProjectMetadata.getCourseName());
        lblCardDept.setText("Department: " + ProjectMetadata.getDepartment());

        lblM1Name.setText("Name: " + ProjectMetadata.getMember1Name());
        lblM1Roll.setText("Roll / Register No: " + ProjectMetadata.getMember1Roll());
        lblM1Role.setText("Subsystem & Viva Deliverables: " + ProjectMetadata.getMember1Role());

        lblM2Name.setText("Name: " + ProjectMetadata.getMember2Name());
        lblM2Roll.setText("Roll / Register No: " + ProjectMetadata.getMember2Roll());
        lblM2Role.setText("Subsystem & Viva Deliverables: " + ProjectMetadata.getMember2Role());

        lblM3Name.setText("Name: " + ProjectMetadata.getMember3Name());
        lblM3Roll.setText("Roll / Register No: " + ProjectMetadata.getMember3Roll());
        lblM3Role.setText("Subsystem & Viva Deliverables: " + ProjectMetadata.getMember3Role());

        JOptionPane.showMessageDialog(this,
                "Team and project details successfully saved to data/project_team.properties!",
                "Details Saved", JOptionPane.INFORMATION_MESSAGE);
    }

    private JLabel createFormLabel(String text) {
        JLabel l = new JLabel(text);
        l.setFont(CyberTheme.FONT_BODY);
        l.setForeground(CyberTheme.TEXT_MUTED);
        return l;
    }

    private JTextField createFormField(String val) {
        JTextField tf = new JTextField(val, 20);
        tf.setBackground(CyberTheme.BG_CARD);
        tf.setForeground(CyberTheme.TEXT_PRIMARY);
        tf.setCaretColor(CyberTheme.ACCENT_CYAN);
        tf.setFont(CyberTheme.FONT_BODY);
        tf.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                BorderFactory.createEmptyBorder(4, 8, 4, 8)
        ));
        return tf;
    }

    private JPanel createComponentAuditPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBackground(CyberTheme.BG_DARK);
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JLabel info = new JLabel("Audit of Java Swing Components implemented in CYBERSHIELD (For Maximum Review Marks):");
        info.setFont(CyberTheme.FONT_BODY_BOLD);
        info.setForeground(CyberTheme.ACCENT_CYAN);
        panel.add(info, BorderLayout.NORTH);

        String[] headers = {"#", "Swing Component", "Class Name", "Primary Purpose in CYBERSHIELD", "Implemented In File"};
        Object[][] data = {
            {"1", "JFrame", "javax.swing.JFrame", "Primary top-level SOC application window", "MainDashboardFrame.java"},
            {"2", "JDialog", "javax.swing.JDialog", "Modal dialogs (LoginDialog, ProjectTeamDialog, ThemeChooser)", "LoginDialog.java, ProjectTeamDialog.java"},
            {"3", "JPanel", "javax.swing.JPanel", "Modular structural containers with custom backgrounds", "All Panels & Components"},
            {"4", "JLabel", "javax.swing.JLabel", "Metrics, status badges, dynamic text counters", "MetricCard.java, Header, Panels"},
            {"5", "JButton", "javax.swing.JButton", "Custom themed action buttons with glow hover", "StyledButton.java"},
            {"6", "JToggleButton", "javax.swing.JToggleButton", "Real-time Telemetry Live Stream toggle ON/OFF", "MainDashboardFrame.java Toolbar"},
            {"7", "JCheckBox", "javax.swing.JCheckBox", "Auto-escalate, Auto-refresh, Sound alert toggles", "AttackSimulatorPanel.java, Toolbar"},
            {"8", "JRadioButton", "javax.swing.JRadioButton", "Severity filters & Simulation profile selector", "ThreatMonitorPanel.java, Simulator"},
            {"9", "ButtonGroup", "javax.swing.ButtonGroup", "Mutual exclusion grouping for radio buttons", "ThreatMonitorPanel.java"},
            {"10", "JComboBox", "javax.swing.JComboBox", "Filter dropdowns for Event Types, Roles, Formats", "TelemetryPanel.java, UsersPanel.java"},
            {"11", "JTextField", "javax.swing.JTextField", "Telemetry search, IP address input, user fields", "TelemetryPanel.java, LoginDialog.java"},
            {"12", "JPasswordField", "javax.swing.JPasswordField", "Secure masked password inputs", "LoginDialog.java, UsersPanel.java"},
            {"13", "JTextArea", "javax.swing.JTextArea", "Raw payload viewer, simulation execution traces", "TelemetryPanel.java, SimulatorPanel.java"},
            {"14", "JTextPane", "javax.swing.JTextPane", "Rich HTML-styled polymorphic threat dossiers", "ThreatMonitorPanel.java"},
            {"15", "JTable", "javax.swing.JTable", "Tabular data display with custom cell renderers", "CyberTable.java"},
            {"16", "JScrollPane", "javax.swing.JScrollPane", "Themed scroll panes for tables, trees, & text areas", "CyberTable.java, Panels"},
            {"17", "JSplitPane", "javax.swing.JSplitPane", "Resizable master-detail dividers", "ThreatMonitorPanel.java, IncidentConsole.java"},
            {"18", "JTabbedPane", "javax.swing.JTabbedPane", "Multi-tab navigation across views & reports", "MainDashboardFrame.java, AnalyticsPanel.java"},
            {"19", "JProgressBar", "javax.swing.JProgressBar", "Threat category breakdown & attack progress meters", "AnalyticsPanel.java, SimulatorPanel.java"},
            {"20", "JSlider", "javax.swing.JSlider", "Detection Sensitivity & Simulation Speed sliders", "MainDashboardFrame.java Toolbar"},
            {"21", "JSpinner", "javax.swing.JSpinner", "Auto-refresh rate & query limit number spinners", "MainDashboardFrame.java Toolbar"},
            {"22", "JList", "javax.swing.JList", "Active firewall blocked IP rules & IoC list", "BlockedIpsListPanel.java"},
            {"23", "JTree", "javax.swing.JTree", "Enterprise Infrastructure & MITRE ATT&CK Matrix tree", "MitreAssetTreePanel.java"},
            {"24", "JMenuBar", "javax.swing.JMenuBar", "Top desktop application menu bar", "MainDashboardFrame.java"},
            {"25", "JMenu", "javax.swing.JMenu", "File, View, Simulation, Tools, Review menus", "MainDashboardFrame.java"},
            {"26", "JMenuItem", "javax.swing.JMenuItem", "Action menu items for export, actions, and dialogs", "MainDashboardFrame.java"},
            {"27", "JCheckBoxMenuItem", "javax.swing.JCheckBoxMenuItem", "Menu toggles for High Contrast & Live Monitoring", "MainDashboardFrame.java"},
            {"28", "JRadioButtonMenuItem", "javax.swing.JRadioButtonMenuItem", "Menu simulation profiles (Standard/Training)", "MainDashboardFrame.java"},
            {"29", "JPopupMenu", "javax.swing.JPopupMenu", "Right-click context menus on table rows", "ThreatMonitorPanel.java, CyberTable.java"},
            {"30", "JToolBar", "javax.swing.JToolBar", "Top quick-access SOC operations toolbar", "MainDashboardFrame.java"},
            {"31", "JFileChooser", "javax.swing.JFileChooser", "Export incident audit report to CSV/TXT", "MainDashboardFrame.java"},
            {"32", "JColorChooser", "javax.swing.JColorChooser", "Live interactive SOC theme accent color picker", "MainDashboardFrame.java"},
            {"33", "JSeparator", "javax.swing.JSeparator", "Visual dividers in toolbars, menus, and forms", "MainDashboardFrame.java, Dialogs"},
            {"34", "JToolTip", "javax.swing.JToolTip", "Contextual help tooltips on buttons and widgets", "Throughout all UI controls"},
            {"35", "JOptionPane", "javax.swing.JOptionPane", "Alert, Confirmation, and Input popups", "Throughout all controllers"}
        };

        DefaultTableModel model = new DefaultTableModel(data, headers) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        CyberTable table = new CyberTable(model);
        table.getColumnModel().getColumn(0).setPreferredWidth(35);
        table.getColumnModel().getColumn(1).setPreferredWidth(120);
        table.getColumnModel().getColumn(2).setPreferredWidth(180);
        table.getColumnModel().getColumn(3).setPreferredWidth(320);
        table.getColumnModel().getColumn(4).setPreferredWidth(200);

        JScrollPane scroll = CyberTable.wrapInScrollPane(table);
        panel.add(scroll, BorderLayout.CENTER);
        return panel;
    }
}
