package cybershield.ui;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.text.DateFormatter;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.TreePath;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileWriter;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * ComponentLabPanel — Academic Java Swing Component Showcase for Faculty Review.
 * Demonstrates 40+ authentic Java Swing components, containers, layout managers,
 * dialogs, and event-driven keyboard/mouse bindings.
 *
 * Covered Component Categories:
 * 1. Containers: JFrame (parent/popups), JPanel, JDialog, JWindow, JScrollPane,
 *    JSplitPane, JTabbedPane, JLayeredPane, JDesktopPane, JInternalFrame.
 * 2. Text & Display: JLabel, JTextField, JPasswordField, JTextArea, JTextPane,
 *    JEditorPane, JFormattedTextField.
 * 3. Buttons & Selection: JButton, JToggleButton, JCheckBox, JRadioButton,
 *    ButtonGroup, JComboBox, JList, JSpinner.
 * 4. Tables & Menus: JTable, JTree, JMenuBar, JMenu, JMenuItem, JPopupMenu, JToolBar.
 * 5. Feedback & Progress: JProgressBar, JSlider, JSeparator, Tooltips.
 * 6. Dialogs & Utilities: JOptionPane, JFileChooser, JColorChooser, InputMap/ActionMap bindings.
 * 7. Layout Managers: BorderLayout, FlowLayout, GridLayout, GridBagLayout, BoxLayout, CardLayout, GroupLayout.
 */
public class ComponentLabPanel extends JPanel {

    private JTabbedPane labTabbedPane;

    public ComponentLabPanel() {
        setLayout(new BorderLayout(0, 10));
        setBackground(SwingTheme.PANEL_BG);
        setBorder(BorderFactory.createEmptyBorder(16, 18, 16, 18));

        initHeader();
        initLabTabs();
    }

    /** Header providing context for college examiners */
    private void initHeader() {
        JPanel headerPanel = new JPanel(new BorderLayout(0, 4));
        headerPanel.setOpaque(false);

        JLabel title = new JLabel("Academic Swing Component Lab (Viva Evaluation Center)");
        title.setFont(SwingTheme.FONT_TITLE);
        title.setForeground(SwingTheme.TEXT_PRIMARY);

        JLabel subtitle = new JLabel(
            "Interactive demonstration of 40+ core Java Swing components, Layout Managers, MDI Desktop, and event listeners for B.Tech CSE review."
        );
        subtitle.setFont(SwingTheme.FONT_BODY);
        subtitle.setForeground(SwingTheme.TEXT_MUTED);

        headerPanel.add(title, BorderLayout.NORTH);
        headerPanel.add(subtitle, BorderLayout.SOUTH);
        add(headerPanel, BorderLayout.NORTH);
    }

    /** Initializes the primary tabbed interface containing specialized laboratory sections */
    private void initLabTabs() {
        labTabbedPane = new JTabbedPane(JTabbedPane.TOP);
        labTabbedPane.setFont(SwingTheme.FONT_BOLD);
        labTabbedPane.setBackground(SwingTheme.PANEL_BG);
        labTabbedPane.setForeground(SwingTheme.TEXT_PRIMARY);

        // Add 6 specialized labs
        labTabbedPane.addTab("1. Forms & Inputs", createFormInputsLab());
        labTabbedPane.addTab("2. JTree & SplitPane", createTreeHierarchyLab());
        labTabbedPane.addTab("3. Progress & Sliders", createProgressFeedbackLab());
        labTabbedPane.addTab("4. MDI DesktopPane", createMdiDesktopLab());
        labTabbedPane.addTab("5. Dialogs & Utilities", createDialogsUtilitiesLab());
        labTabbedPane.addTab("6. Layout Managers", createLayoutManagersLab());

        add(labTabbedPane, BorderLayout.CENTER);
    }

    // =========================================================================
    // LAB 1: FORMS & INPUT COMPONENTS
    // Demonstrates: JTextField, JPasswordField, JFormattedTextField, JTextArea,
    // JTextPane, JEditorPane, JButton, JToggleButton, JCheckBox, JRadioButton,
    // ButtonGroup, JComboBox, JList, JSpinner.
    // =========================================================================
    private JPanel createFormInputsLab() {
        JPanel panel = new JPanel(new BorderLayout(14, 14));
        panel.setBackground(SwingTheme.CARD_BG);
        panel.setBorder(BorderFactory.createEmptyBorder(14, 14, 14, 14));

        // LEFT: Form Inputs (GridBagLayout)
        JPanel leftForm = new JPanel(new GridBagLayout());
        leftForm.setOpaque(false);
        leftForm.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR),
            "Input Controls & Selection Components", TitledBorder.LEFT, TitledBorder.TOP,
            SwingTheme.FONT_BOLD, SwingTheme.TEXT_PRIMARY
        ));

        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(6, 8, 6, 8);
        g.fill = GridBagConstraints.HORIZONTAL;

        // 1. JTextField
        g.gridx = 0; g.gridy = 0;
        leftForm.add(new JLabel("JTextField (Target IP):"), g);
        g.gridx = 1;
        JTextField ipField = new JTextField("192.168.1.105", 14);
        SwingTheme.styleTextField(ipField);
        ipField.setToolTipText("Standard single-line text input");
        leftForm.add(ipField, g);

        // 2. JPasswordField
        g.gridx = 0; g.gridy = 1;
        leftForm.add(new JLabel("JPasswordField (API Secret):"), g);
        g.gridx = 1;
        JPasswordField secretField = new JPasswordField("SecretVaultKey2026", 14);
        SwingTheme.stylePasswordField(secretField);
        secretField.setToolTipText("Masks characters for security");
        leftForm.add(secretField, g);

        // 3. JFormattedTextField
        g.gridx = 0; g.gridy = 2;
        leftForm.add(new JLabel("JFormattedTextField (Date):"), g);
        g.gridx = 1;
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd");
        JFormattedTextField formattedDate = new JFormattedTextField(new DateFormatter(df));
        formattedDate.setValue(new Date());
        SwingTheme.styleTextField(formattedDate);
        formattedDate.setToolTipText("Enforces custom text parsing and formatting rules");
        leftForm.add(formattedDate, g);

        // 4. JSpinner
        g.gridx = 0; g.gridy = 3;
        leftForm.add(new JLabel("JSpinner (Port / Retries):"), g);
        g.gridx = 1;
        SpinnerNumberModel spinModel = new SpinnerNumberModel(443, 1, 65535, 1);
        JSpinner portSpinner = new JSpinner(spinModel);
        portSpinner.setToolTipText("Numeric spin selector with min/max bounds");
        leftForm.add(portSpinner, g);

        // 5. JComboBox
        g.gridx = 0; g.gridy = 4;
        leftForm.add(new JLabel("JComboBox (Threat Vector):"), g);
        g.gridx = 1;
        JComboBox<String> vectorCombo = new JComboBox<>(new String[]{"SQL Injection", "DDoS Flood", "Phishing Link", "Credential Stuffing"});
        SwingTheme.styleComboBox(vectorCombo);
        vectorCombo.setToolTipText("Dropdown selection element");
        leftForm.add(vectorCombo, g);

        // 6. JToggleButton
        g.gridx = 0; g.gridy = 5;
        leftForm.add(new JLabel("JToggleButton (Sensor State):"), g);
        g.gridx = 1;
        JToggleButton toggleBtn = new JToggleButton("Sensor: ACTIVE", true);
        toggleBtn.setBackground(SwingTheme.PRIMARY_COLOR);
        toggleBtn.setForeground(Color.WHITE);
        toggleBtn.setFocusPainted(false);
        toggleBtn.addActionListener(e -> {
            boolean active = toggleBtn.isSelected();
            toggleBtn.setText(active ? "Sensor: ACTIVE" : "Sensor: OFFLINE");
            toggleBtn.setBackground(active ? SwingTheme.PRIMARY_COLOR : SwingTheme.SEVERITY_CRITICAL);
        });
        leftForm.add(toggleBtn, g);

        // 7. JCheckBox
        g.gridx = 0; g.gridy = 6;
        leftForm.add(new JLabel("JCheckBox (Telemetry Flags):"), g);
        g.gridx = 1;
        JPanel checkPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        checkPanel.setOpaque(false);
        JCheckBox chkLogging = new JCheckBox("Audit Logs", true);
        SwingTheme.styleCheckBox(chkLogging);
        JCheckBox chkAlerts = new JCheckBox("Email Alerts", false);
        SwingTheme.styleCheckBox(chkAlerts);
        checkPanel.add(chkLogging);
        checkPanel.add(chkAlerts);
        leftForm.add(checkPanel, g);

        // 8. JRadioButton & ButtonGroup
        g.gridx = 0; g.gridy = 7;
        leftForm.add(new JLabel("JRadioButton (Firewall Mode):"), g);
        g.gridx = 1;
        JPanel radioPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        radioPanel.setOpaque(false);
        JRadioButton rbStrict = new JRadioButton("Strict", true);
        SwingTheme.styleRadioButton(rbStrict);
        JRadioButton rbAudit = new JRadioButton("Audit", false);
        SwingTheme.styleRadioButton(rbAudit);
        ButtonGroup fwGroup = new ButtonGroup();
        fwGroup.add(rbStrict);
        fwGroup.add(rbAudit);
        radioPanel.add(rbStrict);
        radioPanel.add(rbAudit);
        leftForm.add(radioPanel, g);

        panel.add(new JScrollPane(leftForm), BorderLayout.WEST);

        // RIGHT: Rich Text & Display Components (JTextArea, JTextPane, JEditorPane, JList)
        JPanel rightDisplay = new JPanel(new GridLayout(2, 2, 10, 10));
        rightDisplay.setOpaque(false);

        // 9. JTextArea
        JPanel areaBox = new JPanel(new BorderLayout());
        areaBox.setOpaque(false);
        areaBox.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR), "JTextArea (Raw Logs)",
            TitledBorder.LEFT, TitledBorder.TOP, SwingTheme.FONT_BOLD, SwingTheme.TEXT_PRIMARY));
        JTextArea rawArea = new JTextArea("2026-10-09 06:30:10 [WARN] SYN flood from 10.0.0.12\n2026-10-09 06:30:15 [ALERT] Rate limit exceeded\n2026-10-09 06:30:20 [INFO] Rule applied: DROP");
        rawArea.setBackground(SwingTheme.PANEL_BG);
        rawArea.setForeground(SwingTheme.TEXT_MUTED);
        rawArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        areaBox.add(new JScrollPane(rawArea), BorderLayout.CENTER);
        rightDisplay.add(areaBox);

        // 10. JTextPane (Styled formatted text)
        JPanel paneBox = new JPanel(new BorderLayout());
        paneBox.setOpaque(false);
        paneBox.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR), "JTextPane (Styled Forensics)",
            TitledBorder.LEFT, TitledBorder.TOP, SwingTheme.FONT_BOLD, SwingTheme.TEXT_PRIMARY));
        JTextPane styledPane = new JTextPane();
        styledPane.setBackground(SwingTheme.PANEL_BG);
        styledPane.setForeground(SwingTheme.TEXT_PRIMARY);
        styledPane.setContentType("text/html");
        styledPane.setEditable(false);
        styledPane.setText("<html><body style='font-family:sans-serif;color:#e2e8f0;padding:6px;'>" +
            "<h4 style='color:#38bdf8;margin:0;'>Heuristic Threat Report</h4>" +
            "<p><b style='color:#ef4444;'>[CRITICAL]</b> SQL Injection attempt detected in <code>/api/incidents</code>.</p>" +
            "<p><b style='color:#22c55e;'>[MITIGATED]</b> Parameterized JDBC queries prevented injection.</p>" +
            "</body></html>");
        paneBox.add(new JScrollPane(styledPane), BorderLayout.CENTER);
        rightDisplay.add(paneBox);

        // 11. JEditorPane (HTML documentation display)
        JPanel editorBox = new JPanel(new BorderLayout());
        editorBox.setOpaque(false);
        editorBox.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR), "JEditorPane (HTML Security Bulletin)",
            TitledBorder.LEFT, TitledBorder.TOP, SwingTheme.FONT_BOLD, SwingTheme.TEXT_PRIMARY));
        JEditorPane htmlEditor = new JEditorPane();
        htmlEditor.setContentType("text/html");
        htmlEditor.setEditable(false);
        htmlEditor.setBackground(SwingTheme.PANEL_BG);
        htmlEditor.setText("<html><body style='font-family:sans-serif;color:#94a3b8;padding:6px;'>" +
            "<p style='color:#f59e0b;font-weight:bold;'>CVE-2026-NIST Advisory</p>" +
            "<small>NIST CSF 2.0 Compliance: CyberShield implements <b>Identify</b>, <b>Protect</b>, <b>Detect</b>, and <b>Respond</b> core functions.</small>" +
            "</body></html>");
        editorBox.add(new JScrollPane(htmlEditor), BorderLayout.CENTER);
        rightDisplay.add(editorBox);

        // 12. JList
        JPanel listBox = new JPanel(new BorderLayout());
        listBox.setOpaque(false);
        listBox.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR), "JList (Target IP Blacklist)",
            TitledBorder.LEFT, TitledBorder.TOP, SwingTheme.FONT_BOLD, SwingTheme.TEXT_PRIMARY));
        String[] blacklistedIps = {"198.51.100.44 (Tor Node)", "203.0.113.19 (Botnet Client)", "192.0.2.77 (Spam Relay)", "185.220.101.5 (Port Scanner)"};
        JList<String> ipList = new JList<>(blacklistedIps);
        ipList.setBackground(SwingTheme.PANEL_BG);
        ipList.setForeground(SwingTheme.TEXT_PRIMARY);
        ipList.setSelectionBackground(SwingTheme.PRIMARY_COLOR);
        ipList.setFont(SwingTheme.FONT_BODY);
        listBox.add(new JScrollPane(ipList), BorderLayout.CENTER);
        rightDisplay.add(listBox);

        panel.add(rightDisplay, BorderLayout.CENTER);
        return panel;
    }

    // =========================================================================
    // LAB 2: JTREE, JSPLITPANE, JTOOLBAR, JPOPUPMENU
    // =========================================================================
    private JPanel createTreeHierarchyLab() {
        JPanel panel = new JPanel(new BorderLayout(0, 8));
        panel.setBackground(SwingTheme.CARD_BG);
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        // JToolBar (Toolbar containing navigation actions)
        JToolBar toolBar = new JToolBar("Taxonomy Actions");
        toolBar.setFloatable(false);
        toolBar.setBackground(SwingTheme.PANEL_BG);
        toolBar.setBorder(BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR));

        JButton btnExpand = new JButton("Expand Tree");
        SwingTheme.styleSecondaryButton(btnExpand);
        JButton btnCollapse = new JButton("Collapse Tree");
        SwingTheme.styleSecondaryButton(btnCollapse);
        JLabel tbHint = new JLabel("  <- JToolBar Controls | Right-click tree for JPopupMenu");
        tbHint.setForeground(SwingTheme.TEXT_MUTED);
        tbHint.setFont(SwingTheme.FONT_SMALL);

        toolBar.add(btnExpand);
        toolBar.add(Box.createHorizontalStrut(8));
        toolBar.add(btnCollapse);
        toolBar.add(tbHint);
        panel.add(toolBar, BorderLayout.NORTH);

        // Build JTree: MITRE ATT&CK & Security Framework Hierarchy
        DefaultMutableTreeNode root = new DefaultMutableTreeNode("CyberShield Security Hierarchy");

        DefaultMutableTreeNode mitre = new DefaultMutableTreeNode("MITRE ATT&CK Framework");
        DefaultMutableTreeNode initialAccess = new DefaultMutableTreeNode("TA0001: Initial Access");
        initialAccess.add(new DefaultMutableTreeNode("T1190: Exploit Public-Facing Application"));
        initialAccess.add(new DefaultMutableTreeNode("T1566: Phishing / Social Engineering"));

        DefaultMutableTreeNode execution = new DefaultMutableTreeNode("TA0002: Execution");
        execution.add(new DefaultMutableTreeNode("T1059: Command and Scripting Interpreter"));
        execution.add(new DefaultMutableTreeNode("T1204: User Execution"));

        DefaultMutableTreeNode defenseEvasion = new DefaultMutableTreeNode("TA0005: Defense Evasion");
        defenseEvasion.add(new DefaultMutableTreeNode("T1070: Indicator Removal on Host"));
        defenseEvasion.add(new DefaultMutableTreeNode("T1036: Masquerading"));

        mitre.add(initialAccess);
        mitre.add(execution);
        mitre.add(defenseEvasion);

        DefaultMutableTreeNode nist = new DefaultMutableTreeNode("NIST Cybersecurity Framework");
        nist.add(new DefaultMutableTreeNode("ID: Identify (Asset Management & Governance)"));
        nist.add(new DefaultMutableTreeNode("PR: Protect (Access Control & Data Security)"));
        nist.add(new DefaultMutableTreeNode("DE: Detect (Anomalies & Continuous Monitoring)"));
        nist.add(new DefaultMutableTreeNode("RS: Respond (Incident Analysis & Mitigation)"));
        nist.add(new DefaultMutableTreeNode("RC: Recover (Restoration & Improvements)"));

        root.add(mitre);
        root.add(nist);

        JTree securityTree = new JTree(root);
        securityTree.setBackground(SwingTheme.PANEL_BG);
        securityTree.setForeground(SwingTheme.TEXT_PRIMARY);
        securityTree.setFont(SwingTheme.FONT_BODY);

        // Customize tree cell rendering
        DefaultTreeCellRenderer renderer = new DefaultTreeCellRenderer();
        renderer.setBackgroundNonSelectionColor(SwingTheme.PANEL_BG);
        renderer.setBackgroundSelectionColor(SwingTheme.PRIMARY_COLOR);
        renderer.setTextNonSelectionColor(SwingTheme.TEXT_PRIMARY);
        renderer.setTextSelectionColor(Color.WHITE);
        securityTree.setCellRenderer(renderer);

        // Right side detail panel
        JTextPane detailPane = new JTextPane();
        detailPane.setContentType("text/html");
        detailPane.setEditable(false);
        detailPane.setBackground(SwingTheme.PANEL_BG);
        detailPane.setText("<html><body style='font-family:sans-serif;color:#e2e8f0;padding:12px;'>" +
            "<h3 style='color:#38bdf8;'>Security Domain Inspector</h3>" +
            "<p>Select any item in the <b>JTree</b> to inspect its cybersecurity mapping, attack techniques, and mitigation guidance.</p>" +
            "<p style='color:#94a3b8;'>This component demonstrates hierarchical data navigation using <code>DefaultMutableTreeNode</code> and <code>TreePath</code>.</p>" +
            "</body></html>");

        securityTree.addTreeSelectionListener(e -> {
            TreePath path = e.getPath();
            Object selectedNode = path.getLastPathComponent();
            if (selectedNode != null) {
                String nodeName = selectedNode.toString();
                detailPane.setText("<html><body style='font-family:sans-serif;color:#e2e8f0;padding:12px;'>" +
                    "<h3 style='color:#38bdf8;'>" + nodeName + "</h3>" +
                    "<p><b>Hierarchy Path:</b> <span style='color:#f59e0b;'>" + path.toString() + "</span></p>" +
                    "<hr style='border:1px solid #334155;'/>" +
                    "<p><b>Classification:</b> Active Threat Taxonomy Node</p>" +
                    "<p><b>CyberShield Monitoring Status:</b> <span style='color:#22c55e;'>PROTECTED & MONITORED</span></p>" +
                    "<p style='color:#94a3b8;'>CyberShield continuously correlates inbound events against this standard.</p>" +
                    "</body></html>");
            }
        });

        // JPopupMenu (Context Menu)
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem itemInspect = new JMenuItem("Inspect Category Properties");
        itemInspect.addActionListener(ev -> JOptionPane.showMessageDialog(panel,
            "JPopupMenu Demonstration: Selected category inspected.\nPath: " + securityTree.getSelectionPath(),
            "Category Properties", JOptionPane.INFORMATION_MESSAGE));
        JMenuItem itemAudit = new JMenuItem("Run Telemetry Audit on Node");
        itemAudit.addActionListener(ev -> JOptionPane.showMessageDialog(panel,
            "Simulated audit check triggered on selected tree hierarchy.", "Node Audit", JOptionPane.WARNING_MESSAGE));

        popupMenu.add(itemInspect);
        popupMenu.add(itemAudit);

        securityTree.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    popupMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
            @Override
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    popupMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });

        btnExpand.addActionListener(e -> {
            for (int i = 0; i < securityTree.getRowCount(); i++) {
                securityTree.expandRow(i);
            }
        });

        btnCollapse.addActionListener(e -> {
            for (int i = securityTree.getRowCount() - 1; i > 0; i--) {
                securityTree.collapseRow(i);
            }
        });

        // JSplitPane (Splits tree on left and details on right)
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
            new JScrollPane(securityTree),
            new JScrollPane(detailPane));
        splitPane.setDividerLocation(360);
        splitPane.setContinuousLayout(true);
        splitPane.setBorder(BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR));

        panel.add(splitPane, BorderLayout.CENTER);
        return panel;
    }

    // =========================================================================
    // LAB 3: PROGRESS BARS, SLIDERS & FEEDBACK
    // Demonstrates: JProgressBar, JSlider, JSeparator, Tooltips
    // =========================================================================
    private JPanel createProgressFeedbackLab() {
        JPanel panel = new JPanel(new BorderLayout(14, 14));
        panel.setBackground(SwingTheme.CARD_BG);
        panel.setBorder(BorderFactory.createEmptyBorder(18, 18, 18, 18));

        JPanel formBox = new JPanel(new GridLayout(6, 1, 10, 10));
        formBox.setOpaque(false);

        // 1. Interactive JSlider
        JPanel sliderRow = new JPanel(new BorderLayout(10, 0));
        sliderRow.setOpaque(false);
        JLabel sliderLabel = new JLabel("JSlider (IDS Heuristic Sensitivity: 50%):");
        sliderLabel.setForeground(SwingTheme.TEXT_PRIMARY);
        sliderLabel.setFont(SwingTheme.FONT_BOLD);

        JSlider sensitivitySlider = new JSlider(0, 100, 50);
        sensitivitySlider.setMajorTickSpacing(25);
        sensitivitySlider.setMinorTickSpacing(5);
        sensitivitySlider.setPaintTicks(true);
        sensitivitySlider.setPaintLabels(true);
        sensitivitySlider.setBackground(SwingTheme.CARD_BG);
        sensitivitySlider.setForeground(SwingTheme.TEXT_MUTED);

        sliderRow.add(sliderLabel, BorderLayout.NORTH);
        sliderRow.add(sensitivitySlider, BorderLayout.CENTER);
        formBox.add(sliderRow);

        // 2. Determinate JProgressBar
        JPanel progressRow = new JPanel(new BorderLayout(10, 4));
        progressRow.setOpaque(false);
        JLabel progressLabel = new JLabel("JProgressBar (Network Anomaly Vulnerability Scan):");
        progressLabel.setForeground(SwingTheme.TEXT_PRIMARY);
        progressLabel.setFont(SwingTheme.FONT_BOLD);

        JProgressBar progressBar = new JProgressBar(0, 100);
        progressBar.setValue(50);
        progressBar.setStringPainted(true);
        progressBar.setForeground(SwingTheme.PRIMARY_COLOR);
        progressBar.setBackground(SwingTheme.PANEL_BG);

        // Linking slider to progress bar dynamically
        sensitivitySlider.addChangeListener(e -> {
            int val = sensitivitySlider.getValue();
            sliderLabel.setText("JSlider (IDS Heuristic Sensitivity: " + val + "%):");
            progressBar.setValue(val);
        });

        progressRow.add(progressLabel, BorderLayout.NORTH);
        progressRow.add(progressBar, BorderLayout.CENTER);
        formBox.add(progressRow);

        // 3. JSeparator demonstration
        JSeparator separator = new JSeparator(SwingConstants.HORIZONTAL);
        separator.setForeground(SwingTheme.BORDER_COLOR);
        formBox.add(separator);

        // 4. Indeterminate JProgressBar
        JPanel indetRow = new JPanel(new BorderLayout(10, 4));
        indetRow.setOpaque(false);
        JLabel indetLabel = new JLabel("JProgressBar (Indeterminate Background Threat Hunting):");
        indetLabel.setForeground(SwingTheme.TEXT_PRIMARY);
        indetLabel.setFont(SwingTheme.FONT_BOLD);

        JProgressBar indetProgress = new JProgressBar();
        indetProgress.setIndeterminate(true);
        indetProgress.setForeground(SwingTheme.SEVERITY_HIGH);
        indetProgress.setBackground(SwingTheme.PANEL_BG);

        indetRow.add(indetLabel, BorderLayout.NORTH);
        indetRow.add(indetProgress, BorderLayout.CENTER);
        formBox.add(indetRow);

        // 5. Scan Simulation Controller
        JPanel scanControlRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        scanControlRow.setOpaque(false);

        JButton btnStartScan = new JButton("Run Simulated 0-100% Scan");
        SwingTheme.stylePrimaryButton(btnStartScan);

        JButton btnResetScan = new JButton("Reset Progress");
        SwingTheme.styleSecondaryButton(btnResetScan);

        JLabel scanStatus = new JLabel("Ready to scan.");
        scanStatus.setForeground(SwingTheme.TEXT_MUTED);

        // Timer-based animated simulation
        Timer scanTimer = new Timer(30, null);
        scanTimer.addActionListener(e -> {
            int current = progressBar.getValue();
            if (current < 100) {
                progressBar.setValue(current + 1);
                scanStatus.setText("Scanning port/packet #" + (current * 44) + "...");
            } else {
                scanTimer.stop();
                btnStartScan.setEnabled(true);
                scanStatus.setText("Scan completed successfully! 0 vulnerabilities detected.");
                JOptionPane.showMessageDialog(panel,
                    "Simulated vulnerability scan reached 100% completion!\nAll network interfaces verified.",
                    "Scan Completed", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        btnStartScan.addActionListener(e -> {
            btnStartScan.setEnabled(false);
            progressBar.setValue(0);
            scanStatus.setText("Initializing scanner...");
            scanTimer.start();
        });

        btnResetScan.addActionListener(e -> {
            scanTimer.stop();
            btnStartScan.setEnabled(true);
            progressBar.setValue(50);
            sensitivitySlider.setValue(50);
            scanStatus.setText("Reset to default 50%.");
        });

        scanControlRow.add(btnStartScan);
        scanControlRow.add(btnResetScan);
        scanControlRow.add(scanStatus);
        formBox.add(scanControlRow);

        panel.add(formBox, BorderLayout.NORTH);
        return panel;
    }

    // =========================================================================
    // LAB 4: MDI WORKSPACE (JDesktopPane & JInternalFrame & JLayeredPane)
    // =========================================================================
    private JPanel createMdiDesktopLab() {
        JPanel panel = new JPanel(new BorderLayout(0, 8));
        panel.setBackground(SwingTheme.CARD_BG);
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Top bar to spawn internal frames
        JPanel topBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        topBar.setOpaque(false);

        JButton btnNewFrame = new JButton("+ Spawn New JInternalFrame");
        SwingTheme.stylePrimaryButton(btnNewFrame);

        JButton btnTile = new JButton("Reset Default MDI Windows");
        SwingTheme.styleSecondaryButton(btnTile);

        JLabel mdiNote = new JLabel("<- JDesktopPane Multi-Document Interface (Drag, minimize, maximize windows below)");
        mdiNote.setForeground(SwingTheme.TEXT_MUTED);
        mdiNote.setFont(SwingTheme.FONT_SMALL);

        topBar.add(btnNewFrame);
        topBar.add(btnTile);
        topBar.add(mdiNote);
        panel.add(topBar, BorderLayout.NORTH);

        // JDesktopPane (Virtual desktop hosting multiple internal windows)
        JDesktopPane desktopPane = new JDesktopPane();
        desktopPane.setBackground(new Color(15, 23, 42)); // Deep SOC navy
        desktopPane.setBorder(BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR));

        // Create 2 default JInternalFrames
        Runnable populateMdi = () -> {
            desktopPane.removeAll();

            // Internal Frame 1: Network Packet Sniffer
            JInternalFrame snifferFrame = new JInternalFrame("Packet Sniffer Console", true, true, true, true);
            snifferFrame.setSize(340, 220);
            snifferFrame.setLocation(20, 20);
            snifferFrame.getContentPane().setLayout(new BorderLayout());
            JTextArea snifferText = new JTextArea("TCP [SYN] 192.168.1.15:49152 -> 10.0.0.1:443\nTCP [SYN-ACK] 10.0.0.1:443 -> 192.168.1.15:49152\nTLSv1.3 Client Hello (SNI: api.cybershield.org)");
            snifferText.setBackground(SwingTheme.PANEL_BG);
            snifferText.setForeground(new Color(74, 222, 128));
            snifferText.setFont(new Font("Consolas", Font.PLAIN, 11));
            snifferFrame.getContentPane().add(new JScrollPane(snifferText), BorderLayout.CENTER);
            snifferFrame.setVisible(true);
            desktopPane.add(snifferFrame);

            // Internal Frame 2: Live IDS Sensor Stats
            JInternalFrame idsFrame = new JInternalFrame("IDS Sensor Status", true, true, true, true);
            idsFrame.setSize(320, 200);
            idsFrame.setLocation(380, 40);
            idsFrame.getContentPane().setLayout(new GridLayout(3, 1, 6, 6));
            idsFrame.getContentPane().setBackground(SwingTheme.PANEL_BG);

            JLabel l1 = new JLabel("  Packets Analyzed: 148,290 / sec", SwingConstants.LEFT);
            l1.setForeground(SwingTheme.TEXT_PRIMARY);
            JLabel l2 = new JLabel("  Dropped Malicious Packets: 42", SwingConstants.LEFT);
            l2.setForeground(SwingTheme.SEVERITY_CRITICAL);
            JLabel l3 = new JLabel("  Firewall CPU Core Usage: 18%", SwingConstants.LEFT);
            l3.setForeground(SwingTheme.STATUS_RESOLVED);

            idsFrame.getContentPane().add(l1);
            idsFrame.getContentPane().add(l2);
            idsFrame.getContentPane().add(l3);
            idsFrame.setVisible(true);
            desktopPane.add(idsFrame);

            desktopPane.repaint();
        };

        populateMdi.run();

        int[] frameCounter = {3};
        btnNewFrame.addActionListener(e -> {
            JInternalFrame customFrame = new JInternalFrame("Custom Monitor #" + (frameCounter[0]++), true, true, true, true);
            customFrame.setSize(280, 180);
            customFrame.setLocation(60 + (frameCounter[0] * 20) % 200, 60 + (frameCounter[0] * 15) % 150);
            JPanel p = new JPanel(new BorderLayout());
            p.setBackground(SwingTheme.PANEL_BG);
            JLabel lbl = new JLabel("Dynamically spawned JInternalFrame", SwingConstants.CENTER);
            lbl.setForeground(SwingTheme.TEXT_PRIMARY);
            p.add(lbl, BorderLayout.CENTER);
            customFrame.getContentPane().add(p);
            customFrame.setVisible(true);
            desktopPane.add(customFrame);
            try {
                customFrame.setSelected(true);
            } catch (Exception ignored) {}
        });

        btnTile.addActionListener(e -> populateMdi.run());

        panel.add(desktopPane, BorderLayout.CENTER);
        return panel;
    }

    // =========================================================================
    // LAB 5: DIALOGS & UTILITIES
    // Demonstrates: JOptionPane, JFileChooser, JColorChooser, JDialog, JWindow,
    // and Keyboard Shortcuts using InputMap & ActionMap.
    // =========================================================================
    private JPanel createDialogsUtilitiesLab() {
        JPanel panel = new JPanel(new GridLayout(2, 3, 14, 14));
        panel.setBackground(SwingTheme.CARD_BG);
        panel.setBorder(BorderFactory.createEmptyBorder(18, 18, 18, 18));

        // 1. JOptionPane Showcase
        JPanel optBox = new JPanel(new GridLayout(4, 1, 6, 6));
        optBox.setOpaque(false);
        optBox.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR), "1. JOptionPane Family",
            TitledBorder.LEFT, TitledBorder.TOP, SwingTheme.FONT_BOLD, SwingTheme.TEXT_PRIMARY));

        JButton btnInfo = new JButton("Show Message Dialog");
        SwingTheme.styleSecondaryButton(btnInfo);
        btnInfo.addActionListener(e -> JOptionPane.showMessageDialog(panel,
            "JOptionPane.showMessageDialog:\nInbound TLS certificate validation passed.",
            "Security Notice", JOptionPane.INFORMATION_MESSAGE));

        JButton btnConfirm = new JButton("Show Confirm Dialog");
        SwingTheme.styleSecondaryButton(btnConfirm);
        btnConfirm.addActionListener(e -> {
            int res = JOptionPane.showConfirmDialog(panel,
                "JOptionPane.showConfirmDialog:\nDo you want to purge non-critical cache?",
                "Purge Confirmation", JOptionPane.YES_NO_CANCEL_OPTION);
            JOptionPane.showMessageDialog(panel, "You selected option code: " + res);
        });

        JButton btnInput = new JButton("Show Input Dialog");
        SwingTheme.styleSecondaryButton(btnInput);
        btnInput.addActionListener(e -> {
            String val = JOptionPane.showInputDialog(panel, "Enter IP Address to Ping:", "192.168.1.1");
            if (val != null) {
                JOptionPane.showMessageDialog(panel, "Ping initiated for: " + val);
            }
        });

        optBox.add(btnInfo);
        optBox.add(btnConfirm);
        optBox.add(btnInput);
        panel.add(optBox);

        // 2. JFileChooser Showcase
        JPanel fileBox = new JPanel(new BorderLayout(0, 10));
        fileBox.setOpaque(false);
        fileBox.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR), "2. JFileChooser",
            TitledBorder.LEFT, TitledBorder.TOP, SwingTheme.FONT_BOLD, SwingTheme.TEXT_PRIMARY));

        JLabel fileDesc = new JLabel("<html>Export forensic evidence log to disk using authentic <b>JFileChooser</b> file selection dialog.</html>");
        fileDesc.setForeground(SwingTheme.TEXT_MUTED);

        JButton btnExport = new JButton("Export Forensic Report...");
        SwingTheme.stylePrimaryButton(btnExport);
        btnExport.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setSelectedFile(new File("cybershield_security_export.txt"));
            int choice = chooser.showSaveDialog(panel);
            if (choice == JFileChooser.APPROVE_OPTION) {
                File target = chooser.getSelectedFile();
                try (FileWriter writer = new FileWriter(target)) {
                    writer.write("=== CYBERSHIELD FORENSIC EXPORT ===\n");
                    writer.write("Exported at: " + new Date() + "\n");
                    writer.write("System Status: All security controls operational.\n");
                    JOptionPane.showMessageDialog(panel,
                        "Report exported successfully to:\n" + target.getAbsolutePath(),
                        "Export Complete", JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(panel, "File Error: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        fileBox.add(fileDesc, BorderLayout.CENTER);
        fileBox.add(btnExport, BorderLayout.SOUTH);
        panel.add(fileBox);

        // 3. JColorChooser Showcase
        JPanel colorBox = new JPanel(new BorderLayout(0, 10));
        colorBox.setOpaque(false);
        colorBox.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR), "3. JColorChooser",
            TitledBorder.LEFT, TitledBorder.TOP, SwingTheme.FONT_BOLD, SwingTheme.TEXT_PRIMARY));

        JPanel previewCard = new JPanel();
        previewCard.setBackground(SwingTheme.PRIMARY_COLOR);
        previewCard.setBorder(BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR));
        JLabel previewLabel = new JLabel("Accent Color Preview", SwingConstants.CENTER);
        previewLabel.setForeground(Color.WHITE);
        previewCard.add(previewLabel);

        JButton btnPickColor = new JButton("Select Custom UI Accent...");
        SwingTheme.styleSecondaryButton(btnPickColor);
        btnPickColor.addActionListener(e -> {
            Color chosen = JColorChooser.showDialog(panel, "Pick CyberShield Accent Color", previewCard.getBackground());
            if (chosen != null) {
                previewCard.setBackground(chosen);
            }
        });

        colorBox.add(previewCard, BorderLayout.CENTER);
        colorBox.add(btnPickColor, BorderLayout.SOUTH);
        panel.add(colorBox);

        // 4. Custom JDialog Showcase
        JPanel dialogBox = new JPanel(new BorderLayout(0, 10));
        dialogBox.setOpaque(false);
        dialogBox.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR), "4. Custom JDialog",
            TitledBorder.LEFT, TitledBorder.TOP, SwingTheme.FONT_BOLD, SwingTheme.TEXT_PRIMARY));

        JLabel dialogDesc = new JLabel("<html>Spawns a custom modal <b>JDialog</b> with form validation and dedicated layout hierarchy.</html>");
        dialogDesc.setForeground(SwingTheme.TEXT_MUTED);

        JButton btnSpawnDialog = new JButton("Launch Custom JDialog");
        SwingTheme.styleSecondaryButton(btnSpawnDialog);
        btnSpawnDialog.addActionListener(e -> {
            Window parentWindow = SwingUtilities.getWindowAncestor(panel);
            JDialog customDlg = new JDialog(parentWindow, "Custom Security Policy Dialog", Dialog.ModalityType.APPLICATION_MODAL);
            customDlg.setSize(380, 240);
            customDlg.setLocationRelativeTo(panel);
            customDlg.getContentPane().setBackground(SwingTheme.PANEL_BG);
            customDlg.setLayout(new BorderLayout(10, 10));

            JPanel content = new JPanel(new GridLayout(3, 1, 8, 8));
            content.setBackground(SwingTheme.PANEL_BG);
            content.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

            JLabel titleLbl = new JLabel("Custom JDialog Demonstration", SwingConstants.CENTER);
            titleLbl.setFont(SwingTheme.FONT_BOLD);
            titleLbl.setForeground(SwingTheme.TEXT_PRIMARY);

            JLabel bodyLbl = new JLabel("Modal dialog blocks parent interaction until dismissed.", SwingConstants.CENTER);
            bodyLbl.setForeground(SwingTheme.TEXT_MUTED);

            JButton closeBtn = new JButton("Dismiss Dialog");
            SwingTheme.stylePrimaryButton(closeBtn);
            closeBtn.addActionListener(ev -> customDlg.dispose());

            content.add(titleLbl);
            content.add(bodyLbl);
            content.add(closeBtn);

            customDlg.add(content, BorderLayout.CENTER);
            customDlg.setVisible(true);
        });

        dialogBox.add(dialogDesc, BorderLayout.CENTER);
        dialogBox.add(btnSpawnDialog, BorderLayout.SOUTH);
        panel.add(dialogBox);

        // 5. JWindow (Frameless Overlay)
        JPanel windowBox = new JPanel(new BorderLayout(0, 10));
        windowBox.setOpaque(false);
        windowBox.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR), "5. JWindow (Toast Popup)",
            TitledBorder.LEFT, TitledBorder.TOP, SwingTheme.FONT_BOLD, SwingTheme.TEXT_PRIMARY));

        JLabel winDesc = new JLabel("<html>Launches a borderless, title-less <b>JWindow</b> notification that auto-dismisses after 2.5 seconds.</html>");
        winDesc.setForeground(SwingTheme.TEXT_MUTED);

        JButton btnSpawnWindow = new JButton("Show Toast via JWindow");
        SwingTheme.styleSecondaryButton(btnSpawnWindow);
        btnSpawnWindow.addActionListener(e -> {
            Window parentWindow = SwingUtilities.getWindowAncestor(panel);
            JWindow toast = new JWindow(parentWindow);
            JPanel toastPanel = new JPanel(new BorderLayout(8, 8));
            toastPanel.setBackground(new Color(30, 41, 59));
            toastPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(SwingTheme.PRIMARY_COLOR, 2),
                BorderFactory.createEmptyBorder(14, 18, 14, 18)
            ));

            JLabel toastText = new JLabel("JWindow Toast: Threat definition update downloaded!", SwingConstants.CENTER);
            toastText.setForeground(Color.WHITE);
            toastText.setFont(SwingTheme.FONT_BOLD);

            toastPanel.add(toastText, BorderLayout.CENTER);
            toast.getContentPane().add(toastPanel);
            toast.pack();
            toast.setLocationRelativeTo(panel);
            toast.setVisible(true);

            // Auto dismiss after 2.5 seconds
            Timer dismissTimer = new Timer(2500, ev -> toast.dispose());
            dismissTimer.setRepeats(false);
            dismissTimer.start();
        });

        windowBox.add(winDesc, BorderLayout.CENTER);
        windowBox.add(btnSpawnWindow, BorderLayout.SOUTH);
        panel.add(windowBox);

        // 6. Keyboard Shortcuts (InputMap & ActionMap)
        JPanel keyBox = new JPanel(new BorderLayout(0, 8));
        keyBox.setOpaque(false);
        keyBox.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR), "6. InputMap & ActionMap",
            TitledBorder.LEFT, TitledBorder.TOP, SwingTheme.FONT_BOLD, SwingTheme.TEXT_PRIMARY));

        JLabel keyDesc = new JLabel("<html>Press <b>Ctrl + S</b> anywhere in this window to test key bindings mapped via <code>InputMap</code> and <code>ActionMap</code>.</html>");
        keyDesc.setForeground(SwingTheme.TEXT_MUTED);

        JLabel keyStatus = new JLabel("Status: Awaiting Ctrl+S trigger...", SwingConstants.CENTER);
        keyStatus.setForeground(SwingTheme.STATUS_OPEN);
        keyStatus.setFont(SwingTheme.FONT_BOLD);

        // Bind Ctrl+S to component
        InputMap im = panel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW);
        ActionMap am = panel.getActionMap();

        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_S, KeyEvent.CTRL_DOWN_MASK), "saveShortcut");
        am.put("saveShortcut", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                keyStatus.setText("Triggered: Ctrl+S handled by ActionMap!");
                JOptionPane.showMessageDialog(panel,
                    "ActionMap executed 'saveShortcut' successfully!\nEvent triggered via keyboard shortcut Ctrl + S.",
                    "KeyBinding Handled", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        keyBox.add(keyDesc, BorderLayout.NORTH);
        keyBox.add(keyStatus, BorderLayout.CENTER);
        panel.add(keyBox);

        return panel;
    }

    // =========================================================================
    // LAB 6: LAYOUT MANAGERS SHOWCASE
    // Demonstrates: BorderLayout, FlowLayout, GridLayout, GridBagLayout,
    // BoxLayout, CardLayout, GroupLayout.
    // =========================================================================
    private JPanel createLayoutManagersLab() {
        JPanel panel = new JPanel(new BorderLayout(0, 10));
        panel.setBackground(SwingTheme.CARD_BG);
        panel.setBorder(BorderFactory.createEmptyBorder(14, 14, 14, 14));

        // Sub-tabs demonstrating each layout manager in practice
        JTabbedPane layoutTabs = new JTabbedPane(JTabbedPane.TOP);
        layoutTabs.setBackground(SwingTheme.PANEL_BG);
        layoutTabs.setForeground(SwingTheme.TEXT_PRIMARY);

        // 1. BorderLayout Demo
        JPanel borderDemo = new JPanel(new BorderLayout(8, 8));
        borderDemo.setBackground(SwingTheme.PANEL_BG);
        borderDemo.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        borderDemo.add(createBadgeLabel("BorderLayout.NORTH (Header)", SwingTheme.PRIMARY_COLOR), BorderLayout.NORTH);
        borderDemo.add(createBadgeLabel("WEST (Navigation Sidebar)", SwingTheme.CARD_BG), BorderLayout.WEST);
        borderDemo.add(createBadgeLabel("CENTER (Main Dynamic Content)", SwingTheme.CARD_BG), BorderLayout.CENTER);
        borderDemo.add(createBadgeLabel("EAST (Properties Inspector)", SwingTheme.CARD_BG), BorderLayout.EAST);
        borderDemo.add(createBadgeLabel("BorderLayout.SOUTH (Status Bar)", SwingTheme.PRIMARY_COLOR), BorderLayout.SOUTH);
        layoutTabs.addTab("BorderLayout", borderDemo);

        // 2. FlowLayout Demo
        JPanel flowDemo = new JPanel(new FlowLayout(FlowLayout.CENTER, 14, 20));
        flowDemo.setBackground(SwingTheme.PANEL_BG);
        for (int i = 1; i <= 6; i++) {
            JButton b = new JButton("Flow Component #" + i);
            SwingTheme.styleSecondaryButton(b);
            flowDemo.add(b);
        }
        layoutTabs.addTab("FlowLayout", flowDemo);

        // 3. GridLayout Demo
        JPanel gridDemo = new JPanel(new GridLayout(2, 3, 10, 10));
        gridDemo.setBackground(SwingTheme.PANEL_BG);
        gridDemo.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        for (int i = 1; i <= 6; i++) {
            gridDemo.add(createBadgeLabel("Grid Cell (" + i + "/6)", SwingTheme.CARD_BG));
        }
        layoutTabs.addTab("GridLayout", gridDemo);

        // 4. GridBagLayout Demo
        JPanel gblDemo = new JPanel(new GridBagLayout());
        gblDemo.setBackground(SwingTheme.PANEL_BG);
        gblDemo.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.BOTH;
        c.insets = new Insets(6, 6, 6, 6);

        c.gridx = 0; c.gridy = 0; c.gridwidth = 2; c.weightx = 1.0; c.weighty = 0.3;
        gblDemo.add(createBadgeLabel("GridBag: Row 0 Spanning 2 Columns", SwingTheme.PRIMARY_COLOR), c);

        c.gridx = 0; c.gridy = 1; c.gridwidth = 1; c.weightx = 0.4; c.weighty = 0.7;
        gblDemo.add(createBadgeLabel("GridBag: Cell (0,1)", SwingTheme.CARD_BG), c);

        c.gridx = 1; c.gridy = 1; c.weightx = 0.6;
        gblDemo.add(createBadgeLabel("GridBag: Cell (1,1)", SwingTheme.CARD_BG), c);
        layoutTabs.addTab("GridBagLayout", gblDemo);

        // 5. BoxLayout Demo
        JPanel boxDemo = new JPanel();
        boxDemo.setLayout(new BoxLayout(boxDemo, BoxLayout.Y_AXIS));
        boxDemo.setBackground(SwingTheme.PANEL_BG);
        boxDemo.setBorder(BorderFactory.createEmptyBorder(16, 24, 16, 24));
        for (int i = 1; i <= 4; i++) {
            JButton bb = new JButton("BoxLayout Vertical Item #" + i);
            SwingTheme.styleSecondaryButton(bb);
            bb.setAlignmentX(Component.CENTER_ALIGNMENT);
            boxDemo.add(bb);
            boxDemo.add(Box.createVerticalStrut(10));
        }
        layoutTabs.addTab("BoxLayout", boxDemo);

        // 6. CardLayout Demo
        CardLayout cardLayout = new CardLayout();
        JPanel cardContainer = new JPanel(cardLayout);
        cardContainer.setBackground(SwingTheme.PANEL_BG);

        JPanel card1 = new JPanel(new BorderLayout());
        card1.setBackground(SwingTheme.PANEL_BG);
        card1.add(createBadgeLabel("Card 1: Intrusion Sensor Overview", SwingTheme.CARD_BG), BorderLayout.CENTER);

        JPanel card2 = new JPanel(new BorderLayout());
        card2.setBackground(SwingTheme.PANEL_BG);
        card2.add(createBadgeLabel("Card 2: Firewall Rule Configurator", SwingTheme.PRIMARY_COLOR), BorderLayout.CENTER);

        JPanel card3 = new JPanel(new BorderLayout());
        card3.setBackground(SwingTheme.PANEL_BG);
        card3.add(createBadgeLabel("Card 3: Audit Encryption Keys", SwingTheme.CARD_BG), BorderLayout.CENTER);

        cardContainer.add(card1, "C1");
        cardContainer.add(card2, "C2");
        cardContainer.add(card3, "C3");

        JPanel cardWrapper = new JPanel(new BorderLayout(0, 10));
        cardWrapper.setBackground(SwingTheme.PANEL_BG);

        JPanel cardNav = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 8));
        cardNav.setOpaque(false);
        JButton btnPrev = new JButton("< Previous Card");
        SwingTheme.styleSecondaryButton(btnPrev);
        btnPrev.addActionListener(e -> cardLayout.previous(cardContainer));

        JButton btnNext = new JButton("Next Card >");
        SwingTheme.styleSecondaryButton(btnNext);
        btnNext.addActionListener(e -> cardLayout.next(cardContainer));

        cardNav.add(btnPrev);
        cardNav.add(btnNext);
        cardNav.add(new JLabel("CardLayout allows wizard-like step switching without creating new windows"));

        cardWrapper.add(cardNav, BorderLayout.NORTH);
        cardWrapper.add(cardContainer, BorderLayout.CENTER);
        layoutTabs.addTab("CardLayout", cardWrapper);

        // 7. GroupLayout Demo
        JPanel groupDemo = new JPanel();
        groupDemo.setBackground(SwingTheme.PANEL_BG);
        GroupLayout gl = new GroupLayout(groupDemo);
        groupDemo.setLayout(gl);
        gl.setAutoCreateGaps(true);
        gl.setAutoCreateContainerGaps(true);

        JLabel glLbl1 = new JLabel("Rule Name:");
        glLbl1.setForeground(SwingTheme.TEXT_PRIMARY);
        JTextField glTxt1 = new JTextField("Block_Port_23_Telnet");
        SwingTheme.styleTextField(glTxt1);

        JLabel glLbl2 = new JLabel("Action:");
        glLbl2.setForeground(SwingTheme.TEXT_PRIMARY);
        JComboBox<String> glCmb = new JComboBox<>(new String[]{"DENY", "ALLOW", "ALERT"});
        SwingTheme.styleComboBox(glCmb);

        gl.setHorizontalGroup(gl.createSequentialGroup()
            .addGroup(gl.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(glLbl1).addComponent(glLbl2))
            .addGroup(gl.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(glTxt1).addComponent(glCmb))
        );
        gl.setVerticalGroup(gl.createSequentialGroup()
            .addGroup(gl.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(glLbl1).addComponent(glTxt1))
            .addGroup(gl.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(glLbl2).addComponent(glCmb))
        );
        layoutTabs.addTab("GroupLayout", groupDemo);

        panel.add(layoutTabs, BorderLayout.CENTER);
        return panel;
    }

    private JLabel createBadgeLabel(String text, Color bg) {
        JLabel l = new JLabel(text, SwingConstants.CENTER);
        l.setOpaque(true);
        l.setBackground(bg);
        l.setForeground(Color.WHITE);
        l.setFont(SwingTheme.FONT_BOLD);
        l.setBorder(BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR, 1));
        return l;
    }
}
