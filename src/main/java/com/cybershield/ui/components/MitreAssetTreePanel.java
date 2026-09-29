package com.cybershield.ui.components;

import com.cybershield.ui.CyberTheme;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridLayout;
import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.TreeSelectionModel;

/**
 * Demonstrates javax.swing.JTree with TreeSelectionListener.
 * Visualizes Enterprise IT Infrastructure Assets and MITRE ATT&CK Matrix Mapping.
 */
public class MitreAssetTreePanel extends JPanel {

    private final JTree assetTree;
    private final JTextArea txtNodeDetails;
    private final JLabel lblSelectedNode;

    public MitreAssetTreePanel() {
        setLayout(new BorderLayout(8, 8));
        setBackground(CyberTheme.BG_DARK);
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Top Header
        JPanel topHeader = new JPanel(new BorderLayout(6, 6));
        topHeader.setOpaque(false);
        JLabel title = new JLabel("🌳 ENTERPRISE ASSET HIERARCHY & MITRE ATT&CK MATRIX");
        title.setFont(CyberTheme.FONT_TITLE);
        title.setForeground(CyberTheme.ACCENT_CYAN);

        JLabel sub = new JLabel("Hierarchical tree navigation using javax.swing.JTree & TreeSelectionListener");
        sub.setFont(CyberTheme.FONT_SMALL);
        sub.setForeground(CyberTheme.TEXT_MUTED);

        topHeader.add(title, BorderLayout.NORTH);
        topHeader.add(sub, BorderLayout.SOUTH);
        add(topHeader, BorderLayout.NORTH);

        // Build JTree model
        DefaultMutableTreeNode root = buildTreeModel();
        assetTree = new JTree(root);
        assetTree.setBackground(CyberTheme.BG_CARD);
        assetTree.setForeground(CyberTheme.TEXT_PRIMARY);
        assetTree.setFont(CyberTheme.FONT_BODY);
        assetTree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);

        // Customize Tree Renderer colors for Dark SOC Theme
        DefaultTreeCellRenderer renderer = new DefaultTreeCellRenderer();
        renderer.setBackgroundNonSelectionColor(CyberTheme.BG_CARD);
        renderer.setBackgroundSelectionColor(CyberTheme.ACCENT_BLUE);
        renderer.setTextNonSelectionColor(CyberTheme.TEXT_PRIMARY);
        renderer.setTextSelectionColor(Color.WHITE);
        assetTree.setCellRenderer(renderer);

        JScrollPane treeScroll = new JScrollPane(assetTree);
        treeScroll.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                " Security Infrastructure & Tactics Tree ", 0, 0, CyberTheme.FONT_BODY_BOLD, CyberTheme.ACCENT_CYAN
        ));
        treeScroll.setPreferredSize(new Dimension(360, 400));

        // Right Inspector Panel
        JPanel inspector = new JPanel(new BorderLayout(8, 8));
        inspector.setBackground(CyberTheme.BG_CARD);
        inspector.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                BorderFactory.createEmptyBorder(12, 12, 12, 12)
        ));

        lblSelectedNode = new JLabel("Node Inspector: Root");
        lblSelectedNode.setFont(CyberTheme.FONT_HEADER);
        lblSelectedNode.setForeground(CyberTheme.ACCENT_CYAN);

        txtNodeDetails = new JTextArea("Click any node in the JTree to inspect technical specifications, MITRE ID, or asset telemetry status...");
        txtNodeDetails.setEditable(false);
        txtNodeDetails.setFont(CyberTheme.FONT_MONO);
        txtNodeDetails.setBackground(CyberTheme.BG_DARK);
        txtNodeDetails.setForeground(CyberTheme.TEXT_PRIMARY);
        txtNodeDetails.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        inspector.add(lblSelectedNode, BorderLayout.NORTH);
        inspector.add(new JScrollPane(txtNodeDetails), BorderLayout.CENTER);

        // Wire TreeSelectionListener
        assetTree.addTreeSelectionListener(e -> {
            DefaultMutableTreeNode selected = (DefaultMutableTreeNode) assetTree.getLastSelectedPathComponent();
            if (selected == null) return;
            updateInspector(selected);
        });

        // JSplitPane master-detail
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, treeScroll, inspector);
        splitPane.setDividerLocation(380);
        splitPane.setOpaque(false);
        splitPane.setBorder(null);

        add(splitPane, BorderLayout.CENTER);
    }

    private DefaultMutableTreeNode buildTreeModel() {
        DefaultMutableTreeNode root = new DefaultMutableTreeNode("🛡 CYBERSHIELD Enterprise SOC Realm");

        // Branch 1: Infrastructure Assets
        DefaultMutableTreeNode assets = new DefaultMutableTreeNode("🏢 Monitored IT Infrastructure Assets");

        DefaultMutableTreeNode perimeter = new DefaultMutableTreeNode("🌐 Perimeter & DMZ Gateway");
        perimeter.add(new DefaultMutableTreeNode("Edge Firewall (198.51.100.1) [State: ACTIVE]"));
        perimeter.add(new DefaultMutableTreeNode("Reverse Proxy Nginx (198.51.100.24) [State: INSPECTED]"));
        perimeter.add(new DefaultMutableTreeNode("Public Web Application (203.0.113.88) [State: SECURED]"));

        DefaultMutableTreeNode internal = new DefaultMutableTreeNode("🔒 Internal Subnet (192.168.1.0/24)");
        internal.add(new DefaultMutableTreeNode("Active Directory / LDAP (192.168.1.10) [State: MONITORED]"));
        internal.add(new DefaultMutableTreeNode("Finance PostgreSQL Database (192.168.1.15) [State: HIGH VALUE]"));
        internal.add(new DefaultMutableTreeNode("HR Enterprise Portal (192.168.1.20) [State: NORMAL]"));

        DefaultMutableTreeNode endpoints = new DefaultMutableTreeNode("💻 Corporate Endpoint Fleet");
        endpoints.add(new DefaultMutableTreeNode("WORKSTATION-01 (192.168.1.101) - Alice (Engineering)"));
        endpoints.add(new DefaultMutableTreeNode("WORKSTATION-04 (192.168.1.104) - Bob (Finance - Target)"));
        endpoints.add(new DefaultMutableTreeNode("WORKSTATION-09 (192.168.1.109) - Charlie (Marketing)"));

        assets.add(perimeter);
        assets.add(internal);
        assets.add(endpoints);

        // Branch 2: MITRE ATT&CK Matrix Mapping
        DefaultMutableTreeNode mitre = new DefaultMutableTreeNode("🎯 MITRE ATT&CK Enterprise Matrix");

        DefaultMutableTreeNode initAccess = new DefaultMutableTreeNode("TA0001: Initial Access");
        initAccess.add(new DefaultMutableTreeNode("T1566.001 - Spearphishing Attachment [Detected in CYBERSHIELD]"));
        initAccess.add(new DefaultMutableTreeNode("T1566.002 - Spearphishing Link [Detected in CYBERSHIELD]"));

        DefaultMutableTreeNode execution = new DefaultMutableTreeNode("TA0002: Execution");
        execution.add(new DefaultMutableTreeNode("T1059.001 - PowerShell Scripting [Simulated in Malware Module]"));
        execution.add(new DefaultMutableTreeNode("T1204 - User Execution of Malicious Binary"));

        DefaultMutableTreeNode credAccess = new DefaultMutableTreeNode("TA0006: Credential Access");
        credAccess.add(new DefaultMutableTreeNode("T1110.001 - Password Guessing / Brute Force [Detected in CYBERSHIELD]"));
        credAccess.add(new DefaultMutableTreeNode("T1110.003 - Password Spraying against Active Accounts"));

        DefaultMutableTreeNode defenseEvasion = new DefaultMutableTreeNode("TA0005: Defense Evasion");
        defenseEvasion.add(new DefaultMutableTreeNode("T1027 - Obfuscated Files / Hidden Scripts"));
        defenseEvasion.add(new DefaultMutableTreeNode("T1070 - Indicator Removal on Host"));

        DefaultMutableTreeNode lateralMovement = new DefaultMutableTreeNode("TA0008: Lateral Movement");
        lateralMovement.add(new DefaultMutableTreeNode("T1021.004 - SSH Protocol Hijacking"));
        lateralMovement.add(new DefaultMutableTreeNode("T1078.002 - Domain Accounts Abuse"));

        mitre.add(initAccess);
        mitre.add(execution);
        mitre.add(credAccess);
        mitre.add(defenseEvasion);
        mitre.add(lateralMovement);

        root.add(assets);
        root.add(mitre);
        return root;
    }

    private void updateInspector(DefaultMutableTreeNode node) {
        String nodeText = node.getUserObject().toString();
        lblSelectedNode.setText("Node Inspector: " + nodeText);

        StringBuilder sb = new StringBuilder();
        sb.append("=================================================================\n");
        sb.append("   CYBERSHIELD SECURITY ASSET & TAXONOMY INSPECTION DOSSIER\n");
        sb.append("=================================================================\n\n");
        sb.append("Selected Node:     ").append(nodeText).append("\n");
        sb.append("Hierarchy Depth:   Level ").append(node.getLevel()).append("\n");
        sb.append("Leaf Node:         ").append(node.isLeaf() ? "YES (Terminal Entity)" : "NO (Branch Container)").append("\n");
        sb.append("Child Node Count:  ").append(node.getChildCount()).append("\n\n");

        if (nodeText.contains("Brute Force") || nodeText.contains("T1110")) {
            sb.append(">>> DETECTOR LINKED: BruteForceDetector (AOOP Polymorphic Class)\n");
            sb.append(">>> TECHNIQUE ID:    MITRE ATT&CK T1110.001\n");
            sb.append(">>> CORRESPONDING MODEL: BruteForceThreat.java (Subclass of Threat)\n");
            sb.append(">>> HEURISTIC RULE:  Sliding 120s window, >= 5 consecutive auth failures.\n");
            sb.append(">>> MITIGATION:      Automated Perimeter Firewall Rule (BLOCK_IP).\n");
        } else if (nodeText.contains("Phishing") || nodeText.contains("T1566")) {
            sb.append(">>> DETECTOR LINKED: PhishingDetector (AOOP Polymorphic Class)\n");
            sb.append(">>> TECHNIQUE ID:    MITRE ATT&CK T1566.002\n");
            sb.append(">>> CORRESPONDING MODEL: PhishingThreat.java (Subclass of Threat)\n");
            sb.append(">>> HEURISTIC RULE:  Sender spoofing heuristics & deceptive URL matching.\n");
            sb.append(">>> MITIGATION:      Credential Quarantine & Account Lockout (DISABLE_USER).\n");
        } else if (nodeText.contains("Malware") || nodeText.contains("T1059") || nodeText.contains("WORKSTATION-04")) {
            sb.append(">>> DETECTOR LINKED: MalwareDetector (AOOP Polymorphic Class)\n");
            sb.append(">>> TECHNIQUE ID:    MITRE ATT&CK T1059 / T1204\n");
            sb.append(">>> CORRESPONDING MODEL: MalwareThreat.java (Subclass of Threat)\n");
            sb.append(">>> HEURISTIC RULE:  Executable process creation with suspicious hash.\n");
            sb.append(">>> MITIGATION:      Endpoint Host Isolation (QUARANTINE_SIMULATION).\n");
        } else if (nodeText.contains("Firewall") || nodeText.contains("198.51.100.1")) {
            sb.append(">>> ASSET ROLE:      Perimeter Security Enforcement\n");
            sb.append(">>> DEFENSE POLICY:  SYN Flood Protection & Dynamic Ingress Drop\n");
            sb.append(">>> ACTIVE RULES:    Connected to IncidentConsolePanel Block IP triggers.\n");
        } else {
            sb.append(">>> STATUS:          Standard Monitored Telemetry Scope\n");
            sb.append(">>> INGESTION PROTO: Syslog RFC 5424 / Simulated Local JSON Ingestion\n");
            sb.append(">>> VIVA HIGHLIGHT:  Demonstrates javax.swing.JTree & DefaultMutableTreeNode.\n");
        }

        sb.append("\n-----------------------------------------------------------------\n");
        sb.append("Swing Viva Tip: JTree uses TreeModel and TreeSelectionModel.\n");
        sb.append("TreeSelectionListener listens for user clicks and updates this panel.\n");

        txtNodeDetails.setText(sb.toString());
        txtNodeDetails.setCaretPosition(0);
    }
}
