package com.cybershield.ui.components;

import com.cybershield.ui.CyberTheme;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.util.HashSet;
import java.util.Set;
import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;

/**
 * Demonstrates javax.swing.JList and DefaultListModel.
 * Shows active firewall blocked IPs, quarantine list, and containment state.
 */
public class BlockedIpsListPanel extends JPanel {

    private final DefaultListModel<String> listModel;
    private final JList<String> ipList;
    private final JLabel lblSelectedInfo;
    private final JTextField txtNewIp;
    private final Set<String> blockedSet = new HashSet<>();

    public BlockedIpsListPanel() {
        setLayout(new BorderLayout(8, 8));
        setBackground(CyberTheme.BG_DARK);
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Top Header
        JPanel topHeader = new JPanel(new BorderLayout(6, 6));
        topHeader.setOpaque(false);

        JLabel title = new JLabel("🛡 ACTIVE FIREWALL BLOCKED IPs & QUARANTINE LIST");
        title.setFont(CyberTheme.FONT_TITLE);
        title.setForeground(CyberTheme.STATUS_RED);

        JLabel sub = new JLabel("Live containment enforcement list using javax.swing.JList & DefaultListModel");
        sub.setFont(CyberTheme.FONT_SMALL);
        sub.setForeground(CyberTheme.TEXT_MUTED);

        topHeader.add(title, BorderLayout.NORTH);
        topHeader.add(sub, BorderLayout.SOUTH);
        add(topHeader, BorderLayout.NORTH);

        // Center JList
        listModel = new DefaultListModel<>();
        seedDefaultBlockedIps();

        ipList = new JList<>(listModel);
        ipList.setBackground(CyberTheme.BG_CARD);
        ipList.setForeground(CyberTheme.TEXT_PRIMARY);
        ipList.setFont(CyberTheme.FONT_MONO);
        ipList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        ipList.setSelectionBackground(CyberTheme.ACCENT_BLUE);
        ipList.setSelectionForeground(java.awt.Color.WHITE);

        JScrollPane scrollPane = new JScrollPane(ipList);
        scrollPane.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                " Simulated Active Perimeter Droplist (JList) ", 0, 0, CyberTheme.FONT_BODY_BOLD, CyberTheme.ACCENT_CYAN
        ));

        // Right Detail & Action Panel
        JPanel rightPanel = new JPanel(new BorderLayout(8, 8));
        rightPanel.setBackground(CyberTheme.BG_CARD);
        rightPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                BorderFactory.createEmptyBorder(12, 12, 12, 12)
        ));
        rightPanel.setPreferredSize(new Dimension(340, 200));

        lblSelectedInfo = new JLabel("<html><b>Selected Rule:</b> None<br>Select an IP from the JList on the left to inspect or unblock.</html>");
        lblSelectedInfo.setFont(CyberTheme.FONT_BODY);
        lblSelectedInfo.setForeground(CyberTheme.TEXT_PRIMARY);

        ipList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                String selected = ipList.getSelectedValue();
                if (selected != null) {
                    lblSelectedInfo.setText("<html><b style='color:#00e5ff;'>Selected Firewall Rule:</b><br><br>" +
                            "<b>Entry:</b> " + selected + "<br>" +
                            "<b>Action:</b> DROP / REJECT ALL INGRESS<br>" +
                            "<b>Policy:</b> Active Simulated Mitigation<br>" +
                            "<b>Viva Concept:</b> JList with ListSelectionListener</html>");
                }
            }
        });

        // Controls to add or remove IP
        JPanel controls = new JPanel(new GridLayout(4, 1, 6, 6));
        controls.setOpaque(false);

        txtNewIp = new JTextField("198.51.100.99");
        txtNewIp.setBackground(CyberTheme.BG_DARK);
        txtNewIp.setForeground(CyberTheme.TEXT_PRIMARY);
        txtNewIp.setCaretColor(CyberTheme.ACCENT_CYAN);
        txtNewIp.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                BorderFactory.createEmptyBorder(4, 8, 4, 8)
        ));

        StyledButton btnAdd = new StyledButton("+ Block New IP Address", StyledButton.ButtonStyle.DANGER);
        btnAdd.addActionListener(e -> addManualIp());

        StyledButton btnRemove = new StyledButton("✓ Unblock Selected IP", StyledButton.ButtonStyle.PRIMARY);
        btnRemove.addActionListener(e -> removeSelectedIp());

        StyledButton btnClear = new StyledButton("Reset Default Droplist", StyledButton.ButtonStyle.SECONDARY);
        btnClear.addActionListener(e -> seedDefaultBlockedIps());

        controls.add(txtNewIp);
        controls.add(btnAdd);
        controls.add(btnRemove);
        controls.add(btnClear);

        rightPanel.add(lblSelectedInfo, BorderLayout.CENTER);
        rightPanel.add(controls, BorderLayout.SOUTH);

        JPanel centerContainer = new JPanel(new GridLayout(1, 2, 10, 10));
        centerContainer.setOpaque(false);
        centerContainer.add(scrollPane);
        centerContainer.add(rightPanel);

        add(centerContainer, BorderLayout.CENTER);
    }

    private void seedDefaultBlockedIps() {
        listModel.clear();
        blockedSet.clear();
        addIpToModel("198.51.100.24 — [BRUTE FORCE] Attacker SSH Spray (HIGH)");
        addIpToModel("203.0.113.88 — [PHISHING] Malicious Credential Harvest Host");
        addIpToModel("192.0.2.145 — [GEO-ANOMALY] Impossible Travel Login Attempt");
        addIpToModel("185.220.101.5 — [TOR EXIT] Known Malicious Proxy Node");
        addIpToModel("45.154.255.89 — [SCANNER] Automated Vulnerability Prober");
    }

    public synchronized void addIpToModel(String entry) {
        if (!blockedSet.contains(entry)) {
            blockedSet.add(entry);
            listModel.addElement(entry);
        }
    }

    private void addManualIp() {
        String ip = txtNewIp.getText().trim();
        if (ip.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter an IP address or hostname to block.", "Validation Error", JOptionPane.WARNING_MESSAGE);
            return;
        }
        String entry = ip + " — [MANUAL SOC BLOCK] Custom Perimeter Mitigation";
        addIpToModel(entry);
        JOptionPane.showMessageDialog(this, "Firewall rule created: Dropping ingress traffic from " + ip, "Rule Activated", JOptionPane.INFORMATION_MESSAGE);
    }

    private void removeSelectedIp() {
        int index = ipList.getSelectedIndex();
        if (index >= 0) {
            String val = listModel.get(index);
            listModel.remove(index);
            blockedSet.remove(val);
            lblSelectedInfo.setText("<html><b>Selected Rule:</b> None<br>Unblocked rule: " + val + "</html>");
            JOptionPane.showMessageDialog(this, "Successfully removed firewall rule for:\n" + val, "IP Unblocked", JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(this, "Please select an IP address from the JList first.", "No Selection", JOptionPane.WARNING_MESSAGE);
        }
    }
}
