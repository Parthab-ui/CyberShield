package com.cybershield.ui.panels;

import com.cybershield.exception.DatabaseOperationException;
import com.cybershield.model.Incident;
import com.cybershield.model.ResponseAction;
import com.cybershield.model.Threat;
import com.cybershield.model.enums.IncidentStatus;
import com.cybershield.model.enums.ResponseActionType;
import com.cybershield.model.enums.Severity;
import com.cybershield.model.enums.ThreatType;
import com.cybershield.repository.DatabaseManager;
import com.cybershield.repository.IncidentRepository;
import com.cybershield.repository.ResponseActionRepository;
import com.cybershield.repository.ThreatRepository;
import com.cybershield.ui.CyberTheme;
import com.cybershield.ui.components.CyberTable;
import com.cybershield.ui.components.StyledButton;
import com.cybershield.util.DateTimeUtils;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.table.DefaultTableModel;

/**
 * Analytics Panel showing threat breakdowns, mitigation metrics, and response action audit logs.
 */
public class AnalyticsPanel extends JPanel {

    private final ThreatRepository threatRepository;
    private final IncidentRepository incidentRepository;
    private final ResponseActionRepository responseActionRepository;

    private final JPanel pnlTypeStats;
    private final JPanel pnlSeverityStats;
    private final JPanel pnlIncidentStats;
    private final DefaultTableModel auditTableModel;
    private final CyberTable auditTable;

    public AnalyticsPanel() {
        DatabaseManager db = DatabaseManager.getInstance();
        this.threatRepository = new ThreatRepository(db);
        this.responseActionRepository = new ResponseActionRepository(db);
        this.incidentRepository = new IncidentRepository(db, threatRepository, responseActionRepository);

        setLayout(new BorderLayout(12, 12));
        setBackground(CyberTheme.BG_DARK);
        setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        // Header
        JPanel topBar = new JPanel(new BorderLayout(8, 8));
        topBar.setOpaque(false);

        JLabel lblTitle = new JLabel("SECURITY METRICS & RESPONSE AUDIT LOG");
        lblTitle.setFont(CyberTheme.FONT_TITLE);
        lblTitle.setForeground(CyberTheme.TEXT_PRIMARY);

        StyledButton btnRefresh = new StyledButton("Refresh Metrics", StyledButton.ButtonStyle.SECONDARY);
        btnRefresh.addActionListener(e -> refreshData());

        topBar.add(lblTitle, BorderLayout.WEST);
        topBar.add(btnRefresh, BorderLayout.EAST);
        add(topBar, BorderLayout.NORTH);

        // Top 3 Analytics Cards
        JPanel metricsContainer = new JPanel(new GridLayout(1, 3, 12, 12));
        metricsContainer.setOpaque(false);
        metricsContainer.setPreferredSize(new Dimension(800, 180));

        pnlTypeStats = createCardPanel("THREATS BY CATEGORY");
        pnlSeverityStats = createCardPanel("THREATS BY SEVERITY");
        pnlIncidentStats = createCardPanel("INCIDENTS BY STATUS");

        metricsContainer.add(pnlTypeStats);
        metricsContainer.add(pnlSeverityStats);
        metricsContainer.add(pnlIncidentStats);

        // Bottom Table: Response Actions Audit Log
        String[] auditCols = {"Action ID", "Incident ID", "Action Dispatched", "Target Entity", "Operator", "Status", "Timestamp"};
        auditTableModel = new DefaultTableModel(auditCols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) { return false; }
        };
        auditTable = new CyberTable(auditTableModel);
        JScrollPane auditScroll = CyberTable.wrapInScrollPane(auditTable);
        auditScroll.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                " Incident Response Containment Audit Trail ", 0, 0, CyberTheme.FONT_BODY_BOLD, CyberTheme.ACCENT_CYAN
        ));

        JPanel centerPanel = new JPanel(new BorderLayout(0, 12));
        centerPanel.setOpaque(false);
        centerPanel.add(metricsContainer, BorderLayout.NORTH);
        centerPanel.add(auditScroll, BorderLayout.CENTER);

        add(centerPanel, BorderLayout.CENTER);

        refreshData();
    }

    private JPanel createCardPanel(String title) {
        JPanel card = new JPanel(new BorderLayout(6, 6));
        card.setBackground(CyberTheme.BG_CARD);
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                BorderFactory.createEmptyBorder(10, 12, 10, 12)
        ));

        JLabel lbl = new JLabel(title);
        lbl.setFont(CyberTheme.FONT_HEADER);
        lbl.setForeground(CyberTheme.ACCENT_CYAN);
        card.add(lbl, BorderLayout.NORTH);

        JPanel content = new JPanel();
        content.setLayout(new GridLayout(4, 1, 4, 4));
        content.setOpaque(false);
        card.add(content, BorderLayout.CENTER);

        return card;
    }

    public void refreshData() {
        try {
            // Aggregate Threats
            List<Threat> threats = threatRepository.findAll();
            Map<ThreatType, Integer> typeCounts = new EnumMap<>(ThreatType.class);
            Map<Severity, Integer> sevCounts = new EnumMap<>(Severity.class);

            for (Threat t : threats) {
                typeCounts.put(t.getThreatType(), typeCounts.getOrDefault(t.getThreatType(), 0) + 1);
                sevCounts.put(t.getSeverity(), sevCounts.getOrDefault(t.getSeverity(), 0) + 1);
            }

            int totalThreats = Math.max(1, threats.size());

            // Populate Category Panel
            JPanel typeContent = (JPanel) ((BorderLayout) pnlTypeStats.getLayout()).getLayoutComponent(BorderLayout.CENTER);
            typeContent.removeAll();
            for (ThreatType tt : ThreatType.values()) {
                int count = typeCounts.getOrDefault(tt, 0);
                typeContent.add(createMetricBar(tt.name(), count, totalThreats, CyberTheme.ACCENT_BLUE));
            }
            pnlTypeStats.revalidate();
            pnlTypeStats.repaint();

            // Populate Severity Panel
            JPanel sevContent = (JPanel) ((BorderLayout) pnlSeverityStats.getLayout()).getLayoutComponent(BorderLayout.CENTER);
            sevContent.removeAll();
            for (Severity sv : Severity.values()) {
                int count = sevCounts.getOrDefault(sv, 0);
                Color barColor = switch (sv) {
                    case CRITICAL -> CyberTheme.STATUS_RED;
                    case HIGH -> new Color(249, 115, 22);
                    case MEDIUM -> CyberTheme.STATUS_AMBER;
                    case LOW -> CyberTheme.STATUS_GREEN;
                };
                sevContent.add(createMetricBar(sv.name(), count, totalThreats, barColor));
            }
            pnlSeverityStats.revalidate();
            pnlSeverityStats.repaint();

            // Populate Incident Panel
            List<Incident> incidents = incidentRepository.findAll();
            Map<IncidentStatus, Integer> incCounts = new EnumMap<>(IncidentStatus.class);
            for (Incident inc : incidents) {
                incCounts.put(inc.getStatus(), incCounts.getOrDefault(inc.getStatus(), 0) + 1);
            }
            int totalIncidents = Math.max(1, incidents.size());

            JPanel incContent = (JPanel) ((BorderLayout) pnlIncidentStats.getLayout()).getLayoutComponent(BorderLayout.CENTER);
            incContent.removeAll();
            for (IncidentStatus is : IncidentStatus.values()) {
                int count = incCounts.getOrDefault(is, 0);
                Color barColor = is == IncidentStatus.RESOLVED ? CyberTheme.STATUS_GREEN :
                                 (is == IncidentStatus.OPEN ? CyberTheme.STATUS_RED : CyberTheme.STATUS_AMBER);
                incContent.add(createMetricBar(is.name(), count, totalIncidents, barColor));
            }
            pnlIncidentStats.revalidate();
            pnlIncidentStats.repaint();

            // Populate Audit Table
            List<ResponseAction> actions = responseActionRepository.findAll(100);
            auditTableModel.setRowCount(0);
            for (ResponseAction act : actions) {
                auditTableModel.addRow(new Object[]{
                    act.getActionId(),
                    act.getIncidentId(),
                    act.getActionType().getDisplayName(),
                    act.getTarget(),
                    act.getExecutedBy(),
                    act.getStatus(),
                    DateTimeUtils.format(act.getExecutedAt())
                });
            }

        } catch (DatabaseOperationException e) {
            JOptionPane.showMessageDialog(this, "Failed to compute analytics: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private JPanel createMetricBar(String label, int value, int total, Color color) {
        JPanel barPanel = new JPanel(new BorderLayout(6, 2));
        barPanel.setOpaque(false);

        JLabel lbl = new JLabel(String.format("%s: %d", label, value));
        lbl.setFont(CyberTheme.FONT_SMALL);
        lbl.setForeground(CyberTheme.TEXT_PRIMARY);

        JProgressBar progress = new JProgressBar(0, total);
        progress.setValue(value);
        progress.setForeground(color);
        progress.setBackground(CyberTheme.BG_SIDEBAR);
        progress.setBorderPainted(false);
        progress.setPreferredSize(new Dimension(80, 8));

        barPanel.add(lbl, BorderLayout.WEST);
        barPanel.add(progress, BorderLayout.CENTER);
        return barPanel;
    }
}
