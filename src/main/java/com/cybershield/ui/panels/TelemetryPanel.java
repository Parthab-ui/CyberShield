package com.cybershield.ui.panels;

import com.cybershield.exception.DatabaseOperationException;
import com.cybershield.model.SecurityEvent;
import com.cybershield.repository.DatabaseManager;
import com.cybershield.repository.SecurityEventRepository;
import com.cybershield.ui.CyberTheme;
import com.cybershield.ui.components.CyberTable;
import com.cybershield.ui.components.StyledButton;
import com.cybershield.util.DateTimeUtils;
import com.cybershield.util.SimulationDataGenerator;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableModel;

/**
 * Panel displaying real-time simulated security telemetry event logs.
 */
public class TelemetryPanel extends JPanel {

    private final SecurityEventRepository eventRepository;
    private final DefaultTableModel tableModel;
    private final CyberTable eventTable;
    private final JTextField txtSearch;
    private final JTextArea txtPayloadPreview;
    private final JLabel lblCount;
    private List<SecurityEvent> currentEvents;

    public TelemetryPanel() {
        this.eventRepository = new SecurityEventRepository(DatabaseManager.getInstance());

        setLayout(new BorderLayout(10, 10));
        setBackground(CyberTheme.BG_DARK);
        setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        // Top Toolbar
        JPanel topBar = new JPanel(new BorderLayout(8, 8));
        topBar.setOpaque(false);

        JLabel lblTitle = new JLabel("SECURITY TELEMETRY LOG MONITOR");
        lblTitle.setFont(CyberTheme.FONT_TITLE);
        lblTitle.setForeground(CyberTheme.TEXT_PRIMARY);

        JPanel actionControls = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        actionControls.setOpaque(false);

        txtSearch = new JTextField(16);
        txtSearch.setBackground(CyberTheme.BG_CARD);
        txtSearch.setForeground(CyberTheme.TEXT_PRIMARY);
        txtSearch.setCaretColor(CyberTheme.ACCENT_CYAN);
        txtSearch.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                BorderFactory.createEmptyBorder(6, 8, 6, 8)
        ));

        StyledButton btnSearch = new StyledButton("Filter Logs", StyledButton.ButtonStyle.SECONDARY);
        btnSearch.addActionListener(e -> performSearch());

        StyledButton btnInjectBenign = new StyledButton("+ Add Simulated Event", StyledButton.ButtonStyle.PRIMARY);
        btnInjectBenign.addActionListener(e -> injectSampleEvent());

        StyledButton btnRefresh = new StyledButton("Refresh", StyledButton.ButtonStyle.SECONDARY);
        btnRefresh.addActionListener(e -> refreshData());

        actionControls.add(new JLabel("Search:") {{ setForeground(CyberTheme.TEXT_MUTED); }});
        actionControls.add(txtSearch);
        actionControls.add(btnSearch);
        actionControls.add(btnInjectBenign);
        actionControls.add(btnRefresh);

        topBar.add(lblTitle, BorderLayout.WEST);
        topBar.add(actionControls, BorderLayout.EAST);
        add(topBar, BorderLayout.NORTH);

        // Initialize Details Preview text area first so lambda can reference it
        txtPayloadPreview = new JTextArea("Select a telemetry event from the table above to inspect raw protocol payload...");
        txtPayloadPreview.setEditable(false);
        txtPayloadPreview.setFont(CyberTheme.FONT_MONO);
        txtPayloadPreview.setBackground(CyberTheme.BG_CARD);
        txtPayloadPreview.setForeground(CyberTheme.ACCENT_CYAN);
        txtPayloadPreview.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // Center Table
        String[] columnNames = {"Event ID", "Timestamp", "Type", "Source IP", "Username / Host", "Severity", "Description"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        eventTable = new CyberTable(tableModel);
        eventTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = eventTable.getSelectedRow();
                if (selectedRow >= 0 && currentEvents != null && selectedRow < currentEvents.size()) {
                    SecurityEvent evt = currentEvents.get(selectedRow);
                    txtPayloadPreview.setText(String.format(
                        "=== RAW TELEMETRY EVENT PACKET [%s] ===\nTimestamp: %s\nEvent Type: %s | Severity: %s\nSource IP: %s -> Target Principal: %s\nSummary: %s\n\n[Raw Telemetry Payload]:\n%s",
                        evt.getEventId(), DateTimeUtils.format(evt.getTimestamp()), evt.getEventType(),
                        evt.getSeverity(), evt.getSourceIp(), evt.getUsername(), evt.getDescription(),
                        evt.getRawPayload() != null ? evt.getRawPayload() : "(None)"
                    ));
                }
            }
        });

        JScrollPane tableScroll = CyberTable.wrapInScrollPane(eventTable);

        // Bottom Details Pane
        JPanel bottomPane = new JPanel(new BorderLayout(8, 8));
        bottomPane.setOpaque(false);
        bottomPane.setPreferredSize(new Dimension(800, 130));

        JScrollPane previewScroll = new JScrollPane(txtPayloadPreview);
        previewScroll.setBorder(BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1));

        JPanel statusBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 4));
        statusBar.setOpaque(false);
        lblCount = new JLabel("Telemetry Records: 0");
        lblCount.setFont(CyberTheme.FONT_SMALL);
        lblCount.setForeground(CyberTheme.TEXT_MUTED);
        statusBar.add(lblCount);

        bottomPane.add(previewScroll, BorderLayout.CENTER);
        bottomPane.add(statusBar, BorderLayout.SOUTH);

        JPanel centerContainer = new JPanel(new BorderLayout(0, 10));
        centerContainer.setOpaque(false);
        centerContainer.add(tableScroll, BorderLayout.CENTER);
        centerContainer.add(bottomPane, BorderLayout.SOUTH);

        add(centerContainer, BorderLayout.CENTER);

        refreshData();
    }

    public void refreshData() {
        try {
            currentEvents = eventRepository.findAll(200);
            updateTableRows(currentEvents);
        } catch (DatabaseOperationException e) {
            JOptionPane.showMessageDialog(this, "Failed to load events: " + e.getMessage(), "Database Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void performSearch() {
        String keyword = txtSearch.getText().trim();
        try {
            if (keyword.isEmpty()) {
                currentEvents = eventRepository.findAll(200);
            } else {
                currentEvents = eventRepository.search(keyword);
            }
            updateTableRows(currentEvents);
        } catch (DatabaseOperationException e) {
            JOptionPane.showMessageDialog(this, "Search error: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void injectSampleEvent() {
        try {
            SecurityEvent evt = SimulationDataGenerator.generateBenignEvent();
            eventRepository.save(evt);
            refreshData();
        } catch (DatabaseOperationException e) {
            JOptionPane.showMessageDialog(this, "Failed to inject event: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void updateTableRows(List<SecurityEvent> events) {
        tableModel.setRowCount(0);
        if (events != null) {
            for (SecurityEvent evt : events) {
                tableModel.addRow(new Object[]{
                    evt.getEventId(),
                    DateTimeUtils.format(evt.getTimestamp()),
                    evt.getEventType().getDisplayName(),
                    evt.getSourceIp(),
                    evt.getUsername(),
                    evt.getSeverity().name(),
                    evt.getDescription()
                });
            }
            lblCount.setText(String.format("Telemetry Records Displayed: %d (Real-time simulated feed)", events.size()));
        }
    }
}
