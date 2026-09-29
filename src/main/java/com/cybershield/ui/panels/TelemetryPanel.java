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
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JSpinner;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;

/**
 * Panel displaying real-time simulated security telemetry event logs.
 * Demonstrates:
 * - Swing components: JTable, JSplitPane, JComboBox, JSpinner, JCheckBox,
 *   JTextField, JTextArea, JPopupMenu, JMenuItem, JFileChooser.
 */
public class TelemetryPanel extends JPanel {

    private final SecurityEventRepository eventRepository;
    private final DefaultTableModel tableModel;
    private final CyberTable eventTable;
    private final JTextField txtSearch;
    private final JComboBox<String> cmbEventType;
    private final JSpinner spinLimit;
    private final JCheckBox chkHighlightFailed;
    private final JTextArea txtPayloadPreview;
    private final JLabel lblCount;
    private List<SecurityEvent> currentEvents;
    private SecurityEvent selectedEvent;

    public TelemetryPanel() {
        this.eventRepository = new SecurityEventRepository(DatabaseManager.getInstance());

        setLayout(new BorderLayout(10, 10));
        setBackground(CyberTheme.BG_DARK);
        setBorder(BorderFactory.createEmptyBorder(14, 14, 14, 14));

        // 1. Top Container: Title + Filters Toolbar
        JPanel topContainer = new JPanel(new BorderLayout(8, 8));
        topContainer.setOpaque(false);

        JPanel topBar = new JPanel(new BorderLayout(8, 8));
        topBar.setOpaque(false);

        JLabel lblTitle = new JLabel("📡 SECURITY TELEMETRY LOG MONITOR");
        lblTitle.setFont(CyberTheme.FONT_TITLE);
        lblTitle.setForeground(CyberTheme.TEXT_PRIMARY);

        JPanel quickActions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        quickActions.setOpaque(false);

        StyledButton btnInjectBenign = new StyledButton("+ Ingest Test Telemetry", StyledButton.ButtonStyle.PRIMARY);
        btnInjectBenign.setToolTipText("Add a simulated background security event");
        btnInjectBenign.addActionListener(e -> injectSampleEvent());

        StyledButton btnExport = new StyledButton("📁 Export CSV (JFileChooser)", StyledButton.ButtonStyle.SECONDARY);
        btnExport.setToolTipText("Demonstrates javax.swing.JFileChooser to export telemetry logs");
        btnExport.addActionListener(e -> exportTelemetryToCsv());

        StyledButton btnRefresh = new StyledButton("Refresh", StyledButton.ButtonStyle.SECONDARY);
        btnRefresh.addActionListener(e -> refreshData());

        quickActions.add(btnInjectBenign);
        quickActions.add(btnExport);
        quickActions.add(btnRefresh);

        topBar.add(lblTitle, BorderLayout.WEST);
        topBar.add(quickActions, BorderLayout.EAST);
        topContainer.add(topBar, BorderLayout.NORTH);

        // Filter Bar with JComboBox, JSpinner, JTextField, and JCheckBox
        JPanel filterBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 4));
        filterBar.setBackground(CyberTheme.BG_CARD);
        filterBar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                BorderFactory.createEmptyBorder(4, 10, 4, 10)
        ));

        filterBar.add(new JLabel("Search Filter:") {{ setForeground(CyberTheme.TEXT_MUTED); setFont(CyberTheme.FONT_BODY_BOLD); }});
        txtSearch = new JTextField(14);
        txtSearch.setBackground(CyberTheme.BG_DARK);
        txtSearch.setForeground(CyberTheme.TEXT_PRIMARY);
        txtSearch.setCaretColor(CyberTheme.ACCENT_CYAN);
        txtSearch.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                BorderFactory.createEmptyBorder(4, 6, 4, 6)
        ));
        filterBar.add(txtSearch);

        StyledButton btnFilter = new StyledButton("Search", StyledButton.ButtonStyle.SECONDARY);
        btnFilter.addActionListener(e -> performSearch());
        filterBar.add(btnFilter);

        filterBar.add(new JSeparator(JSeparator.VERTICAL) {{ setPreferredSize(new Dimension(2, 20)); }});

        // JComboBox
        filterBar.add(new JLabel("Type (JComboBox):") {{ setForeground(CyberTheme.ACCENT_CYAN); setFont(CyberTheme.FONT_BODY_BOLD); }});
        cmbEventType = new JComboBox<>(new String[]{"ALL TYPES", "AUTH_FAILURE", "SUSPICIOUS_EMAIL", "PROCESS_EXECUTION", "NETWORK_ANOMALY"});
        cmbEventType.setBackground(CyberTheme.BG_DARK);
        cmbEventType.setForeground(CyberTheme.TEXT_PRIMARY);
        cmbEventType.setFont(CyberTheme.FONT_SMALL);
        cmbEventType.addActionListener(e -> performSearch());
        filterBar.add(cmbEventType);

        filterBar.add(new JSeparator(JSeparator.VERTICAL) {{ setPreferredSize(new Dimension(2, 20)); }});

        // JSpinner
        filterBar.add(new JLabel("Limit (JSpinner):") {{ setForeground(CyberTheme.STATUS_AMBER); setFont(CyberTheme.FONT_BODY_BOLD); }});
        spinLimit = new JSpinner(new SpinnerNumberModel(50, 10, 500, 10));
        spinLimit.setPreferredSize(new Dimension(65, 26));
        spinLimit.addChangeListener(e -> refreshData());
        filterBar.add(spinLimit);

        // JCheckBox
        chkHighlightFailed = new JCheckBox("Failed Events Only (JCheckBox)");
        chkHighlightFailed.setOpaque(false);
        chkHighlightFailed.setFont(CyberTheme.FONT_SMALL);
        chkHighlightFailed.setForeground(CyberTheme.TEXT_PRIMARY);
        chkHighlightFailed.addActionListener(e -> performSearch());
        filterBar.add(chkHighlightFailed);

        topContainer.add(filterBar, BorderLayout.SOUTH);
        add(topContainer, BorderLayout.NORTH);

        // 2. Initialize Bottom Payload Inspector first so listener can safely reference it
        txtPayloadPreview = new JTextArea("Select a telemetry event from the table above to inspect raw protocol payload...");
        txtPayloadPreview.setEditable(false);
        txtPayloadPreview.setFont(CyberTheme.FONT_MONO);
        txtPayloadPreview.setBackground(CyberTheme.BG_CARD);
        txtPayloadPreview.setForeground(CyberTheme.ACCENT_CYAN);
        txtPayloadPreview.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // Center Table
        String[] columnNames = {"Event ID", "Timestamp", "Type", "Source IP", "Username / Host", "Severity", "Description"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override public boolean isCellEditable(int row, int column) { return false; }
        };
        eventTable = new CyberTable(tableModel);

        eventTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = eventTable.getSelectedRow();
                if (selectedRow >= 0 && currentEvents != null && selectedRow < currentEvents.size()) {
                    selectedEvent = currentEvents.get(selectedRow);
                    txtPayloadPreview.setText(String.format(
                        "=== RAW TELEMETRY EVENT PACKET [%s] ===\nTimestamp: %s\nEvent Type: %s | Severity: %s\nSource IP: %s -> Target Principal: %s\nSummary: %s\n\n[Raw Telemetry Payload]:\n%s",
                        selectedEvent.getEventId(), DateTimeUtils.format(selectedEvent.getTimestamp()), selectedEvent.getEventType(),
                        selectedEvent.getSeverity(), selectedEvent.getSourceIp(), selectedEvent.getUsername(), selectedEvent.getDescription(),
                        selectedEvent.getRawPayload() != null ? selectedEvent.getRawPayload() : "(None)"
                    ));
                    txtPayloadPreview.setCaretPosition(0);
                }
            }
        });

        // JPopupMenu on Table
        JPopupMenu popupMenu = createEventPopupMenu();
        eventTable.setComponentPopupMenu(popupMenu);
        eventTable.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) { if (e.isPopupTrigger()) selectRow(e); }
            @Override public void mouseReleased(MouseEvent e) { if (e.isPopupTrigger()) selectRow(e); }
            private void selectRow(MouseEvent e) {
                int r = eventTable.rowAtPoint(e.getPoint());
                if (r >= 0 && r < eventTable.getRowCount()) {
                    eventTable.setRowSelectionInterval(r, r);
                }
            }
        });

        JScrollPane tableScroll = CyberTable.wrapInScrollPane(eventTable);
        tableScroll.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                " Live Ingested Telemetry Feed (Right-Click for JPopupMenu) ",
                0, 0, CyberTheme.FONT_BODY_BOLD, CyberTheme.ACCENT_CYAN
        ));

        JScrollPane previewScroll = new JScrollPane(txtPayloadPreview);
        previewScroll.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1),
                " Packet Inspection Buffer (JTextArea) ",
                0, 0, CyberTheme.FONT_BODY_BOLD, CyberTheme.STATUS_GREEN
        ));

        JPanel bottomPane = new JPanel(new BorderLayout(4, 4));
        bottomPane.setOpaque(false);
        bottomPane.add(previewScroll, BorderLayout.CENTER);

        lblCount = new JLabel("Telemetry Records: 0");
        lblCount.setFont(CyberTheme.FONT_SMALL);
        lblCount.setForeground(CyberTheme.TEXT_MUTED);
        bottomPane.add(lblCount, BorderLayout.SOUTH);

        // JSplitPane
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, bottomPane);
        splitPane.setResizeWeight(0.65);
        splitPane.setDividerSize(6);
        splitPane.setOpaque(false);
        splitPane.setBorder(null);

        add(splitPane, BorderLayout.CENTER);
        refreshData();
    }

    private JPopupMenu createEventPopupMenu() {
        JPopupMenu popup = new JPopupMenu();
        popup.setBackground(CyberTheme.BG_CARD);
        popup.setBorder(BorderFactory.createLineBorder(CyberTheme.ACCENT_CYAN, 1));

        JMenuItem miCopyId = new JMenuItem("📋 Copy Event ID");
        miCopyId.addActionListener(e -> {
            if (selectedEvent != null) {
                Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(new StringSelection(selectedEvent.getEventId()), null);
                JOptionPane.showMessageDialog(this, "Copied Event ID: " + selectedEvent.getEventId(), "Clipboard", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        JMenuItem miCopyIp = new JMenuItem("🌐 Copy Source IP Address");
        miCopyIp.addActionListener(e -> {
            if (selectedEvent != null) {
                Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(new StringSelection(selectedEvent.getSourceIp()), null);
                JOptionPane.showMessageDialog(this, "Copied IP: " + selectedEvent.getSourceIp(), "Clipboard", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        JMenuItem miCopyPayload = new JMenuItem("📄 Copy Raw Payload JSON");
        miCopyPayload.addActionListener(e -> {
            if (selectedEvent != null && selectedEvent.getRawPayload() != null) {
                Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(new StringSelection(selectedEvent.getRawPayload()), null);
                JOptionPane.showMessageDialog(this, "Raw payload copied to system clipboard!", "Clipboard", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        popup.add(miCopyId);
        popup.add(miCopyIp);
        popup.add(miCopyPayload);
        return popup;
    }

    public void refreshData() {
        try {
            int limit = (int) spinLimit.getValue();
            currentEvents = eventRepository.findAll(limit);
            populateTable(currentEvents);
        } catch (DatabaseOperationException e) {
            JOptionPane.showMessageDialog(this, "Failed to load telemetry: " + e.getMessage(), "Database Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void performSearch() {
        String keyword = txtSearch.getText().trim();
        String selectedType = (String) cmbEventType.getSelectedItem();
        boolean failOnly = chkHighlightFailed.isSelected();

        try {
            int limit = (int) spinLimit.getValue();
            List<SecurityEvent> rawList = keyword.isEmpty()
                    ? eventRepository.findAll(limit)
                    : eventRepository.search(keyword);

            // Filter by JComboBox and JCheckBox in memory
            currentEvents = rawList.stream()
                    .filter(e -> {
                        if (selectedType != null && !selectedType.equals("ALL TYPES")) {
                            if (!e.getEventType().name().equals(selectedType)) return false;
                        }
                        if (failOnly) {
                            String desc = e.getDescription().toLowerCase();
                            return desc.contains("fail") || desc.contains("unauthorized") || desc.contains("denied");
                        }
                        return true;
                    })
                    .toList();

            populateTable(currentEvents);
        } catch (DatabaseOperationException e) {
            JOptionPane.showMessageDialog(this, "Search failed: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void populateTable(List<SecurityEvent> events) {
        tableModel.setRowCount(0);
        for (SecurityEvent e : events) {
            tableModel.addRow(new Object[]{
                e.getEventId(),
                DateTimeUtils.formatTimeOnly(e.getTimestamp()),
                e.getEventType().name(),
                e.getSourceIp(),
                e.getUsername(),
                e.getSeverity().name(),
                e.getDescription()
            });
        }
        lblCount.setText(String.format("Telemetry Records Displayed: %d (Fetched from SQLite via JDBC)", events.size()));
    }

    private void injectSampleEvent() {
        try {
            SecurityEvent evt = SimulationDataGenerator.generateBenignEvent();
            eventRepository.save(evt);
            refreshData();
            JOptionPane.showMessageDialog(this, "Simulated security event ingested:\n" + evt.getDescription(), "Event Ingested", JOptionPane.INFORMATION_MESSAGE);
        } catch (DatabaseOperationException e) {
            JOptionPane.showMessageDialog(this, "Failed to inject event: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void exportTelemetryToCsv() {
        if (currentEvents == null || currentEvents.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No telemetry records available to export.", "Empty Feed", JOptionPane.WARNING_MESSAGE);
            return;
        }

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Export Telemetry Log Stream to CSV (JFileChooser)");
        fileChooser.setSelectedFile(new File("cybershield_telemetry_export.csv"));
        fileChooser.setFileFilter(new FileNameExtensionFilter("CSV Files (*.csv)", "csv"));

        int userSelection = fileChooser.showSaveDialog(this);
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File fileToSave = fileChooser.getSelectedFile();
            if (!fileToSave.getName().toLowerCase().endsWith(".csv")) {
                fileToSave = new File(fileToSave.getParentFile(), fileToSave.getName() + ".csv");
            }

            try (FileWriter writer = new FileWriter(fileToSave)) {
                writer.write("Event ID,Timestamp,Event Type,Source IP,Username/Host,Severity,Description,Raw Payload\n");
                for (SecurityEvent e : currentEvents) {
                    writer.write(String.format("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
                            e.getEventId(),
                            DateTimeUtils.format(e.getTimestamp()),
                            e.getEventType().name(),
                            e.getSourceIp(),
                            e.getUsername(),
                            e.getSeverity().name(),
                            e.getDescription().replace("\"", "\"\""),
                            e.getRawPayload() != null ? e.getRawPayload().replace("\"", "\"\"") : ""
                    ));
                }
                JOptionPane.showMessageDialog(this,
                        "Successfully exported " + currentEvents.size() + " telemetry records to:\n" + fileToSave.getAbsolutePath(),
                        "Export Successful", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "Error saving CSV file: " + ex.getMessage(), "Export Failed", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
}
