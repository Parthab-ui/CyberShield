package cybershield.gui;

import cybershield.dao.LogDAO;
import cybershield.dao.ThreatDAO;
import cybershield.model.LogEntry;
import cybershield.model.Threat;
import cybershield.model.User;
import cybershield.util.ReportGenerator;
import cybershield.util.Theme;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JEditorPane;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JSpinner;
import javax.swing.JTable;
import javax.swing.JTextPane;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingConstants;
import javax.swing.SwingWorker;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

/**
 * ReportPanel — Cybersecurity reporting module supporting HTML and styled text formats.
 * Demonstrates: CardLayout, JEditorPane ("text/html"), JTextPane with StyledDocument,
 * SimpleAttributeSet styling, JTable with DefaultTableModel, SwingWorker generation, and JFileChooser export.
 */
public class ReportPanel extends BasePanel {

    private static final String CARD_SUMMARY   = "Summary Report";
    private static final String CARD_THREAT    = "Threat Report";
    private static final String CARD_INCIDENT  = "Incident Report";
    private static final String CARD_LOGS      = "Activity Log";

    private final ReportGenerator reportGenerator;
    private final ThreatDAO       threatDAO;
    private final LogDAO          logDAO;
    private User                  currentUser;

    /** Sets the current logged-in user for report context. */
    public void setCurrentUser(User user) {
        this.currentUser = user;
    }

    // CardLayout container
    private JPanel      cardsContainer;
    private CardLayout  cardLayout;
    private String      activeCardName = CARD_SUMMARY;

    // Report display components
    private JEditorPane       summaryEditorPane;
    private JTextPane         threatTextPane;
    private JEditorPane       incidentEditorPane;
    private JTable            logsTable;
    private DefaultTableModel logsTableModel;

    // Controls
    private JSpinner     daysSpinner;
    private JButton      generateButton;
    private JButton      exportButton;
    private JButton      printPreviewButton;
    private JProgressBar progressBar;

    // Constructor — builds the report interface
    public ReportPanel() {
        this.reportGenerator = new ReportGenerator();
        this.threatDAO       = new ThreatDAO();
        this.logDAO          = new LogDAO();

        setBackground(Theme.BACKGROUND);
        setLayout(new BorderLayout(0, 6));
        setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        add(createControlsBar(), BorderLayout.NORTH);
        add(createCardsArea(), BorderLayout.CENTER);

        // Initial generation
        generateReports();
    }

    // ================================================================
    // NORTH: CONTROLS & CARD SELECTORS
    // ================================================================

    /** Creates toolbar with CardLayout radio toggles, spinner, and generation actions. */
    private JPanel createControlsBar() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        bar.setBackground(Theme.PANEL_BG);
        bar.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Theme.ACCENT, 1),
            BorderFactory.createEmptyBorder(4, 6, 4, 6)
        ));

        // Card selectors
        JLabel viewLbl = new JLabel("Report Type:");
        viewLbl.setFont(Theme.FONT_SMALL);
        viewLbl.setForeground(Theme.TEXT_SECONDARY);

        JRadioButton rbSummary  = new JRadioButton("Summary", true);
        JRadioButton rbThreat   = new JRadioButton("Threats", false);
        JRadioButton rbIncident = new JRadioButton("Incidents", false);
        JRadioButton rbLogs     = new JRadioButton("Logs", false);

        styleRadio(rbSummary);
        styleRadio(rbThreat);
        styleRadio(rbIncident);
        styleRadio(rbLogs);

        ButtonGroup group = new ButtonGroup();
        group.add(rbSummary);
        group.add(rbThreat);
        group.add(rbIncident);
        group.add(rbLogs);

        rbSummary.addActionListener(e -> switchCard(CARD_SUMMARY));
        rbThreat.addActionListener(e -> switchCard(CARD_THREAT));
        rbIncident.addActionListener(e -> switchCard(CARD_INCIDENT));
        rbLogs.addActionListener(e -> switchCard(CARD_LOGS));

        // Days scope spinner
        JLabel daysLbl = new JLabel("Days:");
        daysLbl.setFont(Theme.FONT_SMALL);
        daysLbl.setForeground(Theme.TEXT_SECONDARY);
        daysSpinner = new JSpinner(new SpinnerNumberModel(30, 1, 365, 5));
        daysSpinner.setPreferredSize(new Dimension(55, 24));

        // Action buttons
        generateButton = new JButton("Generate");
        Theme.styleButton(generateButton);
        generateButton.setToolTipText("Recompile reports with latest database data");

        exportButton = new JButton("Export File");
        Theme.styleButton(exportButton);
        exportButton.setBackground(Theme.PANEL_BG);
        exportButton.setForeground(Theme.TEXT_PRIMARY);
        exportButton.setToolTipText("Save active report to disk");

        printPreviewButton = new JButton("Print Preview");
        Theme.styleButton(printPreviewButton);
        printPreviewButton.setBackground(Theme.PANEL_BG);
        printPreviewButton.setForeground(Theme.TEXT_SECONDARY);
        printPreviewButton.setToolTipText("Preview printed page format");

        progressBar = new JProgressBar(0, 100);
        progressBar.setPreferredSize(new Dimension(100, 18));
        progressBar.setForeground(Theme.ACCENT);
        progressBar.setBackground(Theme.BACKGROUND);
        progressBar.setVisible(false);

        generateButton.addActionListener(e -> generateReports());
        exportButton.addActionListener(e -> exportActiveReport());
        printPreviewButton.addActionListener(e -> JOptionPane.showMessageDialog(this,
            "Print Preview: 1 Page ready for printer spooler.\nOrientation: Portrait | Paper: A4",
            "Print Preview", JOptionPane.INFORMATION_MESSAGE));

        bar.add(viewLbl);
        bar.add(rbSummary);
        bar.add(rbThreat);
        bar.add(rbIncident);
        bar.add(rbLogs);
        bar.add(new JSeparator(SwingConstants.VERTICAL));
        bar.add(daysLbl);
        bar.add(daysSpinner);
        bar.add(generateButton);
        bar.add(exportButton);
        bar.add(printPreviewButton);
        bar.add(progressBar);

        return bar;
    }

    private void styleRadio(JRadioButton rb) {
        rb.setBackground(Theme.PANEL_BG);
        rb.setForeground(Theme.TEXT_PRIMARY);
        rb.setFont(Theme.FONT_SMALL);
    }

    // ================================================================
    // CENTER: CARDLAYOUT PANELS
    // ================================================================

    /** Creates central container managed by CardLayout. */
    private JPanel createCardsArea() {
        cardLayout = new CardLayout();
        cardsContainer = new JPanel(cardLayout);
        cardsContainer.setBackground(Theme.BACKGROUND);

        // 1. Summary Report Card (JEditorPane HTML)
        summaryEditorPane = new JEditorPane();
        summaryEditorPane.setEditable(false);
        summaryEditorPane.setContentType("text/html");
        summaryEditorPane.setBackground(Theme.BACKGROUND);
        JScrollPane summaryScroll = new JScrollPane(summaryEditorPane);
        summaryScroll.setBorder(BorderFactory.createLineBorder(new Color(40, 40, 70)));
        cardsContainer.add(summaryScroll, CARD_SUMMARY);

        // 2. Threat Report Card (JTextPane StyledDocument)
        threatTextPane = new JTextPane();
        threatTextPane.setEditable(false);
        threatTextPane.setBackground(new Color(18, 18, 40));
        threatTextPane.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        JScrollPane threatScroll = new JScrollPane(threatTextPane);
        threatScroll.setBorder(BorderFactory.createLineBorder(new Color(40, 40, 70)));
        cardsContainer.add(threatScroll, CARD_THREAT);

        // 3. Incident Report Card (JEditorPane HTML)
        incidentEditorPane = new JEditorPane();
        incidentEditorPane.setEditable(false);
        incidentEditorPane.setContentType("text/html");
        incidentEditorPane.setBackground(Theme.BACKGROUND);
        JScrollPane incidentScroll = new JScrollPane(incidentEditorPane);
        incidentScroll.setBorder(BorderFactory.createLineBorder(new Color(40, 40, 70)));
        cardsContainer.add(incidentScroll, CARD_INCIDENT);

        // 4. Activity Log Card (JTable with DefaultTableModel)
        String[] logCols = {"ID", "User ID", "Action Performed", "Timestamp"};
        logsTableModel = new DefaultTableModel(logCols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) { return false; }
        };
        logsTable = new JTable(logsTableModel);
        logsTable.setBackground(Theme.PANEL_BG);
        logsTable.setForeground(Theme.TEXT_PRIMARY);
        logsTable.setFont(Theme.FONT_BODY);
        logsTable.setRowHeight(22);
        logsTable.getTableHeader().setBackground(new Color(35, 35, 75));
        logsTable.getTableHeader().setForeground(Theme.ACCENT);
        JScrollPane logsScroll = new JScrollPane(logsTable);
        logsScroll.setBorder(BorderFactory.createLineBorder(new Color(40, 40, 70)));
        cardsContainer.add(logsScroll, CARD_LOGS);

        return cardsContainer;
    }

    /** Switches active visible card. */
    private void switchCard(String cardName) {
        this.activeCardName = cardName;
        cardLayout.show(cardsContainer, cardName);
    }

    // ================================================================
    // ASYNC REPORT GENERATION (SWINGWORKER)
    // ================================================================

    /** Runs report generation in background using SwingWorker. */
    private void generateReports() {
        int days = (Integer) daysSpinner.getValue();
        generateButton.setEnabled(false);
        progressBar.setVisible(true);
        progressBar.setIndeterminate(true);

        SwingWorker<Void, Void> worker = new SwingWorker<Void, Void>() {
            private String summaryHtml;
            private String incidentHtml;
            private List<Threat> threats;
            private List<LogEntry> logs;

            @Override
            protected Void doInBackground() throws Exception {
                // Fetch and prepare report data in background
                Thread.sleep(400); // Simulated assembly pause
                summaryHtml  = reportGenerator.generateSummaryHtmlReport(days);
                incidentHtml = reportGenerator.generateIncidentHtmlReport(days);
                threats      = threatDAO.getRecentThreats(days);
                if (threats.isEmpty()) threats = threatDAO.getAll();
                logs         = logDAO.getRecentLogs(days);
                if (logs.isEmpty()) logs = logDAO.getAll();
                return null;
            }

            @Override
            protected void done() {
                generateButton.setEnabled(true);
                progressBar.setIndeterminate(false);
                progressBar.setVisible(false);

                // Update HTML editor panes
                summaryEditorPane.setText(summaryHtml);
                summaryEditorPane.setCaretPosition(0);

                incidentEditorPane.setText(incidentHtml);
                incidentEditorPane.setCaretPosition(0);

                // Populate StyledDocument in JTextPane
                populateThreatStyledDocument(threats);

                // Populate Activity Log Table
                logsTableModel.setRowCount(0);
                for (LogEntry l : logs) {
                    logsTableModel.addRow(new Object[]{
                        l.getId(), l.getUserId(), l.getAction(), l.getLogTime()
                    });
                }
            }
        };

        worker.execute();
    }

    /** Populates JTextPane using StyledDocument and SimpleAttributeSet. */
    private void populateThreatStyledDocument(List<Threat> threats) {
        StyledDocument doc = threatTextPane.getStyledDocument();
        try {
            doc.remove(0, doc.getLength());

            // Header Style
            SimpleAttributeSet headerStyle = new SimpleAttributeSet();
            StyleConstants.setFontFamily(headerStyle, "Segoe UI");
            StyleConstants.setFontSize(headerStyle, 16);
            StyleConstants.setBold(headerStyle, true);
            StyleConstants.setForeground(headerStyle, Theme.ACCENT);

            doc.insertString(doc.getLength(), "THREAT INTELLIGENCE AUDIT LOG\n", headerStyle);
            doc.insertString(doc.getLength(), "Analyzed Threats: " + threats.size() + "\n\n", null);

            // Severity Attributes
            SimpleAttributeSet critStyle = new SimpleAttributeSet();
            StyleConstants.setBold(critStyle, true);
            StyleConstants.setForeground(critStyle, new Color(230, 50, 50));

            SimpleAttributeSet highStyle = new SimpleAttributeSet();
            StyleConstants.setBold(highStyle, true);
            StyleConstants.setForeground(highStyle, new Color(255, 140, 0));

            SimpleAttributeSet medStyle = new SimpleAttributeSet();
            StyleConstants.setBold(medStyle, true);
            StyleConstants.setForeground(medStyle, new Color(240, 200, 50));

            SimpleAttributeSet lowStyle = new SimpleAttributeSet();
            StyleConstants.setBold(lowStyle, true);
            StyleConstants.setForeground(lowStyle, new Color(50, 200, 80));

            SimpleAttributeSet bodyStyle = new SimpleAttributeSet();
            StyleConstants.setForeground(bodyStyle, Theme.TEXT_PRIMARY);

            for (Threat t : threats) {
                doc.insertString(doc.getLength(), String.format("Threat #%d: [", t.getId()), bodyStyle);

                String sev = t.getSeverity().toUpperCase();
                SimpleAttributeSet appliedStyle = lowStyle;
                if ("CRITICAL".equals(sev)) appliedStyle = critStyle;
                else if ("HIGH".equals(sev)) appliedStyle = highStyle;
                else if ("MEDIUM".equals(sev)) appliedStyle = medStyle;

                doc.insertString(doc.getLength(), sev, appliedStyle);
                doc.insertString(doc.getLength(), String.format("] Type: %s | Target: %s | Source IP: %s\n",
                    t.getThreatType(), t.getTargetSystem(), t.getSourceIp()), bodyStyle);
            }

        } catch (BadLocationException e) {
            System.out.println("Error formatting styled document: " + e.getMessage());
        }
        threatTextPane.setCaretPosition(0);
    }

    // ================================================================
    // EXPORT ACTION
    // ================================================================

    /** Exports current card content to file using JFileChooser. */
    private void exportActiveReport() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export " + activeCardName);

        String ext = (activeCardName.equals(CARD_SUMMARY) || activeCardName.equals(CARD_INCIDENT)) ? ".html" : ".txt";
        chooser.setSelectedFile(new File(activeCardName.replace(" ", "_").toLowerCase() + ext));
        chooser.setFileFilter(new FileNameExtensionFilter("Report Files (*" + ext + ")", ext.substring(1)));

        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            try (FileWriter writer = new FileWriter(file)) {
                if (activeCardName.equals(CARD_SUMMARY)) {
                    writer.write(summaryEditorPane.getText());
                } else if (activeCardName.equals(CARD_INCIDENT)) {
                    writer.write(incidentEditorPane.getText());
                } else if (activeCardName.equals(CARD_THREAT)) {
                    writer.write(threatTextPane.getText());
                } else {
                    for (int i = 0; i < logsTable.getRowCount(); i++) {
                        writer.write(String.format("%s | %s | %s | %s\n",
                            logsTable.getValueAt(i, 0), logsTable.getValueAt(i, 1),
                            logsTable.getValueAt(i, 2), logsTable.getValueAt(i, 3)));
                    }
                }
                JOptionPane.showMessageDialog(this, "Exported successfully to:\n" + file.getAbsolutePath(),
                    "Export Finished", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "Failed to write file: " + ex.getMessage(),
                    "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    /** BasePanel contract implementation. */
    @Override
    public void refreshData() {
        generateReports();
    }
}
