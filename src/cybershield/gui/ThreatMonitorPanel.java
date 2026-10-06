package cybershield.gui;

import cybershield.dao.BlockedIPDAO;
import cybershield.dao.LogDAO;
import cybershield.dao.ThreatDAO;
import cybershield.model.BlockedIP;
import cybershield.model.LogEntry;
import cybershield.model.Threat;
import cybershield.model.User;
import cybershield.util.Theme;
import cybershield.util.Validator;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.awt.Point;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;
import java.util.Random;
import java.util.regex.Pattern;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBoxMenuItem;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JProgressBar;
import javax.swing.JRadioButtonMenuItem;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JSpinner;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JTree;
import javax.swing.ListSelectionModel;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import javax.swing.RowFilter;

/**
 * ThreatMonitorPanel — The Threat Monitoring module for CyberShield.
 * Demonstrates: JTable, custom ThreatTableModel, TableRowSorter, RowFilter,
 * custom TableCellRenderer, JPopupMenu, JTree, JSplitPane, JTabbedPane,
 * SwingWorker for asynchronous background tasks, and plain CSV export.
 */
public class ThreatMonitorPanel extends BasePanel {

    // DAOs for database interaction
    private ThreatDAO    threatDAO;
    private BlockedIPDAO blockedIPDAO;
    private LogDAO       logDAO;

    // Currently logged-in user (for audit log tagging)
    private User currentUser;

    // ---- NORTH: Filter Bar Components ----
    private JTextField        searchField;
    private JComboBox<String> severityCombo;
    private JComboBox<String> statusCombo;
    private JSpinner          daysSpinner;
    private JButton           applyFilterButton;
    private JButton           resetFilterButton;
    private JButton           addThreatButton;
    private JButton           refreshButton;
    private JButton           exportButton;

    // ---- CENTER LEFT: JTable Components ----
    private JTable                        threatTable;
    private ThreatTableModel              tableModel;
    private TableRowSorter<ThreatTableModel> tableSorter;
    private JPopupMenu                    tablePopupMenu;
    private JCheckBoxMenuItem             criticalOnlyItem;

    // ---- CENTER LEFT: JTree Components ----
    private JTree                 networkTree;
    private DefaultMutableTreeNode rootNode;
    private DefaultTreeModel      treeModel;

    // ---- CENTER RIGHT: Details Panel Components ----
    private JLabel    detailIdLabel;
    private JLabel    detailTypeLabel;
    private JLabel    detailIpLabel;
    private JLabel    detailTargetLabel;
    private JLabel    detailSeverityLabel;
    private JLabel    detailStatusLabel;
    private JLabel    detailDateLabel;
    private JTextArea detailTextArea;
    private JButton   btnInvestigate;
    private JButton   btnResolve;
    private JButton   btnBlockFromDetail;
    private JButton   btnDeleteFromDetail;
    private Threat    selectedThreat;

    // ---- CENTER RIGHT: Blocked IPs Tab Components ----
    private DefaultListModel<String> blockedListModel;
    private JList<String>            blockedIpList;
    private JTextField               blockIpInput;
    private JTextField               blockReasonInput;
    private JButton                  blockIpButton;
    private JButton                  unblockButton;

    // ---- SOUTH: Scan & Progress Components ----
    private JProgressBar      scanProgressBar;
    private JLabel            statusLabel;
    private JButton           startScanButton;
    private JButton           cancelScanButton;
    private ThreatScanWorker  currentScanWorker;

    // Constructor — builds the entire module layout
    public ThreatMonitorPanel() {
        this.threatDAO    = new ThreatDAO();
        this.blockedIPDAO = new BlockedIPDAO();
        this.logDAO       = new LogDAO();

        setBackground(Theme.BACKGROUND);
        setLayout(new BorderLayout(0, 6));
        setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        add(createFilterBar(), BorderLayout.NORTH);
        add(createSplitArea(), BorderLayout.CENTER);
        add(createStatusArea(), BorderLayout.SOUTH);

        // Initial data load
        refreshData();
    }

    /** Sets the logged-in user for audit logging. */
    public void setCurrentUser(User user) {
        this.currentUser = user;
    }

    /** Returns the current user ID or fallback to 1. */
    private int getUserId() {
        return (currentUser != null) ? currentUser.getId() : 1;
    }

    // ================================================================
    // 1. NORTH: FILTER BAR
    // ================================================================

    /** Creates the top filter bar with inputs, combos, spinner, and action buttons. */
    private JPanel createFilterBar() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        bar.setBackground(Theme.PANEL_BG);
        bar.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Theme.ACCENT, 1),
            BorderFactory.createEmptyBorder(4, 6, 4, 6)
        ));

        // Search text input
        JLabel searchLbl = new JLabel("Search:");
        searchLbl.setFont(Theme.FONT_SMALL);
        searchLbl.setForeground(Theme.TEXT_SECONDARY);
        searchField = new JTextField(10);
        styleField(searchField);
        searchField.setToolTipText("Filter by Threat Type, Source IP, or Target System");

        // Severity dropdown
        JLabel sevLbl = new JLabel("Severity:");
        sevLbl.setFont(Theme.FONT_SMALL);
        sevLbl.setForeground(Theme.TEXT_SECONDARY);
        severityCombo = new JComboBox<>(new String[]{"ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"});
        styleCombo(severityCombo);
        severityCombo.setToolTipText("Filter threats by severity");

        // Status dropdown
        JLabel statLbl = new JLabel("Status:");
        statLbl.setFont(Theme.FONT_SMALL);
        statLbl.setForeground(Theme.TEXT_SECONDARY);
        statusCombo = new JComboBox<>(new String[]{"ALL", "DETECTED", "INVESTIGATING", "RESOLVED"});
        styleCombo(statusCombo);
        statusCombo.setToolTipText("Filter threats by investigation status");

        // Days spinner
        JLabel daysLbl = new JLabel("Last days:");
        daysLbl.setFont(Theme.FONT_SMALL);
        daysLbl.setForeground(Theme.TEXT_SECONDARY);
        daysSpinner = new JSpinner(new SpinnerNumberModel(30, 1, 365, 5));
        daysSpinner.setPreferredSize(new Dimension(55, 24));
        daysSpinner.setToolTipText("Load threats from the past N days");

        // Filter action buttons
        applyFilterButton = new JButton("Filter");
        Theme.styleButton(applyFilterButton);
        applyFilterButton.setToolTipText("Apply filters to table");

        resetFilterButton = new JButton("Reset");
        Theme.styleButton(resetFilterButton);
        resetFilterButton.setBackground(Theme.PANEL_BG);
        resetFilterButton.setForeground(Theme.TEXT_SECONDARY);
        resetFilterButton.setToolTipText("Clear all filters");

        addThreatButton = new JButton("+ Add Threat");
        Theme.styleButton(addThreatButton);
        addThreatButton.setBackground(Theme.SUCCESS);
        addThreatButton.setForeground(Color.BLACK);
        addThreatButton.setToolTipText("Manually record a new threat");

        refreshButton = new JButton("⟳ Refresh");
        Theme.styleButton(refreshButton);
        refreshButton.setToolTipText("Reload all data from database");

        exportButton = new JButton("Export CSV");
        Theme.styleButton(exportButton);
        exportButton.setToolTipText("Export currently visible rows to CSV file");

        // Event listener: Apply filter clicked
        applyFilterButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                applyTableFilters();
            }
        });

        // Event listener: Reset filter clicked
        resetFilterButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                resetFilters();
            }
        });

        // Event listener: Add Threat button clicked
        addThreatButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                openAddThreatDialog();
            }
        });

        // Event listener: Refresh button clicked
        refreshButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                refreshData();
            }
        });

        // Event listener: Export CSV clicked
        exportButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                exportVisibleRowsToCSV();
            }
        });

        // Assemble filter bar
        bar.add(searchLbl);
        bar.add(searchField);
        bar.add(sevLbl);
        bar.add(severityCombo);
        bar.add(statLbl);
        bar.add(statusCombo);
        bar.add(daysLbl);
        bar.add(daysSpinner);
        bar.add(applyFilterButton);
        bar.add(resetFilterButton);
        bar.add(new JSeparator(SwingConstants.VERTICAL));
        bar.add(addThreatButton);
        bar.add(refreshButton);
        bar.add(exportButton);

        return bar;
    }

    // ================================================================
    // 2. CENTER: SPLIT PANE (LEFT TABS & RIGHT DETAILS)
    // ================================================================

    /** Creates the central JSplitPane splitting Table/Tree on the left and Details on the right. */
    private JSplitPane createSplitArea() {
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setBackground(Theme.BACKGROUND);
        splitPane.setDividerLocation(700);
        splitPane.setResizeWeight(0.65);
        splitPane.setBorder(null);

        // Left side: Tabbed pane with Threat Log (Table) and Network Map (Tree)
        JTabbedPane leftTabbedPane = new JTabbedPane();
        leftTabbedPane.setBackground(Theme.PANEL_BG);
        leftTabbedPane.setForeground(Theme.TEXT_PRIMARY);
        leftTabbedPane.setFont(Theme.FONT_BODY);

        leftTabbedPane.addTab("Threat Log", createTablePanel());
        leftTabbedPane.addTab("Network Map", createTreePanel());

        // Right side: Tabbed pane with Threat Details and Blocked IPs
        JTabbedPane rightTabbedPane = new JTabbedPane();
        rightTabbedPane.setBackground(Theme.PANEL_BG);
        rightTabbedPane.setForeground(Theme.TEXT_PRIMARY);
        rightTabbedPane.setFont(Theme.FONT_BODY);

        rightTabbedPane.addTab("Threat Details", createDetailsPanel());
        rightTabbedPane.addTab("Blocked IPs", createBlockedIpPanel());

        splitPane.setLeftComponent(leftTabbedPane);
        splitPane.setRightComponent(rightTabbedPane);

        return splitPane;
    }

    // ================================================================
    // 3. THREAT LOG: JTABLE WITH SORTER, RENDERER, AND POPUP MENU
    // ================================================================

    /** Builds the Threat Log tab containing the JTable. */
    private JPanel createTablePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(Theme.PANEL_BG);

        tableModel  = new ThreatTableModel();
        threatTable = new JTable(tableModel);

        // Configure table appearance
        threatTable.setBackground(Theme.PANEL_BG);
        threatTable.setForeground(Theme.TEXT_PRIMARY);
        threatTable.setGridColor(new Color(50, 50, 80));
        threatTable.setFont(Theme.FONT_BODY);
        threatTable.setRowHeight(24);
        threatTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        threatTable.setSelectionBackground(Theme.ACCENT.darker().darker());
        threatTable.setSelectionForeground(Theme.TEXT_PRIMARY);
        threatTable.getTableHeader().setBackground(new Color(35, 35, 75));
        threatTable.getTableHeader().setForeground(Theme.ACCENT);
        threatTable.getTableHeader().setFont(new Font("Segoe UI", Font.BOLD, 13));

        // Alternate row colors for non-severity columns
        threatTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                                                           boolean isSelected, boolean hasFocus,
                                                           int row, int col) {
                super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
                if (!isSelected) {
                    setBackground(row % 2 == 0 ? Theme.PANEL_BG : Theme.TABLE_ROW_ALT);
                }
                return this;
            }
        });

        // Set custom TableCellRenderer on Severity column (index 4)
        threatTable.getColumnModel().getColumn(4).setCellRenderer(new SeverityCellRenderer());

        // Attach TableRowSorter for click-to-sort on headers and RowFilter support
        tableSorter = new TableRowSorter<>(tableModel);
        // Custom comparator for Severity column: CRITICAL > HIGH > MEDIUM > LOW
        tableSorter.setComparator(4, new Comparator<String>() {
            @Override
            public int compare(String s1, String s2) {
                return Integer.compare(getSeverityRank(s1), getSeverityRank(s2));
            }
        });
        threatTable.setRowSorter(tableSorter);

        // Selection listener: update right-hand details panel when a row is clicked
        threatTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) {
                    int selectedViewRow = threatTable.getSelectedRow();
                    if (selectedViewRow != -1) {
                        int modelRow = threatTable.convertRowIndexToModel(selectedViewRow);
                        selectedThreat = tableModel.getThreatAt(modelRow);
                        displayThreatDetails(selectedThreat);
                    }
                }
            }
        });

        // Create right-click context menu
        createTablePopupMenu();

        // Mouse listener: popup trigger on right-click
        threatTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                handlePopupTrigger(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                handlePopupTrigger(e);
            }
        });

        JScrollPane scrollPane = new JScrollPane(threatTable);
        scrollPane.setBackground(Theme.PANEL_BG);
        scrollPane.getViewport().setBackground(Theme.PANEL_BG);
        scrollPane.setBorder(BorderFactory.createLineBorder(new Color(40, 40, 70)));
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    /** Handles opening the popup menu on right click and selecting the targeted row. */
    private void handlePopupTrigger(MouseEvent e) {
        if (e.isPopupTrigger()) {
            int row = threatTable.rowAtPoint(e.getPoint());
            if (row != -1) {
                threatTable.setRowSelectionInterval(row, row);
                int modelRow = threatTable.convertRowIndexToModel(row);
                selectedThreat = tableModel.getThreatAt(modelRow);
                displayThreatDetails(selectedThreat);
            }
            tablePopupMenu.show(e.getComponent(), e.getX(), e.getY());
        }
    }

    /** Builds the right-click JPopupMenu with actions, filter toggle, and sort options. */
    private void createTablePopupMenu() {
        tablePopupMenu = new JPopupMenu();
        tablePopupMenu.setBackground(Theme.PANEL_BG);

        JMenuItem itemInvestigating = new JMenuItem("Mark as Investigating");
        JMenuItem itemResolved      = new JMenuItem("Mark as Resolved");
        JMenuItem itemBlockIp       = new JMenuItem("Block Source IP");
        JMenuItem itemDelete        = new JMenuItem("Delete Threat");

        styleMenuItem(itemInvestigating);
        styleMenuItem(itemResolved);
        styleMenuItem(itemBlockIp);
        styleMenuItem(itemDelete);

        // Action: Mark as Investigating
        itemInvestigating.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                updateSelectedThreatStatus("INVESTIGATING");
            }
        });

        // Action: Mark as Resolved
        itemResolved.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                updateSelectedThreatStatus("RESOLVED");
            }
        });

        // Action: Block Source IP
        itemBlockIp.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                blockSelectedThreatIP();
            }
        });

        // Action: Delete Threat
        itemDelete.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                deleteSelectedThreat();
            }
        });

        tablePopupMenu.add(itemInvestigating);
        tablePopupMenu.add(itemResolved);
        tablePopupMenu.add(itemBlockIp);
        tablePopupMenu.add(itemDelete);
        tablePopupMenu.addSeparator();

        // Checkbox menu item: Highlight Critical Only
        criticalOnlyItem = new JCheckBoxMenuItem("Highlight Critical Only");
        criticalOnlyItem.setBackground(Theme.PANEL_BG);
        criticalOnlyItem.setForeground(Theme.TEXT_PRIMARY);
        criticalOnlyItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                applyTableFilters();
            }
        });
        tablePopupMenu.add(criticalOnlyItem);
        tablePopupMenu.addSeparator();

        // Radio button menu item group: Sort by Date vs Severity
        JRadioButtonMenuItem sortByDate = new JRadioButtonMenuItem("Sort by: Date", true);
        JRadioButtonMenuItem sortBySev  = new JRadioButtonMenuItem("Sort by: Severity", false);
        sortByDate.setBackground(Theme.PANEL_BG);
        sortByDate.setForeground(Theme.TEXT_PRIMARY);
        sortBySev.setBackground(Theme.PANEL_BG);
        sortBySev.setForeground(Theme.TEXT_PRIMARY);

        ButtonGroup sortGroup = new ButtonGroup();
        sortGroup.add(sortByDate);
        sortGroup.add(sortBySev);

        sortByDate.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                List<RowSorter.SortKey> keys = new ArrayList<>();
                keys.add(new RowSorter.SortKey(6, SortOrder.DESCENDING)); // Detected At
                tableSorter.setSortKeys(keys);
            }
        });

        sortBySev.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                List<RowSorter.SortKey> keys = new ArrayList<>();
                keys.add(new RowSorter.SortKey(4, SortOrder.DESCENDING)); // Severity
                tableSorter.setSortKeys(keys);
            }
        });

        tablePopupMenu.add(sortByDate);
        tablePopupMenu.add(sortBySev);
    }

    /** Styles JMenuItem for dark theme popup menu. */
    private void styleMenuItem(JMenuItem item) {
        item.setBackground(Theme.PANEL_BG);
        item.setForeground(Theme.TEXT_PRIMARY);
        item.setFont(Theme.FONT_BODY);
    }

    // ================================================================
    // 4. NETWORK MAP: JTREE
    // ================================================================

    /** Builds the Network Map tab containing the hierarchical JTree. */
    private JPanel createTreePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(Theme.PANEL_BG);

        rootNode  = new DefaultMutableTreeNode("Network Infrastructure");
        treeModel = new DefaultTreeModel(rootNode);
        networkTree = new JTree(treeModel);

        networkTree.setBackground(Theme.PANEL_BG);
        networkTree.setForeground(Theme.TEXT_PRIMARY);
        networkTree.setFont(Theme.FONT_BODY);

        // Customize tree cell colors
        DefaultTreeCellRenderer renderer = new DefaultTreeCellRenderer();
        renderer.setBackgroundNonSelectionColor(Theme.PANEL_BG);
        renderer.setTextNonSelectionColor(Theme.TEXT_PRIMARY);
        renderer.setTextSelectionColor(Theme.ACCENT);
        renderer.setBackgroundSelectionColor(Theme.PANEL_BG.darker());
        networkTree.setCellRenderer(renderer);

        // Selection listener: when a tree leaf is clicked, show its details in right panel
        networkTree.addTreeSelectionListener(new TreeSelectionListener() {
            @Override
            public void valueChanged(TreeSelectionEvent e) {
                DefaultMutableTreeNode node =
                    (DefaultMutableTreeNode) networkTree.getLastSelectedPathComponent();
                if (node == null || !node.isLeaf()) {
                    return;
                }
                Object userObj = node.getUserObject();
                if (userObj instanceof ThreatNodeWrapper) {
                    selectedThreat = ((ThreatNodeWrapper) userObj).getThreat();
                    displayThreatDetails(selectedThreat);
                }
            }
        });

        JScrollPane scrollPane = new JScrollPane(networkTree);
        scrollPane.setBackground(Theme.PANEL_BG);
        scrollPane.getViewport().setBackground(Theme.PANEL_BG);
        scrollPane.setBorder(BorderFactory.createLineBorder(new Color(40, 40, 70)));
        panel.add(scrollPane, BorderLayout.CENTER);

        // Top button bar: Expand All & Collapse All
        JPanel treeToolBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        treeToolBar.setBackground(Theme.PANEL_BG);

        JButton expandAllBtn = new JButton("Expand All");
        Theme.styleButton(expandAllBtn);
        JButton collapseAllBtn = new JButton("Collapse All");
        Theme.styleButton(collapseAllBtn);
        collapseAllBtn.setBackground(Theme.PANEL_BG);
        collapseAllBtn.setForeground(Theme.TEXT_SECONDARY);

        expandAllBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                expandAllNodes(networkTree);
            }
        });

        collapseAllBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                collapseAllNodes(networkTree);
            }
        });

        treeToolBar.add(expandAllBtn);
        treeToolBar.add(collapseAllBtn);
        panel.add(treeToolBar, BorderLayout.NORTH);

        return panel;
    }

    /** Rebuilds the JTree hierarchy: Root -> Target Systems -> Threats. */
    private void rebuildNetworkTree(List<Threat> threats) {
        rootNode.removeAllChildren();

        // Get distinct target systems from threats
        List<String> systems = threatDAO.getDistinctTargetSystems();
        for (String sys : systems) {
            DefaultMutableTreeNode sysNode = new DefaultMutableTreeNode("🖥 Target: " + sys);
            for (Threat t : threats) {
                if (t.getTargetSystem().equalsIgnoreCase(sys)) {
                    ThreatNodeWrapper wrapper = new ThreatNodeWrapper(t);
                    DefaultMutableTreeNode threatNode = new DefaultMutableTreeNode(wrapper);
                    sysNode.add(threatNode);
                }
            }
            rootNode.add(sysNode);
        }

        treeModel.reload();
        expandAllNodes(networkTree);
    }

    /** Expands all nodes in the given tree. */
    private void expandAllNodes(JTree tree) {
        for (int i = 0; i < tree.getRowCount(); i++) {
            tree.expandRow(i);
        }
    }

    /** Collapses all nodes in the given tree except root. */
    private void collapseAllNodes(JTree tree) {
        for (int i = tree.getRowCount() - 1; i > 0; i--) {
            tree.collapseRow(i);
        }
    }

    // ================================================================
    // 5. CENTER RIGHT: THREAT DETAILS & ACTION BUTTONS
    // ================================================================

    /** Creates the details panel showing threat attributes and quick actions. */
    private JPanel createDetailsPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 10));
        panel.setBackground(Theme.PANEL_BG);
        panel.setBorder(BorderFactory.createEmptyBorder(10, 12, 10, 12));

        // Top info grid
        JPanel grid = new JPanel(new GridLayout(7, 2, 6, 6));
        grid.setBackground(Theme.PANEL_BG);

        detailIdLabel       = new JLabel("—");
        detailTypeLabel     = new JLabel("—");
        detailIpLabel       = new JLabel("—");
        detailTargetLabel   = new JLabel("—");
        detailSeverityLabel = new JLabel("—");
        detailStatusLabel   = new JLabel("—");
        detailDateLabel     = new JLabel("—");

        styleDetailValue(detailIdLabel);
        styleDetailValue(detailTypeLabel);
        styleDetailValue(detailIpLabel);
        styleDetailValue(detailTargetLabel);
        styleDetailValue(detailSeverityLabel);
        styleDetailValue(detailStatusLabel);
        styleDetailValue(detailDateLabel);

        grid.add(makeDetailTitle("Threat ID:"));
        grid.add(detailIdLabel);
        grid.add(makeDetailTitle("Threat Type:"));
        grid.add(detailTypeLabel);
        grid.add(makeDetailTitle("Source IP:"));
        grid.add(detailIpLabel);
        grid.add(makeDetailTitle("Target System:"));
        grid.add(detailTargetLabel);
        grid.add(makeDetailTitle("Severity:"));
        grid.add(detailSeverityLabel);
        grid.add(makeDetailTitle("Status:"));
        grid.add(detailStatusLabel);
        grid.add(makeDetailTitle("Detected At:"));
        grid.add(detailDateLabel);

        panel.add(grid, BorderLayout.NORTH);

        // Center: Read-only dossier / analysis text area
        detailTextArea = new JTextArea(6, 20);
        detailTextArea.setEditable(false);
        detailTextArea.setLineWrap(true);
        detailTextArea.setWrapStyleWord(true);
        detailTextArea.setBackground(new Color(20, 20, 48));
        detailTextArea.setForeground(Theme.TEXT_SECONDARY);
        detailTextArea.setFont(Theme.FONT_BODY);
        detailTextArea.setText("Select a threat from the table or network tree to inspect details.");
        detailTextArea.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

        JScrollPane textScroll = new JScrollPane(detailTextArea);
        textScroll.setBorder(BorderFactory.createLineBorder(Theme.ACCENT, 1));
        panel.add(textScroll, BorderLayout.CENTER);

        // Bottom: Action buttons
        JPanel actionPanel = new JPanel(new GridLayout(2, 2, 8, 8));
        actionPanel.setBackground(Theme.PANEL_BG);

        btnInvestigate = new JButton("Investigate");
        Theme.styleButton(btnInvestigate);
        btnInvestigate.setToolTipText("Change status to INVESTIGATING");

        btnResolve = new JButton("Resolve");
        Theme.styleButton(btnResolve);
        btnResolve.setBackground(Theme.SUCCESS);
        btnResolve.setForeground(Color.BLACK);
        btnResolve.setToolTipText("Change status to RESOLVED");

        btnBlockFromDetail = new JButton("Block IP");
        Theme.styleButton(btnBlockFromDetail);
        btnBlockFromDetail.setBackground(Theme.WARNING);
        btnBlockFromDetail.setForeground(Color.BLACK);
        btnBlockFromDetail.setToolTipText("Add source IP to blocked list");

        btnDeleteFromDetail = new JButton("Delete");
        Theme.styleButton(btnDeleteFromDetail);
        btnDeleteFromDetail.setBackground(Theme.CRITICAL);
        btnDeleteFromDetail.setForeground(Theme.TEXT_PRIMARY);
        btnDeleteFromDetail.setToolTipText("Permanently delete this threat");

        // Action button listeners
        btnInvestigate.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                updateSelectedThreatStatus("INVESTIGATING");
            }
        });

        btnResolve.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                updateSelectedThreatStatus("RESOLVED");
            }
        });

        btnBlockFromDetail.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                blockSelectedThreatIP();
            }
        });

        btnDeleteFromDetail.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                deleteSelectedThreat();
            }
        });

        actionPanel.add(btnInvestigate);
        actionPanel.add(btnResolve);
        actionPanel.add(btnBlockFromDetail);
        actionPanel.add(btnDeleteFromDetail);
        panel.add(actionPanel, BorderLayout.SOUTH);

        return panel;
    }

    /** Populates the right-hand labels and dossier with threat details. */
    private void displayThreatDetails(Threat threat) {
        if (threat == null) return;

        detailIdLabel.setText(String.valueOf(threat.getId()));
        detailTypeLabel.setText(threat.getThreatType());
        detailIpLabel.setText(threat.getSourceIp());
        detailTargetLabel.setText(threat.getTargetSystem());
        detailSeverityLabel.setText(threat.getSeverity());
        detailStatusLabel.setText(threat.getStatus());
        detailDateLabel.setText(String.valueOf(threat.getDetectedAt()));

        String dossier = String.format(
            "THREAT ANALYSIS DOSSIER\n"
            + "------------------------------------\n"
            + "Threat ID: #%d\n"
            + "Classification: %s attack\n"
            + "Originating IP: %s\n"
            + "Target Asset: %s\n"
            + "Assessed Severity: %s\n"
            + "Incident Status: %s\n\n"
            + "Recommended Action:\n"
            + "Inspect firewall logs for packet bursts from %s and verify target %s patch level.",
            threat.getId(), threat.getThreatType(), threat.getSourceIp(),
            threat.getTargetSystem(), threat.getSeverity(), threat.getStatus(),
            threat.getSourceIp(), threat.getTargetSystem()
        );
        detailTextArea.setText(dossier);
    }

    // ================================================================
    // 6. BLOCKED IPS SECTION
    // ================================================================

    /** Creates the Blocked IPs tab with JList, input fields, and block/unblock actions. */
    private JPanel createBlockedIpPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 8));
        panel.setBackground(Theme.PANEL_BG);
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // JList showing currently blocked IPs
        blockedListModel = new DefaultListModel<>();
        blockedIpList    = new JList<>(blockedListModel);
        blockedIpList.setBackground(new Color(20, 20, 48));
        blockedIpList.setForeground(Theme.TEXT_PRIMARY);
        blockedIpList.setFont(Theme.FONT_BODY);
        blockedIpList.setSelectionBackground(Theme.ACCENT);
        blockedIpList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        JScrollPane scrollPane = new JScrollPane(blockedIpList);
        scrollPane.setBorder(BorderFactory.createLineBorder(Theme.ACCENT, 1));
        panel.add(scrollPane, BorderLayout.CENTER);

        // Input and button form
        JPanel inputPanel = new JPanel(new GridBagLayout());
        inputPanel.setBackground(Theme.PANEL_BG);

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill   = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(4, 4, 4, 4);

        blockIpInput = new JTextField(12);
        styleField(blockIpInput);
        blockIpInput.setToolTipText("Enter IPv4 address to block (e.g. 192.168.1.100)");

        blockReasonInput = new JTextField(12);
        styleField(blockReasonInput);
        blockReasonInput.setToolTipText("Reason for blocking (e.g. Port scanning)");

        blockIpButton = new JButton("Block IP");
        Theme.styleButton(blockIpButton);
        blockIpButton.setBackground(Theme.CRITICAL);
        blockIpButton.setForeground(Theme.TEXT_PRIMARY);

        unblockButton = new JButton("Unblock Selected");
        Theme.styleButton(unblockButton);
        unblockButton.setBackground(Theme.PANEL_BG);
        unblockButton.setForeground(Theme.TEXT_SECONDARY);

        // Event listener: Block IP
        blockIpButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                handleManualBlockIP();
            }
        });

        // Event listener: Unblock selected
        unblockButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                handleUnblockIP();
            }
        });

        gbc.gridx = 0; gbc.gridy = 0;
        inputPanel.add(makeDetailTitle("IP:"), gbc);
        gbc.gridx = 1;
        inputPanel.add(blockIpInput, gbc);

        gbc.gridx = 0; gbc.gridy = 1;
        inputPanel.add(makeDetailTitle("Reason:"), gbc);
        gbc.gridx = 1;
        inputPanel.add(blockReasonInput, gbc);

        gbc.gridx = 0; gbc.gridy = 2;
        inputPanel.add(blockIpButton, gbc);
        gbc.gridx = 1;
        inputPanel.add(unblockButton, gbc);

        panel.add(inputPanel, BorderLayout.SOUTH);

        return panel;
    }

    /** Manually blocks an IP address after validation. */
    private void handleManualBlockIP() {
        String ip     = blockIpInput.getText().trim();
        String reason = blockReasonInput.getText().trim();

        if (!Validator.isValidIP(ip)) {
            JOptionPane.showMessageDialog(this,
                "Please enter a valid IPv4 address (e.g. 192.168.1.50).",
                "Invalid IP", JOptionPane.WARNING_MESSAGE);
            return;
        }

        if (blockedIPDAO.existsByIP(ip)) {
            JOptionPane.showMessageDialog(this,
                "The IP '" + ip + "' is already blocked.",
                "Already Blocked", JOptionPane.WARNING_MESSAGE);
            return;
        }

        if (Validator.isEmpty(reason)) {
            reason = "Manual block by administrator";
        }

        blockedIPDAO.add(new BlockedIP(ip, reason));
        logDAO.add(new LogEntry(getUserId(), "IP blocked: " + ip + " (" + reason + ")"));

        blockIpInput.setText("");
        blockReasonInput.setText("");
        loadBlockedIPs();
        JOptionPane.showMessageDialog(this,
            "IP " + ip + " has been added to the blacklist.",
            "IP Blocked", JOptionPane.INFORMATION_MESSAGE);
    }

    /** Unblocks the currently selected IP in the list. */
    private void handleUnblockIP() {
        String selected = blockedIpList.getSelectedValue();
        if (selected == null) {
            JOptionPane.showMessageDialog(this,
                "Please select an IP address from the list to unblock.",
                "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Selected string is formatted as "192.168.1.1 — Reason"
        String ip = selected.split(" — ")[0].trim();
        blockedIPDAO.deleteByIP(ip);
        logDAO.add(new LogEntry(getUserId(), "IP unblocked: " + ip));

        loadBlockedIPs();
        JOptionPane.showMessageDialog(this,
            "IP " + ip + " has been removed from the blacklist.",
            "IP Unblocked", JOptionPane.INFORMATION_MESSAGE);
    }

    /** Reloads the Blocked IPs JList from the database. */
    private void loadBlockedIPs() {
        blockedListModel.clear();
        List<BlockedIP> list = blockedIPDAO.getAll();
        for (BlockedIP b : list) {
            blockedListModel.addElement(b.getIpAddress() + " — " + b.getReason());
        }
    }

    // ================================================================
    // 7. SOUTH: STATUS AREA & SIMULATED SCAN (SWINGWORKER)
    // ================================================================

    /** Creates the bottom status area with JProgressBar, label, and scan controls. */
    private JPanel createStatusArea() {
        JPanel south = new JPanel(new BorderLayout(0, 4));
        south.setBackground(Theme.BACKGROUND);
        south.add(new JSeparator(), BorderLayout.NORTH);

        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 4));
        panel.setBackground(Theme.PANEL_BG);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Theme.ACCENT, 1),
            BorderFactory.createEmptyBorder(4, 8, 4, 8)
        ));

        scanProgressBar = new JProgressBar(0, 100);
        scanProgressBar.setStringPainted(true);
        scanProgressBar.setPreferredSize(new Dimension(180, 20));
        scanProgressBar.setForeground(Theme.ACCENT);
        scanProgressBar.setBackground(Theme.BACKGROUND);

        statusLabel = new JLabel("System idle — Ready");
        statusLabel.setFont(Theme.FONT_SMALL);
        statusLabel.setForeground(Theme.TEXT_SECONDARY);

        startScanButton  = new JButton("▶ Start Scan");
        cancelScanButton = new JButton("■ Cancel Scan");
        Theme.styleButton(startScanButton);
        Theme.styleButton(cancelScanButton);
        cancelScanButton.setBackground(Theme.PANEL_BG);
        cancelScanButton.setForeground(Theme.TEXT_SECONDARY);
        cancelScanButton.setEnabled(false);

        // Event listener: Start scan clicked
        startScanButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                startSimulatedScan();
            }
        });

        // Event listener: Cancel scan clicked
        cancelScanButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (currentScanWorker != null && !currentScanWorker.isDone()) {
                    currentScanWorker.cancel(true);
                }
            }
        });

        panel.add(startScanButton);
        panel.add(cancelScanButton);
        panel.add(scanProgressBar);
        panel.add(statusLabel);

        south.add(panel, BorderLayout.CENTER);
        return south;
    }

    /** Initiates the 10-second simulated network scan via SwingWorker. */
    private void startSimulatedScan() {
        startScanButton.setEnabled(false);
        cancelScanButton.setEnabled(true);
        scanProgressBar.setValue(0);
        statusLabel.setText("Scanning network traffic...");

        currentScanWorker = new ThreatScanWorker();
        currentScanWorker.execute(); // Run on background worker thread
    }

    /**
     * ThreatScanWorker — Demonstrates SwingWorker<Void, Integer>.
     * Executes simulated scan in background (doInBackground), publishes intermediate progress,
     * updates progress bar on EDT (process), and saves discovered threats in done().
     */
    private class ThreatScanWorker extends SwingWorker<Void, Integer> {

        @Override
        protected Void doInBackground() throws Exception {
            // Simulate 10 seconds of scanning in 20 steps of 500ms
            for (int step = 1; step <= 20; step++) {
                if (isCancelled()) {
                    break;
                }
                Thread.sleep(500); // Simulated network packet inspection
                int percent = step * 5;
                publish(percent); // Sends progress to process() on EDT
            }
            return null;
        }

        @Override
        protected void process(List<Integer> chunks) {
            // Runs on the Event Dispatch Thread (EDT)
            if (!chunks.isEmpty()) {
                int latestProgress = chunks.get(chunks.size() - 1);
                scanProgressBar.setValue(latestProgress);
                statusLabel.setText("Scanning network packets... " + latestProgress + "%");
            }
        }

        @Override
        protected void done() {
            // Runs on the Event Dispatch Thread (EDT)
            startScanButton.setEnabled(true);
            cancelScanButton.setEnabled(false);

            if (isCancelled()) {
                scanProgressBar.setValue(0);
                statusLabel.setText("Scan cancelled by user.");
                JOptionPane.showMessageDialog(ThreatMonitorPanel.this,
                    "The simulated threat scan was cancelled.",
                    "Scan Cancelled", JOptionPane.WARNING_MESSAGE);
                return;
            }

            // Generate 1 to 3 random simulated threats
            Random random = new Random();
            int threatCount = 1 + random.nextInt(3);

            String[] types = {"Port Scan", "DDoS Burst", "Brute Force", "SQL Probe", "Malware Beacon"};
            String[] severities = {"MEDIUM", "HIGH", "CRITICAL"};
            String[] targets = {"Mail Server", "Web Server", "Database Server", "API Gateway"};

            for (int i = 0; i < threatCount; i++) {
                String type     = types[random.nextInt(types.length)];
                String severity = severities[random.nextInt(severities.length)];
                String target   = targets[random.nextInt(targets.length)];
                String ip       = "198.51.100." + (10 + random.nextInt(200));

                Threat newThreat = new Threat(type, ip, target, severity, "DETECTED");
                threatDAO.add(newThreat);
            }

            logDAO.add(new LogEntry(getUserId(),
                "Network scan completed: " + threatCount + " new threats detected"));

            scanProgressBar.setValue(100);
            statusLabel.setText("Scan complete. Detected " + threatCount + " new threats.");
            refreshData();

            JOptionPane.showMessageDialog(ThreatMonitorPanel.this,
                "Scan complete! Discovered " + threatCount + " new threats.",
                "Scan Finished", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    // ================================================================
    // 8. ACTIONS: STATUS UPDATE, IP BLOCKING, DELETE, EXPORT
    // ================================================================

    /** Updates status of currently selected threat. */
    private void updateSelectedThreatStatus(String newStatus) {
        if (selectedThreat == null) {
            JOptionPane.showMessageDialog(this,
                "Please select a threat first.", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }

        threatDAO.updateStatus(selectedThreat.getId(), newStatus);
        logDAO.add(new LogEntry(getUserId(),
            "Threat #" + selectedThreat.getId() + " status updated to " + newStatus));

        refreshData();
        JOptionPane.showMessageDialog(this,
            "Threat #" + selectedThreat.getId() + " status changed to " + newStatus + ".",
            "Status Updated", JOptionPane.INFORMATION_MESSAGE);
    }

    /** Blocks the source IP of the currently selected threat. */
    private void blockSelectedThreatIP() {
        if (selectedThreat == null) {
            JOptionPane.showMessageDialog(this,
                "Please select a threat first.", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String ip = selectedThreat.getSourceIp();
        if (blockedIPDAO.existsByIP(ip)) {
            JOptionPane.showMessageDialog(this,
                "IP " + ip + " is already blocked.",
                "Already Blocked", JOptionPane.WARNING_MESSAGE);
            return;
        }

        int confirm = JOptionPane.showConfirmDialog(this,
            "Are you sure you want to block IP: " + ip + "?",
            "Confirm Block IP", JOptionPane.YES_NO_OPTION);

        if (confirm == JOptionPane.YES_OPTION) {
            blockedIPDAO.add(new BlockedIP(ip, "Blocked via Threat #" + selectedThreat.getId()));
            logDAO.add(new LogEntry(getUserId(), "IP blocked: " + ip));
            loadBlockedIPs();
            JOptionPane.showMessageDialog(this,
                "IP " + ip + " blocked successfully.",
                "IP Blocked", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    /** Deletes the currently selected threat from the database. */
    private void deleteSelectedThreat() {
        if (selectedThreat == null) {
            JOptionPane.showMessageDialog(this,
                "Please select a threat first.", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }

        int confirm = JOptionPane.showConfirmDialog(this,
            "Are you sure you want to delete Threat #" + selectedThreat.getId() + "?",
            "Confirm Delete", JOptionPane.YES_NO_OPTION);

        if (confirm == JOptionPane.YES_OPTION) {
            threatDAO.delete(selectedThreat.getId());
            logDAO.add(new LogEntry(getUserId(), "Deleted Threat #" + selectedThreat.getId()));
            selectedThreat = null;
            clearDetailsPanel();
            refreshData();
            JOptionPane.showMessageDialog(this,
                "Threat deleted successfully.",
                "Threat Deleted", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    /** Opens modal AddThreatDialog. */
    private void openAddThreatDialog() {
        JFrame parent = (JFrame) SwingUtilities.getWindowAncestor(this);
        AddThreatDialog dialog = new AddThreatDialog(parent, getUserId());
        dialog.setVisible(true);
        if (dialog.isSaved()) {
            refreshData();
        }
    }

    /** Exports visible table rows to a CSV file. */
    private void exportVisibleRowsToCSV() {
        if (threatTable.getRowCount() == 0) {
            JOptionPane.showMessageDialog(this,
                "No rows to export.", "Empty Table", JOptionPane.WARNING_MESSAGE);
            return;
        }

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Export Visible Threats as CSV");
        fileChooser.setSelectedFile(new File("threats_export.csv"));
        fileChooser.setFileFilter(new FileNameExtensionFilter("CSV Files (*.csv)", "csv"));

        int result = fileChooser.showSaveDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            if (!file.getName().toLowerCase().endsWith(".csv")) {
                file = new File(file.getParentFile(), file.getName() + ".csv");
            }

            try (FileWriter writer = new FileWriter(file)) {
                // Write column headers
                for (int col = 0; col < threatTable.getColumnCount(); col++) {
                    writer.write(threatTable.getColumnName(col));
                    if (col < threatTable.getColumnCount() - 1) {
                        writer.write(",");
                    }
                }
                writer.write("\n");

                // Write visible rows
                for (int row = 0; row < threatTable.getRowCount(); row++) {
                    for (int col = 0; col < threatTable.getColumnCount(); col++) {
                        Object val = threatTable.getValueAt(row, col);
                        String str = (val != null) ? val.toString().replace(",", " ") : "";
                        writer.write(str);
                        if (col < threatTable.getColumnCount() - 1) {
                            writer.write(",");
                        }
                    }
                    writer.write("\n");
                }

                JOptionPane.showMessageDialog(this,
                    "Successfully exported " + threatTable.getRowCount() + " rows to:\n" + file.getAbsolutePath(),
                    "Export Successful", JOptionPane.INFORMATION_MESSAGE);

            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this,
                    "Error saving CSV file: " + ex.getMessage(),
                    "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    // ================================================================
    // 9. FILTERING LOGIC
    // ================================================================

    /** Applies search text, severity, status, and highlight filters to the table sorter. */
    private void applyTableFilters() {
        List<RowFilter<ThreatTableModel, Object>> filters = new ArrayList<>();

        // Text search across all columns
        String search = searchField.getText().trim();
        if (!search.isEmpty()) {
            filters.add(RowFilter.regexFilter("(?i)" + Pattern.quote(search)));
        }

        // Severity filter
        String severity = (String) severityCombo.getSelectedItem();
        if (criticalOnlyItem.isSelected()) {
            filters.add(RowFilter.regexFilter("^CRITICAL$", 4));
        } else if (severity != null && !severity.equals("ALL")) {
            filters.add(RowFilter.regexFilter("^" + severity + "$", 4));
        }

        // Status filter
        String status = (String) statusCombo.getSelectedItem();
        if (status != null && !status.equals("ALL")) {
            filters.add(RowFilter.regexFilter("^" + status + "$", 5));
        }

        // Combine all filters with AND logic
        if (filters.isEmpty()) {
            tableSorter.setRowFilter(null);
        } else {
            tableSorter.setRowFilter(RowFilter.andFilter(filters));
        }
    }

    /** Resets all filters back to default. */
    private void resetFilters() {
        searchField.setText("");
        severityCombo.setSelectedIndex(0);
        statusCombo.setSelectedIndex(0);
        criticalOnlyItem.setSelected(false);
        tableSorter.setRowFilter(null);
    }

    /** Clears the threat details panel. */
    private void clearDetailsPanel() {
        detailIdLabel.setText("—");
        detailTypeLabel.setText("—");
        detailIpLabel.setText("—");
        detailTargetLabel.setText("—");
        detailSeverityLabel.setText("—");
        detailStatusLabel.setText("—");
        detailDateLabel.setText("—");
        detailTextArea.setText("Select a threat from the table or network tree to inspect details.");
    }

    // ================================================================
    // 10. BASEPANEL CONTRACT: REFRESH DATA
    // ================================================================

    /** Reloads all threats and blocked IPs from MySQL and updates table and tree. */
    @Override
    public void refreshData() {
        int days = (Integer) daysSpinner.getValue();
        List<Threat> threats = threatDAO.getRecentThreats(days);

        // Fallback to getAll() if days filter returns empty
        if (threats.isEmpty()) {
            threats = threatDAO.getAll();
        }

        tableModel.setThreats(threats);
        rebuildNetworkTree(threats);
        loadBlockedIPs();

        statusLabel.setText("Loaded " + threats.size() + " threats from database.");
    }

    // ================================================================
    // 11. HELPER CLASSES & STYLING
    // ================================================================

    /** Numeric rank helper for severity comparison. */
    private int getSeverityRank(String s) {
        if (s == null) return 0;
        switch (s.toUpperCase().trim()) {
            case "CRITICAL": return 4;
            case "HIGH":     return 3;
            case "MEDIUM":   return 2;
            case "LOW":      return 1;
            default:         return 0;
        }
    }

    /** Wrapper object for JTree leaf nodes holding a Threat. */
    private static class ThreatNodeWrapper {
        private final Threat threat;

        public ThreatNodeWrapper(Threat threat) {
            this.threat = threat;
        }

        public Threat getThreat() {
            return threat;
        }

        @Override
        public String toString() {
            return threat.getThreatType() + " [" + threat.getSeverity() + "] (ID #" + threat.getId() + ")";
        }
    }

    /** Applies dark theme styling to a text field. */
    private void styleField(JTextField field) {
        field.setBackground(Theme.PANEL_BG);
        field.setForeground(Theme.TEXT_PRIMARY);
        field.setCaretColor(Theme.ACCENT);
        field.setFont(Theme.FONT_BODY);
        field.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Theme.ACCENT),
            BorderFactory.createEmptyBorder(2, 4, 2, 4)
        ));
    }

    /** Applies styling to a dropdown combo. */
    private void styleCombo(JComboBox<String> combo) {
        combo.setBackground(Theme.PANEL_BG);
        combo.setForeground(Theme.TEXT_PRIMARY);
        combo.setFont(Theme.FONT_BODY);
    }

    /** Helper for detail titles. */
    private JLabel makeDetailTitle(String title) {
        JLabel lbl = new JLabel(title);
        lbl.setFont(Theme.FONT_SMALL);
        lbl.setForeground(Theme.TEXT_SECONDARY);
        return lbl;
    }

    /** Helper for detail value labels. */
    private void styleDetailValue(JLabel lbl) {
        lbl.setFont(new Font("Segoe UI", Font.BOLD, 13));
        lbl.setForeground(Theme.TEXT_PRIMARY);
    }
}
