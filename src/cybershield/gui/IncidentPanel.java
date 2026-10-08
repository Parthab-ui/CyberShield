package cybershield.gui;

import cybershield.dao.IncidentDAO;
import cybershield.dao.LogDAO;
import cybershield.model.Incident;
import cybershield.model.LogEntry;
import cybershield.model.User;
import cybershield.util.Theme;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableRowSorter;

/**
 * IncidentPanel — Incident Response management interface for CyberShield.
 * Demonstrates: JTable, custom IncidentTableModel, TableRowSorter, RowFilter,
 * custom StatusCellRenderer, double-click mouse events, and JPopupMenu actions.
 */
public class IncidentPanel extends BasePanel {

    private IncidentDAO incidentDAO;
    private LogDAO      logDAO;
    private User        currentUser;

    // Table components
    private JTable                            incidentTable;
    private IncidentTableModel                tableModel;
    private TableRowSorter<IncidentTableModel> tableSorter;
    private JPopupMenu                        tablePopupMenu;

    // Filter controls
    private JTextField        searchField;
    private JComboBox<String> statusFilterCombo;
    private JButton           newButton;
    private JButton           editButton;
    private JButton           closeButton;
    private JButton           refreshButton;

    // Details description area
    private JTextArea   descriptionArea;
    private JLabel      detailsHeaderLabel;
    private Incident    selectedIncident;

    // Constructor — builds the Incident Response interface
    public IncidentPanel() {
        this.incidentDAO = new IncidentDAO();
        this.logDAO      = new LogDAO();

        setBackground(Theme.BACKGROUND);
        setLayout(new BorderLayout(0, 8));
        setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        add(createToolBar(), BorderLayout.NORTH);
        add(createCenterTablePanel(), BorderLayout.CENTER);
        add(createDetailsPanel(), BorderLayout.SOUTH);

        refreshData();
    }

    /** Sets the logged-in user for audit logging and assignment actions. */
    public void setCurrentUser(User user) {
        this.currentUser = user;
    }

    /** Returns current user ID or 1. */
    private int getUserId() {
        return (currentUser != null) ? currentUser.getId() : 1;
    }

    // ================================================================
    // NORTH: TOOLBAR
    // ================================================================

    /** Creates top action toolbar with filter inputs and buttons. */
    private JPanel createToolBar() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        bar.setBackground(Theme.PANEL_BG);
        bar.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Theme.ACCENT, 1),
            BorderFactory.createEmptyBorder(4, 6, 4, 6)
        ));

        newButton = new JButton("+ New Incident");
        Theme.styleButton(newButton);
        newButton.setMnemonic(KeyEvent.VK_N);
        newButton.setToolTipText("Create a new incident report (Alt+N)");

        editButton = new JButton("Edit");
        Theme.styleButton(editButton);
        editButton.setBackground(Theme.PANEL_BG);
        editButton.setForeground(Theme.TEXT_PRIMARY);
        editButton.setToolTipText("Edit selected incident");

        closeButton = new JButton("Close Incident");
        Theme.styleButton(closeButton);
        closeButton.setBackground(Theme.SUCCESS);
        closeButton.setForeground(Color.BLACK);
        closeButton.setToolTipText("Mark selected incident as CLOSED");

        refreshButton = new JButton("⟳ Refresh");
        Theme.styleButton(refreshButton);
        refreshButton.setToolTipText("Reload incidents from database");

        // Search text box
        JLabel searchLbl = new JLabel("Search:");
        searchLbl.setFont(Theme.FONT_SMALL);
        searchLbl.setForeground(Theme.TEXT_SECONDARY);
        searchField = new JTextField(12);
        styleField(searchField);
        searchField.setToolTipText("Search by title, description or priority");

        // Status filter
        JLabel statLbl = new JLabel("Status:");
        statLbl.setFont(Theme.FONT_SMALL);
        statLbl.setForeground(Theme.TEXT_SECONDARY);
        statusFilterCombo = new JComboBox<>(new String[]{"ALL", "OPEN", "IN_PROGRESS", "CLOSED"});
        statusFilterCombo.setBackground(Theme.PANEL_BG);
        statusFilterCombo.setForeground(Theme.TEXT_PRIMARY);
        statusFilterCombo.setFont(Theme.FONT_BODY);

        // Listeners
        newButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                openIncidentDialog(null);
            }
        });

        editButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (selectedIncident != null) {
                    openIncidentDialog(selectedIncident);
                } else {
                    JOptionPane.showMessageDialog(IncidentPanel.this,
                        "Please select an incident to edit.", "No Selection", JOptionPane.WARNING_MESSAGE);
                }
            }
        });

        closeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                closeSelectedIncident();
            }
        });

        refreshButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                refreshData();
            }
        });

        searchField.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                applyFilters();
            }
        });

        statusFilterCombo.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                applyFilters();
            }
        });

        bar.add(newButton);
        bar.add(editButton);
        bar.add(closeButton);
        bar.add(refreshButton);
        bar.add(new JSeparator(SwingConstants.VERTICAL));
        bar.add(searchLbl);
        bar.add(searchField);
        bar.add(statLbl);
        bar.add(statusFilterCombo);

        return bar;
    }

    // ================================================================
    // CENTER: TABLE PANEL
    // ================================================================

    /** Creates JTable with custom model, sorter, and renderers. */
    private JPanel createCenterTablePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(Theme.PANEL_BG);

        tableModel    = new IncidentTableModel();
        incidentTable = new JTable(tableModel);

        incidentTable.setBackground(Theme.PANEL_BG);
        incidentTable.setForeground(Theme.TEXT_PRIMARY);
        incidentTable.setFont(Theme.FONT_BODY);
        incidentTable.setRowHeight(24);
        incidentTable.setGridColor(new Color(50, 50, 80));
        incidentTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        incidentTable.setSelectionBackground(Theme.ACCENT.darker().darker());
        incidentTable.setSelectionForeground(Theme.TEXT_PRIMARY);
        incidentTable.getTableHeader().setBackground(new Color(35, 35, 75));
        incidentTable.getTableHeader().setForeground(Theme.ACCENT);
        incidentTable.getTableHeader().setFont(new Font("Segoe UI", Font.BOLD, 13));

        // Format Priority (column 3) and Status (column 4) with StatusCellRenderer
        StatusCellRenderer statusRenderer = new StatusCellRenderer();
        incidentTable.getColumnModel().getColumn(3).setCellRenderer(statusRenderer);
        incidentTable.getColumnModel().getColumn(4).setCellRenderer(statusRenderer);

        // TableRowSorter
        tableSorter = new TableRowSorter<>(tableModel);
        incidentTable.setRowSorter(tableSorter);

        // Row selection listener: update description area
        incidentTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) {
                    int viewRow = incidentTable.getSelectedRow();
                    if (viewRow != -1) {
                        int modelRow = incidentTable.convertRowIndexToModel(viewRow);
                        selectedIncident = tableModel.getIncidentAt(modelRow);
                        displayIncidentDetails(selectedIncident);
                    }
                }
            }
        });

        // Context popup menu
        createPopupMenu();

        // Mouse listener: double-click to edit, right-click for popup menu
        incidentTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
                    int viewRow = incidentTable.getSelectedRow();
                    if (viewRow != -1) {
                        int modelRow = incidentTable.convertRowIndexToModel(viewRow);
                        openIncidentDialog(tableModel.getIncidentAt(modelRow));
                    }
                }
            }

            @Override
            public void mousePressed(MouseEvent e) {
                handlePopupTrigger(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                handlePopupTrigger(e);
            }
        });

        JScrollPane scroll = new JScrollPane(incidentTable);
        scroll.getViewport().setBackground(Theme.PANEL_BG);
        scroll.setBorder(BorderFactory.createLineBorder(new Color(40, 40, 70)));
        panel.add(scroll, BorderLayout.CENTER);

        return panel;
    }

    /** Creates right-click context menu. */
    private void createPopupMenu() {
        tablePopupMenu = new JPopupMenu();
        tablePopupMenu.setBackground(Theme.PANEL_BG);

        JMenuItem assignItem = new JMenuItem("Assign to Me");
        JMenuItem inProgItem = new JMenuItem("Mark In Progress");
        JMenuItem closeItem  = new JMenuItem("Close Incident");

        styleMenuItem(assignItem);
        styleMenuItem(inProgItem);
        styleMenuItem(closeItem);

        assignItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (selectedIncident != null) {
                    incidentDAO.assignTo(selectedIncident.getId(), getUserId());
                    logDAO.add(new LogEntry(getUserId(),
                        "Assigned Incident #" + selectedIncident.getId() + " to current user"));
                    refreshData();
                }
            }
        });

        inProgItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (selectedIncident != null) {
                    incidentDAO.updateStatus(selectedIncident.getId(), "IN_PROGRESS");
                    logDAO.add(new LogEntry(getUserId(),
                        "Marked Incident #" + selectedIncident.getId() + " as IN_PROGRESS"));
                    refreshData();
                }
            }
        });

        closeItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                closeSelectedIncident();
            }
        });

        tablePopupMenu.add(assignItem);
        tablePopupMenu.add(inProgItem);
        tablePopupMenu.add(closeItem);
    }

    /** Handles right click popup trigger. */
    private void handlePopupTrigger(MouseEvent e) {
        if (e.isPopupTrigger()) {
            int row = incidentTable.rowAtPoint(e.getPoint());
            if (row != -1) {
                incidentTable.setRowSelectionInterval(row, row);
                int modelRow = incidentTable.convertRowIndexToModel(row);
                selectedIncident = tableModel.getIncidentAt(modelRow);
                displayIncidentDetails(selectedIncident);
            }
            tablePopupMenu.show(e.getComponent(), e.getX(), e.getY());
        }
    }

    // ================================================================
    // SOUTH: DETAILS PANEL
    // ================================================================

    /** Creates bottom details area showing description of selected incident. */
    private JPanel createDetailsPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 4));
        panel.setBackground(Theme.PANEL_BG);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Theme.ACCENT, 1),
            BorderFactory.createEmptyBorder(6, 10, 8, 10)
        ));

        detailsHeaderLabel = new JLabel("Incident Details & Remediation Notes");
        detailsHeaderLabel.setFont(Theme.FONT_HEADING);
        detailsHeaderLabel.setForeground(Theme.ACCENT);

        descriptionArea = new JTextArea(3, 30);
        descriptionArea.setEditable(false);
        descriptionArea.setLineWrap(true);
        descriptionArea.setWrapStyleWord(true);
        descriptionArea.setBackground(new Color(20, 20, 48));
        descriptionArea.setForeground(Theme.TEXT_SECONDARY);
        descriptionArea.setFont(Theme.FONT_BODY);
        descriptionArea.setText("Select an incident to view investigation notes and actions.");

        JScrollPane descScroll = new JScrollPane(descriptionArea);
        descScroll.setBorder(BorderFactory.createEmptyBorder());

        panel.add(detailsHeaderLabel, BorderLayout.NORTH);
        panel.add(descScroll, BorderLayout.CENTER);

        return panel;
    }

    /** Displays the details and notes for the selected incident. */
    private void displayIncidentDetails(Incident inc) {
        if (inc == null) return;
        detailsHeaderLabel.setText("Incident #" + inc.getId() + " — " + inc.getTitle()
            + " [" + inc.getPriority() + " / " + inc.getStatus() + "]");
        descriptionArea.setText(inc.getDescription());
    }

    // ================================================================
    // LOGIC & ACTIONS
    // ================================================================

    /** Opens IncidentDialog for new or edit mode. */
    private void openIncidentDialog(Incident inc) {
        JFrame parent = (JFrame) SwingUtilities.getWindowAncestor(this);
        IncidentDialog dialog = new IncidentDialog(parent, getUserId(), inc);
        dialog.setVisible(true);
        if (dialog.isSaved()) {
            refreshData();
        }
    }

    /** Closes the selected incident with confirmation. */
    private void closeSelectedIncident() {
        if (selectedIncident == null) {
            JOptionPane.showMessageDialog(this,
                "Please select an incident to close.", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }

        int confirm = JOptionPane.showConfirmDialog(this,
            "Are you sure you want to mark Incident #" + selectedIncident.getId() + " as CLOSED?",
            "Confirm Close", JOptionPane.YES_NO_OPTION);

        if (confirm == JOptionPane.YES_OPTION) {
            incidentDAO.closeIncident(selectedIncident.getId());
            logDAO.add(new LogEntry(getUserId(), "Closed Incident #" + selectedIncident.getId()));
            refreshData();
            JOptionPane.showMessageDialog(this,
                "Incident #" + selectedIncident.getId() + " closed successfully.",
                "Incident Closed", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    /** Applies search text and status filters. */
    private void applyFilters() {
        List<RowFilter<IncidentTableModel, Object>> filters = new ArrayList<>();

        String search = searchField.getText().trim();
        if (!search.isEmpty()) {
            filters.add(RowFilter.regexFilter("(?i)" + Pattern.quote(search)));
        }

        String status = (String) statusFilterCombo.getSelectedItem();
        if (status != null && !status.equals("ALL")) {
            filters.add(RowFilter.regexFilter("^" + status + "$", 4)); // column 4 = Status
        }

        if (filters.isEmpty()) {
            tableSorter.setRowFilter(null);
        } else {
            tableSorter.setRowFilter(RowFilter.andFilter(filters));
        }
    }

    /** Reloads all incidents from database. */
    @Override
    public void refreshData() {
        List<Incident> list = incidentDAO.getAll();
        tableModel.setIncidents(list);
    }

    // ================================================================
    // STYLING HELPERS
    // ================================================================

    private void styleField(JTextField f) {
        f.setBackground(Theme.PANEL_BG);
        f.setForeground(Theme.TEXT_PRIMARY);
        f.setCaretColor(Theme.ACCENT);
        f.setFont(Theme.FONT_BODY);
        f.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Theme.ACCENT),
            BorderFactory.createEmptyBorder(2, 4, 2, 4)
        ));
    }

    private void styleMenuItem(JMenuItem item) {
        item.setBackground(Theme.PANEL_BG);
        item.setForeground(Theme.TEXT_PRIMARY);
        item.setFont(Theme.FONT_BODY);
    }
}
