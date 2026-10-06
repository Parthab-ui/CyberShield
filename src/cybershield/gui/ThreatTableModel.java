package cybershield.gui;

import cybershield.model.Threat;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import javax.swing.table.AbstractTableModel;

/**
 * ThreatTableModel — Custom TableModel for displaying Threat objects in a JTable.
 * Demonstrates the MODEL part of MVC in Swing: decouples data storage from table rendering.
 * Extends AbstractTableModel and provides column metadata, row counts, and cell values.
 */
public class ThreatTableModel extends AbstractTableModel {

    // Column names displayed in the JTable header
    private static final String[] COLUMN_NAMES = {
        "ID", "Type", "Source IP", "Target", "Severity", "Status", "Detected At"
    };

    // Column data types used by TableRowSorter for appropriate comparisons
    private static final Class<?>[] COLUMN_CLASSES = {
        Integer.class, String.class, String.class, String.class, String.class, String.class, Timestamp.class
    };

    // The in-memory list of threats backing this table
    private List<Threat> threats;

    // Constructor — initializes with an empty list
    public ThreatTableModel() {
        this.threats = new ArrayList<>();
    }

    // Constructor — initializes with an existing list of threats
    public ThreatTableModel(List<Threat> threats) {
        this.threats = (threats != null) ? new ArrayList<>(threats) : new ArrayList<>();
    }

    /** Returns the total number of rows (threat records). */
    @Override
    public int getRowCount() {
        return threats.size();
    }

    /** Returns the total number of columns (7). */
    @Override
    public int getColumnCount() {
        return COLUMN_NAMES.length;
    }

    /** Returns the header title for the given column index. */
    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }

    /** Returns the data class for the given column (used for sorting and alignment). */
    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return COLUMN_CLASSES[columnIndex];
    }

    /** Returns false so that table cells cannot be edited directly by double-clicking. */
    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }

    /** Returns the value to display at the specified row and column. */
    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= threats.size()) {
            return null;
        }

        Threat threat = threats.get(rowIndex);
        switch (columnIndex) {
            case 0: return threat.getId();
            case 1: return threat.getThreatType();
            case 2: return threat.getSourceIp();
            case 3: return threat.getTargetSystem();
            case 4: return threat.getSeverity();
            case 5: return threat.getStatus();
            case 6: return threat.getDetectedAt();
            default: return null;
        }
    }

    /** Replaces the entire list of threats and notifies the JTable to redraw. */
    public void setThreats(List<Threat> newThreats) {
        this.threats = (newThreats != null) ? new ArrayList<>(newThreats) : new ArrayList<>();
        fireTableDataChanged(); // Notify all attached listeners (JTable, sorter)
    }

    /** Returns the Threat object at a specific model row index. */
    public Threat getThreatAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < threats.size()) {
            return threats.get(rowIndex);
        }
        return null;
    }

    /** Returns a shallow copy of the current list of threats. */
    public List<Threat> getThreats() {
        return new ArrayList<>(threats);
    }

    /** Removes a threat at the specified row index and notifies the table. */
    public void removeThreatAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < threats.size()) {
            threats.remove(rowIndex);
            fireTableRowsDeleted(rowIndex, rowIndex);
        }
    }
}
