package cybershield.gui;

import cybershield.dao.UserDAO;
import cybershield.model.Incident;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.table.AbstractTableModel;

/**
 * IncidentTableModel — Custom TableModel for displaying Incident entities in a JTable.
 * Demonstrates the MODEL in MVC architecture: isolates incident records from table UI rendering.
 * Provides column names, data types, and row cell mapping.
 */
public class IncidentTableModel extends AbstractTableModel {

    // Column titles displayed in the JTable header
    private static final String[] COLUMN_NAMES = {
        "ID", "Title", "Threat ID", "Priority", "Status", "Assigned To", "Created At"
    };

    // Column data classes for sorting
    private static final Class<?>[] COLUMN_CLASSES = {
        Integer.class, String.class, Integer.class, String.class, String.class, String.class, Timestamp.class
    };

    private List<Incident> incidents;
    private UserDAO userDAO;
    private Map<Integer, String> usernameCache;

    // Constructor — initializes empty model
    public IncidentTableModel() {
        this.incidents = new ArrayList<>();
        this.userDAO = new UserDAO();
        this.usernameCache = new HashMap<>();
    }

    // Constructor — initializes with an initial list
    public IncidentTableModel(List<Incident> incidents) {
        this();
        setIncidents(incidents);
    }

    /** Returns the total number of incident rows. */
    @Override
    public int getRowCount() {
        return incidents.size();
    }

    /** Returns the column count (7). */
    @Override
    public int getColumnCount() {
        return COLUMN_NAMES.length;
    }

    /** Returns the title of the column at columnIndex. */
    @Override
    public String getColumnName(int columnIndex) {
        return COLUMN_NAMES[columnIndex];
    }

    /** Returns the Java class for column values. */
    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return COLUMN_CLASSES[columnIndex];
    }

    /** Disallows in-place cell editing so updates go through the edit dialog. */
    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }

    /** Returns the data value for a cell at (rowIndex, columnIndex). */
    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= incidents.size()) {
            return null;
        }

        Incident inc = incidents.get(rowIndex);
        switch (columnIndex) {
            case 0: return inc.getId();
            case 1: return inc.getTitle();
            case 2: return inc.getThreatId();
            case 3: return inc.getPriority();
            case 4: return inc.getStatus();
            case 5:
                int uid = inc.getAssignedTo();
                if (!usernameCache.containsKey(uid)) {
                    usernameCache.put(uid, userDAO.getUsernameById(uid));
                }
                return usernameCache.get(uid);
            case 6: return inc.getCreatedAt();
            default: return null;
        }
    }

    /** Replaces the incidents list and notifies attached listeners to repaint. */
    public void setIncidents(List<Incident> newIncidents) {
        this.incidents = (newIncidents != null) ? new ArrayList<>(newIncidents) : new ArrayList<>();
        fireTableDataChanged();
    }

    /** Returns the Incident object located at a specific model row index. */
    public Incident getIncidentAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < incidents.size()) {
            return incidents.get(rowIndex);
        }
        return null;
    }

    /** Returns a shallow copy of the current incidents list. */
    public List<Incident> getIncidents() {
        return new ArrayList<>(incidents);
    }
}
