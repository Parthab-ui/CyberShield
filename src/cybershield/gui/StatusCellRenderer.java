package cybershield.gui;

import cybershield.util.Theme;

import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.table.DefaultTableCellRenderer;

/**
 * StatusCellRenderer — Formats and colors Priority and Status values in JTables.
 * Customizes cell rendering:
 * - Status: OPEN (Red), IN_PROGRESS (Orange), CLOSED (Green)
 * - Priority: CRITICAL (Red), HIGH (Orange), MEDIUM (Yellow), LOW (Green)
 */
public class StatusCellRenderer extends DefaultTableCellRenderer {

    private static final Color COLOR_RED    = new Color(230, 50, 50);
    private static final Color COLOR_ORANGE = new Color(255, 140, 0);
    private static final Color COLOR_YELLOW = new Color(240, 200, 50);
    private static final Color COLOR_GREEN  = new Color(50, 200, 80);

    // Constructor — sets center alignment and bold typography
    public StatusCellRenderer() {
        setHorizontalAlignment(SwingConstants.CENTER);
        setFont(new Font("Segoe UI", Font.BOLD, 12));
    }

    /** Configures label background, foreground color, and text for cell rendering. */
    @Override
    public Component getTableCellRendererComponent(JTable table, Object value,
                                                   boolean isSelected, boolean hasFocus,
                                                   int row, int column) {
        super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        if (value != null) {
            String text = value.toString().toUpperCase().trim();
            setText(text);

            Color fgColor = Theme.TEXT_PRIMARY;
            switch (text) {
                case "OPEN":
                case "CRITICAL":
                    fgColor = COLOR_RED;
                    break;
                case "IN_PROGRESS":
                case "HIGH":
                    fgColor = COLOR_ORANGE;
                    break;
                case "MEDIUM":
                    fgColor = COLOR_YELLOW;
                    break;
                case "CLOSED":
                case "LOW":
                    fgColor = COLOR_GREEN;
                    break;
                default:
                    fgColor = Theme.TEXT_PRIMARY;
                    break;
            }

            if (isSelected) {
                setBackground(Theme.ACCENT.darker().darker());
                setForeground(fgColor);
            } else {
                setBackground(row % 2 == 0 ? Theme.PANEL_BG : Theme.TABLE_ROW_ALT);
                setForeground(fgColor);
            }
        }

        return this;
    }
}
