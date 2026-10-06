package cybershield.gui;

import cybershield.util.Theme;

import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.table.DefaultTableCellRenderer;

/**
 * SeverityCellRenderer — Custom cell renderer that highlights threat severity levels with distinct colors.
 * Demonstrates the VIEW rendering customization in Swing: overrides getTableCellRendererComponent.
 * Colors: LOW -> Green, MEDIUM -> Yellow, HIGH -> Orange, CRITICAL -> Red.
 */
public class SeverityCellRenderer extends DefaultTableCellRenderer {

    // Severity colors
    private static final Color COLOR_LOW      = new Color(50, 200, 80);   // Green
    private static final Color COLOR_MEDIUM   = new Color(240, 200, 50);  // Yellow
    private static final Color COLOR_HIGH     = new Color(255, 140, 0);   // Orange
    private static final Color COLOR_CRITICAL = new Color(230, 50, 50);   // Red

    // Constructor — sets center alignment and bold font
    public SeverityCellRenderer() {
        setHorizontalAlignment(SwingConstants.CENTER);
        setFont(new Font("Segoe UI", Font.BOLD, 12));
    }

    /**
     * Configures the rendering component (this JLabel) before Swing draws the cell.
     * Sets font color according to the severity value ("LOW", "MEDIUM", "HIGH", "CRITICAL").
     */
    @Override
    public Component getTableCellRendererComponent(JTable table, Object value,
                                                   boolean isSelected, boolean hasFocus,
                                                   int row, int column) {
        // Delegate default selection, text, and border setup to superclass
        super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        if (value != null) {
            String severity = value.toString().toUpperCase().trim();
            setText(severity);

            if (isSelected) {
                // Keep the selection highlight background, but use bold colored text
                setBackground(Theme.ACCENT.darker().darker());
                switch (severity) {
                    case "LOW":      setForeground(COLOR_LOW); break;
                    case "MEDIUM":   setForeground(COLOR_MEDIUM); break;
                    case "HIGH":     setForeground(COLOR_HIGH); break;
                    case "CRITICAL": setForeground(COLOR_CRITICAL); break;
                    default:         setForeground(Theme.TEXT_PRIMARY); break;
                }
            } else {
                // Apply alternate row dark background
                setBackground(row % 2 == 0 ? Theme.PANEL_BG : Theme.TABLE_ROW_ALT);

                switch (severity) {
                    case "LOW":      setForeground(COLOR_LOW); break;
                    case "MEDIUM":   setForeground(COLOR_MEDIUM); break;
                    case "HIGH":     setForeground(COLOR_HIGH); break;
                    case "CRITICAL": setForeground(COLOR_CRITICAL); break;
                    default:         setForeground(Theme.TEXT_PRIMARY); break;
                }
            }
        }

        return this;
    }
}
