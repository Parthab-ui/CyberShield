package cybershield.util;

import java.awt.Color;
import java.awt.Font;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JPanel;

/**
 * Theme — Holds all color, font, and styling constants for a consistent dark UI.
 * Call the static methods to apply the theme to buttons and panels.
 */
public class Theme {

    // -------- COLORS --------
    public static final Color BACKGROUND     = new Color(18, 18, 40);      // Dark navy
    public static final Color PANEL_BG       = new Color(26, 26, 58);      // Slightly lighter navy
    public static final Color ACCENT         = new Color(0, 200, 220);     // Cyan accent
    public static final Color TEXT_PRIMARY   = new Color(230, 230, 230);   // Light grey text
    public static final Color TEXT_SECONDARY = new Color(150, 150, 170);   // Muted grey text
    public static final Color CRITICAL       = new Color(220, 50, 50);     // Red for critical
    public static final Color WARNING        = new Color(255, 165, 0);     // Orange for warnings
    public static final Color SUCCESS        = new Color(50, 200, 80);     // Green for resolved
    public static final Color TABLE_ROW_ALT  = new Color(30, 30, 65);     // Alternate row color

    // -------- FONTS --------
    public static final Font FONT_TITLE   = new Font("Segoe UI", Font.BOLD, 22);
    public static final Font FONT_HEADING = new Font("Segoe UI", Font.BOLD, 16);
    public static final Font FONT_BODY    = new Font("Segoe UI", Font.PLAIN, 14);
    public static final Font FONT_SMALL   = new Font("Segoe UI", Font.PLAIN, 12);

    // Private constructor — this class should not be instantiated
    private Theme() { }

    /**
     * Applies the dark theme colors and font to a JButton.
     */
    public static void styleButton(JButton button) {
        button.setBackground(ACCENT);
        button.setForeground(Color.BLACK);
        button.setFont(FONT_BODY);
        button.setFocusPainted(false);
        button.setBorderPainted(false);
        button.setOpaque(true);
    }

    /**
     * Applies the dark background and text color to a JPanel.
     */
    public static void stylePanel(JPanel panel) {
        panel.setBackground(PANEL_BG);
        panel.setForeground(TEXT_PRIMARY);
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
    }
}
