package cybershield.ui;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.border.Border;
import javax.swing.table.JTableHeader;

/**
 * SwingTheme — Central design system providing the dark navy cybersecurity aesthetic,
 * typography, component borders, and color palettes across the entire Swing application.
 * Demonstrates: Reusable styling constants, custom painters, and consistent UI design.
 */
public class SwingTheme {

    // Primary Background & Surface Colors
    public static final Color BG_DARK        = new Color(11, 17, 32);     // #0b1120 Deep navy
    public static final Color BG_COLOR       = BG_DARK;                   // Alias for background
    public static final Color PANEL_BG       = new Color(21, 30, 50);     // #151e32 Card background
    public static final Color CARD_BG        = new Color(30, 41, 59);     // #1e293b Input/secondary card
    public static final Color BORDER_COLOR   = new Color(51, 65, 85);     // #334155 Subtle border
    public static final Color BORDER_ACTIVE  = new Color(56, 189, 248);    // #38bdf8 Focus border

    // Text Colors
    public static final Color TEXT_PRIMARY   = new Color(248, 250, 252);  // #f8fafc Crisp white text
    public static final Color TEXT_SECONDARY = new Color(148, 163, 184);  // #94a3b8 Muted subtitle
    public static final Color TEXT_MUTED     = new Color(100, 116, 139);  // #64748b Caption text

    // Accent Colors
    public static final Color ACCENT_BLUE    = new Color(2, 132, 199);    // #0284c7 Primary action
    public static final Color PRIMARY_COLOR  = ACCENT_BLUE;               // Alias for primary
    public static final Color ACCENT_CYAN    = new Color(56, 189, 248);   // #38bdf8 Highlight cyan

    // Severity Colors
    public static final Color SEV_CRITICAL       = new Color(239, 68, 68);    // Red
    public static final Color SEVERITY_CRITICAL   = SEV_CRITICAL;
    public static final Color SEV_HIGH           = new Color(249, 115, 22);   // Orange
    public static final Color SEVERITY_HIGH       = SEV_HIGH;
    public static final Color SEV_MEDIUM         = new Color(234, 179, 8);    // Yellow
    public static final Color SEVERITY_MEDIUM     = SEV_MEDIUM;
    public static final Color SEV_LOW            = new Color(34, 197, 94);    // Green
    public static final Color SEVERITY_LOW        = SEV_LOW;

    // Status Colors
    public static final Color STATUS_OPEN          = new Color(59, 130, 246);   // Blue
    public static final Color STATUS_INVESTIGATING = new Color(168, 85, 247);   // Purple
    public static final Color STATUS_IN_PROGRESS   = STATUS_INVESTIGATING;       // Backward-compatible alias
    public static final Color STATUS_RESOLVED      = new Color(34, 197, 94);    // Green
    public static final Color STATUS_CLOSED        = new Color(100, 116, 139);  // Slate Gray

    // Typography
    public static final Font FONT_TITLE   = new Font("Segoe UI", Font.BOLD, 18);
    public static final Font FONT_HEADER  = new Font("Segoe UI", Font.BOLD, 14);
    public static final Font FONT_REGULAR = new Font("Segoe UI", Font.PLAIN, 13);
    public static final Font FONT_BODY    = FONT_REGULAR;
    public static final Font FONT_BOLD    = new Font("Segoe UI", Font.BOLD, 13);
    public static final Font FONT_SMALL   = new Font("Segoe UI", Font.PLAIN, 11);
    public static final Font FONT_MONO    = new Font("Consolas", Font.PLAIN, 12);

    private SwingTheme() {
        // Utility class
    }

    /** Styles a standard action button with theme colors. */
    public static void styleButton(JButton button, Color bg, Color fg) {
        button.setBackground(bg);
        button.setForeground(fg);
        button.setFont(FONT_BOLD);
        button.setFocusPainted(false);
        button.setBorder(BorderFactory.createEmptyBorder(8, 16, 8, 16));
        button.setOpaque(true);
    }

    /** Styles a primary theme button. */
    public static void stylePrimaryButton(JButton button) {
        styleButton(button, ACCENT_BLUE, Color.WHITE);
    }

    /** Styles a secondary theme button. */
    public static void styleSecondaryButton(JButton button) {
        styleButton(button, CARD_BG, TEXT_PRIMARY);
    }

    /** Styles an input text field. */
    public static void styleTextField(JTextField field) {
        field.setBackground(CARD_BG);
        field.setForeground(TEXT_PRIMARY);
        field.setCaretColor(ACCENT_CYAN);
        field.setFont(FONT_REGULAR);
        field.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(BORDER_COLOR, 1),
            BorderFactory.createEmptyBorder(6, 10, 6, 10)
        ));
    }

    /** Styles a password field. */
    public static void stylePasswordField(JPasswordField field) {
        field.setBackground(CARD_BG);
        field.setForeground(TEXT_PRIMARY);
        field.setCaretColor(ACCENT_CYAN);
        field.setFont(FONT_REGULAR);
        field.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(BORDER_COLOR, 1),
            BorderFactory.createEmptyBorder(6, 10, 6, 10)
        ));
    }

    /** Styles a combo box dropdown. */
    public static void styleComboBox(JComboBox<?> box) {
        box.setBackground(CARD_BG);
        box.setForeground(TEXT_PRIMARY);
        box.setFont(FONT_REGULAR);
        box.setBorder(BorderFactory.createLineBorder(BORDER_COLOR, 1));
    }

    /** Styles a checkbox. */
    public static void styleCheckBox(JCheckBox chk) {
        chk.setOpaque(false);
        chk.setForeground(TEXT_PRIMARY);
        chk.setFont(FONT_REGULAR);
        chk.setFocusPainted(false);
    }

    /** Styles a radio button. */
    public static void styleRadioButton(JRadioButton rb) {
        rb.setOpaque(false);
        rb.setForeground(TEXT_PRIMARY);
        rb.setFont(FONT_REGULAR);
        rb.setFocusPainted(false);
    }

    /** Returns color for given severity string. */
    public static Color getSeverityColor(String severity) {
        if (severity == null) return SEVERITY_LOW;
        switch (severity.toUpperCase()) {
            case "CRITICAL": return SEVERITY_CRITICAL;
            case "HIGH": return SEVERITY_HIGH;
            case "MEDIUM": return SEVERITY_MEDIUM;
            case "LOW":
            default: return SEVERITY_LOW;
        }
    }

    /** Returns color for given status string. */
    public static Color getStatusColor(String status) {
        if (status == null) return STATUS_OPEN;
        switch (status.toUpperCase()) {
            case "OPEN": return STATUS_OPEN;
            case "IN_PROGRESS":
            case "INVESTIGATING": return STATUS_IN_PROGRESS;
            case "RESOLVED": return STATUS_RESOLVED;
            case "CLOSED":
            default: return STATUS_CLOSED;
        }
    }

    /** Applies dark theme styling and headers to a JTable. */
    public static void styleTable(JTable table) {
        table.setBackground(PANEL_BG);
        table.setForeground(TEXT_PRIMARY);
        table.setGridColor(BORDER_COLOR);
        table.setFont(FONT_REGULAR);
        table.setRowHeight(28);
        table.setSelectionBackground(new Color(2, 132, 199, 120));
        table.setSelectionForeground(Color.WHITE);

        JTableHeader header = table.getTableHeader();
        header.setBackground(CARD_BG);
        header.setForeground(TEXT_PRIMARY);
        header.setFont(FONT_BOLD);
        header.setPreferredSize(new Dimension(0, 32));
        header.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, BORDER_COLOR));
    }

    /** Creates a rounded card border. */
    public static Border createCardBorder() {
        return BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(BORDER_COLOR, 1),
            BorderFactory.createEmptyBorder(12, 16, 12, 16)
        );
    }
}
