package com.cybershield.ui;

import java.awt.Color;
import java.awt.Font;
import javax.swing.BorderFactory;
import javax.swing.border.Border;

/**
 * Styling constants and palette for the CyberShield dark SOC aesthetic.
 */
public final class CyberTheme {

    // Palette Colors
    public static final Color BG_DARK = new Color(11, 17, 32);         // #0B1120 deep space dark
    public static final Color BG_SIDEBAR = new Color(15, 23, 42);      // #0F172A sidebar dark
    public static final Color BG_CARD = new Color(30, 41, 59);          // #1E293B card surface
    public static final Color BG_CARD_HOVER = new Color(51, 65, 85);    // #334155
    public static final Color BORDER_COLOR = new Color(51, 65, 85);     // #334155

    // Accent Colors (Customizable via JColorChooser)
    public static Color ACCENT_CYAN = new Color(6, 182, 212);     // #06B6D4
    public static Color ACCENT_BLUE = new Color(56, 189, 248);    // #38BDF8
    public static final Color STATUS_GREEN = new Color(16, 185, 129);   // #10B981
    public static final Color STATUS_AMBER = new Color(245, 158, 11);   // #F59E0B
    public static final Color STATUS_RED = new Color(239, 68, 68);      // #EF4444
    public static final Color STATUS_MUTED = new Color(100, 116, 139);  // #64748B

    // Text Colors
    public static final Color TEXT_PRIMARY = new Color(248, 250, 252);  // #F8FAFC
    public static final Color TEXT_MUTED = new Color(148, 163, 184);    // #94A3B8
    public static final Color TEXT_DARK = new Color(15, 23, 42);

    // Fonts
    public static final Font FONT_TITLE = new Font("Segoe UI", Font.BOLD, 18);
    public static final Font FONT_HEADER = new Font("Segoe UI", Font.BOLD, 14);
    public static final Font FONT_BODY = new Font("Segoe UI", Font.PLAIN, 12);
    public static final Font FONT_BODY_BOLD = new Font("Segoe UI", Font.BOLD, 12);
    public static final Font FONT_SMALL = new Font("Segoe UI", Font.PLAIN, 11);
    public static final Font FONT_MONO = new Font("Consolas", Font.PLAIN, 12);
    public static final Font FONT_MONO_BOLD = new Font("Consolas", Font.BOLD, 12);

    // Borders
    public static Border CARD_BORDER = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(BORDER_COLOR, 1),
            BorderFactory.createEmptyBorder(12, 12, 12, 12)
    );

    public static final Border INNER_PADDING = BorderFactory.createEmptyBorder(8, 8, 8, 8);

    public static void setAccentColor(Color newAccent) {
        if (newAccent != null) {
            ACCENT_CYAN = newAccent;
        }
    }

    private CyberTheme() {}
}
