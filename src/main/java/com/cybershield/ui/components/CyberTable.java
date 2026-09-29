package com.cybershield.ui.components;

import com.cybershield.ui.CyberTheme;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;

/**
 * Custom dark-themed JTable component with customized headers, row heights, and badge rendering.
 */
public class CyberTable extends JTable {

    private static final Color ROW_ALT_COLOR = new Color(23, 32, 51);
    private static final Color SELECTION_COLOR = new Color(51, 65, 85);

    public CyberTable(DefaultTableModel model) {
        super(model);
        configureTable();
    }

    private void configureTable() {
        setBackground(CyberTheme.BG_CARD);
        setForeground(CyberTheme.TEXT_PRIMARY);
        setSelectionBackground(SELECTION_COLOR);
        setSelectionForeground(CyberTheme.TEXT_PRIMARY);
        setGridColor(CyberTheme.BORDER_COLOR);
        setShowGrid(true);
        setShowVerticalLines(false);
        setRowHeight(32);
        setFont(CyberTheme.FONT_BODY);

        // Header Styling
        JTableHeader header = getTableHeader();
        header.setBackground(CyberTheme.BG_SIDEBAR);
        header.setForeground(CyberTheme.TEXT_MUTED);
        header.setFont(CyberTheme.FONT_BODY_BOLD);
        header.setPreferredSize(new Dimension(header.getWidth(), 36));
        header.setReorderingAllowed(false);

        header.setDefaultRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                JLabel lbl = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                lbl.setBackground(CyberTheme.BG_SIDEBAR);
                lbl.setForeground(CyberTheme.TEXT_MUTED);
                lbl.setFont(CyberTheme.FONT_BODY_BOLD);
                lbl.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, CyberTheme.BORDER_COLOR));
                lbl.setHorizontalAlignment(SwingConstants.LEFT);
                return lbl;
            }
        });

        // Alternating row colors and badge renderer
        setDefaultRenderer(Object.class, new CyberCellRenderer());
    }

    private static class CyberCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            if (!isSelected) {
                c.setBackground(row % 2 == 0 ? CyberTheme.BG_CARD : ROW_ALT_COLOR);
            } else {
                c.setBackground(SELECTION_COLOR);
            }
            c.setForeground(CyberTheme.TEXT_PRIMARY);

            String text = value != null ? value.toString() : "";

            // Custom coloring for severities and statuses
            if ("CRITICAL".equalsIgnoreCase(text)) {
                c.setForeground(CyberTheme.STATUS_RED);
                setFont(CyberTheme.FONT_BODY_BOLD);
            } else if ("HIGH".equalsIgnoreCase(text)) {
                c.setForeground(new Color(249, 115, 22)); // Orange
                setFont(CyberTheme.FONT_BODY_BOLD);
            } else if ("MEDIUM".equalsIgnoreCase(text)) {
                c.setForeground(CyberTheme.STATUS_AMBER);
            } else if ("LOW".equalsIgnoreCase(text)) {
                c.setForeground(CyberTheme.STATUS_GREEN);
            } else if ("RESOLVED".equalsIgnoreCase(text)) {
                c.setForeground(CyberTheme.STATUS_GREEN);
                setFont(CyberTheme.FONT_BODY_BOLD);
            } else if ("OPEN".equalsIgnoreCase(text) || "NEW".equalsIgnoreCase(text)) {
                c.setForeground(CyberTheme.STATUS_RED);
                setFont(CyberTheme.FONT_BODY_BOLD);
            } else if ("INVESTIGATING".equalsIgnoreCase(text)) {
                c.setForeground(CyberTheme.STATUS_AMBER);
            } else {
                setFont(CyberTheme.FONT_BODY);
            }

            setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
            return c;
        }
    }

    public static JScrollPane wrapInScrollPane(JTable table) {
        JScrollPane scrollPane = new JScrollPane(table);
        scrollPane.setBackground(CyberTheme.BG_DARK);
        scrollPane.getViewport().setBackground(CyberTheme.BG_CARD);
        scrollPane.setBorder(BorderFactory.createLineBorder(CyberTheme.BORDER_COLOR, 1));
        return scrollPane;
    }
}
