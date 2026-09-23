package com.cybershield.ui.components;

import com.cybershield.ui.CyberTheme;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridLayout;
import java.awt.RenderingHints;
import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;

/**
 * Metric summary card displaying key SOC indicator metrics.
 */
public class MetricCard extends JPanel {

    private final JLabel lblTitle;
    private final JLabel lblValue;
    private final JLabel lblSubtitle;
    private final Color accentColor;

    public MetricCard(String title, String initialValue, String subtitle, Color accentColor) {
        this.accentColor = accentColor != null ? accentColor : CyberTheme.ACCENT_CYAN;
        setLayout(new BorderLayout(8, 8));
        setBackground(CyberTheme.BG_CARD);
        setBorder(BorderFactory.createEmptyBorder(12, 16, 12, 16));
        setPreferredSize(new Dimension(180, 95));

        JPanel content = new JPanel(new GridLayout(3, 1, 2, 2));
        content.setOpaque(false);

        lblTitle = new JLabel(title.toUpperCase());
        lblTitle.setFont(CyberTheme.FONT_SMALL);
        lblTitle.setForeground(CyberTheme.TEXT_MUTED);

        lblValue = new JLabel(initialValue);
        lblValue.setFont(new Font("Segoe UI", Font.BOLD, 26));
        lblValue.setForeground(this.accentColor);

        lblSubtitle = new JLabel(subtitle);
        lblSubtitle.setFont(CyberTheme.FONT_SMALL);
        lblSubtitle.setForeground(CyberTheme.TEXT_MUTED);

        content.add(lblTitle);
        content.add(lblValue);
        content.add(lblSubtitle);

        add(content, BorderLayout.CENTER);
    }

    public void setValue(String value) {
        lblValue.setText(value);
        repaint();
    }

    public void setValue(int count) {
        setValue(String.valueOf(count));
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        // Fill card background
        g2.setColor(getBackground());
        g2.fillRoundRect(0, 0, getWidth(), getHeight(), 10, 10);

        // Card border
        g2.setColor(CyberTheme.BORDER_COLOR);
        g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 10, 10);

        // Top accent bar
        g2.setColor(accentColor);
        g2.fillRoundRect(0, 0, getWidth(), 4, 4, 4);

        g2.dispose();
    }
}
