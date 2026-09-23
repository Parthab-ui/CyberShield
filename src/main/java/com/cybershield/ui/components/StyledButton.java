package com.cybershield.ui.components;

import com.cybershield.ui.CyberTheme;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.JButton;

/**
 * Custom styled button with sleek dark-theme coloring and hover states.
 */
public class StyledButton extends JButton {

    public enum ButtonStyle {
        PRIMARY(CyberTheme.ACCENT_CYAN, CyberTheme.TEXT_DARK, new Color(8, 145, 178)),
        DANGER(CyberTheme.STATUS_RED, CyberTheme.TEXT_PRIMARY, new Color(220, 38, 38)),
        SUCCESS(CyberTheme.STATUS_GREEN, CyberTheme.TEXT_DARK, new Color(5, 150, 105)),
        SECONDARY(CyberTheme.BG_CARD_HOVER, CyberTheme.TEXT_PRIMARY, new Color(71, 85, 105));

        final Color normalBg;
        final Color textFg;
        final Color hoverBg;

        ButtonStyle(Color normalBg, Color textFg, Color hoverBg) {
            this.normalBg = normalBg;
            this.textFg = textFg;
            this.hoverBg = hoverBg;
        }
    }

    private final ButtonStyle style;
    private boolean isHovered = false;

    public StyledButton(String text) {
        this(text, ButtonStyle.PRIMARY);
    }

    public StyledButton(String text, ButtonStyle style) {
        super(text);
        this.style = style != null ? style : ButtonStyle.PRIMARY;
        setContentAreaFilled(false);
        setFocusPainted(false);
        setBorderPainted(false);
        setFont(CyberTheme.FONT_BODY_BOLD);
        setForeground(this.style.textFg);
        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

        addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                isHovered = true;
                repaint();
            }

            @Override
            public void mouseExited(MouseEvent e) {
                isHovered = false;
                repaint();
            }
        });
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        Color bg = isHovered ? style.hoverBg : style.normalBg;
        g2.setColor(bg);
        g2.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8);

        super.paintComponent(g);
        g2.dispose();
    }
}
