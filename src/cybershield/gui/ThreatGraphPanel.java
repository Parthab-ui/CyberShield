package cybershield.gui;

import cybershield.util.Theme;

import java.awt.Color;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * ThreatGraphPanel — Draws a bar chart of threat counts grouped by severity.
 * Uses Graphics2D directly — no external charting library.
 * Call setData(map) and then repaint() whenever new data is available.
 */
public class ThreatGraphPanel extends javax.swing.JPanel {

    // The data to draw: severity label -> count
    private Map<String, Integer> severityData;

    // Colours for each severity bar
    private static final Color COLOR_LOW      = new Color(50, 200, 80);    // green
    private static final Color COLOR_MEDIUM   = new Color(255, 165, 0);    // orange
    private static final Color COLOR_HIGH     = new Color(220, 100, 50);   // orange-red
    private static final Color COLOR_CRITICAL = new Color(220, 50, 50);    // red

    // Padding and layout constants
    private static final int PADDING_LEFT   = 55;  // space for Y-axis labels
    private static final int PADDING_BOTTOM = 40;  // space for X-axis labels
    private static final int PADDING_TOP    = 20;  // space above tallest bar
    private static final int PADDING_RIGHT  = 20;

    // Constructor — starts with empty data
    public ThreatGraphPanel() {
        setBackground(Theme.PANEL_BG);
        // Default empty data so the panel does not crash before refreshData() is called
        severityData = new LinkedHashMap<>();
        severityData.put("LOW",      0);
        severityData.put("MEDIUM",   0);
        severityData.put("HIGH",     0);
        severityData.put("CRITICAL", 0);
    }

    /**
     * Replaces the chart data and triggers a repaint.
     * Called from DashboardPanel.refreshData().
     */
    public void setData(Map<String, Integer> data) {
        this.severityData = data;
        repaint(); // Ask Swing to call paintComponent() again with the new data
    }

    /**
     * Paints the bar chart. Swing calls this automatically whenever the panel
     * needs to be redrawn (window resize, data change, etc.).
     * We override it here to draw our custom chart instead of a blank panel.
     */
    @Override
    protected void paintComponent(Graphics g) {
        // Always call super first — it clears the background
        super.paintComponent(g);

        // Cast to Graphics2D to access advanced drawing features
        Graphics2D g2d = (Graphics2D) g;

        // Turn on anti-aliasing for smoother text and lines
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        int panelWidth  = getWidth();
        int panelHeight = getHeight();

        // The area where bars are actually drawn
        int chartWidth  = panelWidth  - PADDING_LEFT - PADDING_RIGHT;
        int chartHeight = panelHeight - PADDING_TOP  - PADDING_BOTTOM;

        // ---- Draw title ----
        g2d.setFont(Theme.FONT_SMALL);
        g2d.setColor(Theme.TEXT_SECONDARY);
        g2d.drawString("Threats by Severity", PADDING_LEFT, 14);

        // ---- Find the maximum count (used to scale bar heights) ----
        int maxCount = 1; // avoid division by zero
        for (int count : severityData.values()) {
            if (count > maxCount) {
                maxCount = count;
            }
        }

        // ---- Draw Y-axis grid lines and labels ----
        int gridLines = 5; // number of horizontal grid lines
        g2d.setFont(Theme.FONT_SMALL);
        for (int i = 0; i <= gridLines; i++) {
            int yValue = (maxCount * i) / gridLines;
            // Y position: top = PADDING_TOP, bottom = panelHeight - PADDING_BOTTOM
            int yPos = panelHeight - PADDING_BOTTOM - (chartHeight * i / gridLines);

            // Draw a faint horizontal grid line
            g2d.setColor(new Color(60, 60, 90));
            g2d.drawLine(PADDING_LEFT, yPos, panelWidth - PADDING_RIGHT, yPos);

            // Draw the Y-axis number label
            g2d.setColor(Theme.TEXT_SECONDARY);
            String label = String.valueOf(yValue);
            FontMetrics fm = g2d.getFontMetrics();
            g2d.drawString(label, PADDING_LEFT - fm.stringWidth(label) - 4, yPos + 4);
        }

        // ---- Draw Y-axis line ----
        g2d.setColor(Theme.TEXT_SECONDARY);
        g2d.drawLine(PADDING_LEFT, PADDING_TOP, PADDING_LEFT, panelHeight - PADDING_BOTTOM);

        // ---- Draw X-axis line ----
        g2d.drawLine(PADDING_LEFT, panelHeight - PADDING_BOTTOM,
                     panelWidth - PADDING_RIGHT, panelHeight - PADDING_BOTTOM);

        // ---- Draw bars ----
        String[] labels = severityData.keySet().toArray(new String[0]);
        int barCount    = labels.length;
        int barWidth    = (chartWidth / barCount) - 10; // 10px gap between bars

        for (int i = 0; i < barCount; i++) {
            String key   = labels[i];
            int count    = severityData.get(key);

            // Scale the bar height relative to the maximum value
            int barHeight = (int) ((double) count / maxCount * chartHeight);

            // X position of this bar
            int xPos = PADDING_LEFT + i * (chartWidth / barCount) + 5;
            // Y position: bars grow upward from the X-axis
            int yPos = panelHeight - PADDING_BOTTOM - barHeight;

            // Choose colour based on severity key
            g2d.setColor(getBarColor(key));
            g2d.fillRect(xPos, yPos, barWidth, barHeight);

            // Draw a slightly darker border around the bar
            g2d.setColor(g2d.getColor().darker());
            g2d.drawRect(xPos, yPos, barWidth, barHeight);

            // Draw count number on top of the bar
            g2d.setColor(Theme.TEXT_PRIMARY);
            g2d.setFont(Theme.FONT_SMALL);
            FontMetrics fm = g2d.getFontMetrics();
            String countStr = String.valueOf(count);
            int textX = xPos + (barWidth - fm.stringWidth(countStr)) / 2;
            g2d.drawString(countStr, textX, yPos - 3);

            // Draw the severity label below the X-axis
            g2d.setColor(Theme.TEXT_SECONDARY);
            int labelX = xPos + (barWidth - fm.stringWidth(key)) / 2;
            g2d.drawString(key, labelX, panelHeight - PADDING_BOTTOM + 16);
        }
    }

    /** Returns the display colour for a given severity label. */
    private Color getBarColor(String severity) {
        switch (severity) {
            case "LOW":      return COLOR_LOW;
            case "MEDIUM":   return COLOR_MEDIUM;
            case "HIGH":     return COLOR_HIGH;
            case "CRITICAL": return COLOR_CRITICAL;
            default:         return Theme.ACCENT;
        }
    }
}
