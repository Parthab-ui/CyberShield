package cybershield.gui;

import cybershield.util.Theme;

import java.awt.BorderLayout;
import javax.swing.JLabel;
import javax.swing.SwingConstants;

/**
 * ThreatMonitorPanel — Placeholder panel for the Threat Monitor tab.
 * Extends BasePanel (INHERITANCE) and implements refreshData() (POLYMORPHISM).
 * A team member will replace this placeholder with the real threat monitor later.
 */
public class ThreatMonitorPanel extends BasePanel {

    private JLabel placeholderLabel;

    // Constructor — sets up the placeholder UI
    public ThreatMonitorPanel() {
        setLayout(new BorderLayout());
        Theme.stylePanel(this);

        placeholderLabel = new JLabel("Threat Monitor — Coming Soon", SwingConstants.CENTER);
        placeholderLabel.setFont(Theme.FONT_TITLE);
        placeholderLabel.setForeground(Theme.ACCENT);
        add(placeholderLabel, BorderLayout.CENTER);
    }

    /** Refreshes data on this panel (to be implemented by the team member). */
    @Override
    public void refreshData() {
        // Will be implemented when the real threat monitor is built
        System.out.println("ThreatMonitorPanel: refreshData() called");
    }
}
