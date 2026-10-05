package cybershield.gui;

import cybershield.util.Theme;

import java.awt.BorderLayout;
import java.awt.Font;
import javax.swing.JLabel;
import javax.swing.SwingConstants;

/**
 * DashboardPanel — Placeholder panel for the Dashboard tab.
 * Extends BasePanel (INHERITANCE) and implements refreshData() (POLYMORPHISM).
 * A team member will replace this placeholder with the real dashboard later.
 */
public class DashboardPanel extends BasePanel {

    private JLabel placeholderLabel;

    // Constructor — sets up the placeholder UI
    public DashboardPanel() {
        setLayout(new BorderLayout());
        Theme.stylePanel(this);

        placeholderLabel = new JLabel("Dashboard — Coming Soon", SwingConstants.CENTER);
        placeholderLabel.setFont(Theme.FONT_TITLE);
        placeholderLabel.setForeground(Theme.ACCENT);
        add(placeholderLabel, BorderLayout.CENTER);
    }

    /** Refreshes data on this panel (to be implemented by the team member). */
    @Override
    public void refreshData() {
        // Will be implemented when the real dashboard is built
        System.out.println("DashboardPanel: refreshData() called");
    }
}
