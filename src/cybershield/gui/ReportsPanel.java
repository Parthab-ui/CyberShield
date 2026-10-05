package cybershield.gui;

import cybershield.util.Theme;

import java.awt.BorderLayout;
import javax.swing.JLabel;
import javax.swing.SwingConstants;

/**
 * ReportsPanel — Placeholder panel for the Reports tab.
 * Extends BasePanel (INHERITANCE) and implements refreshData() (POLYMORPHISM).
 * A team member will replace this placeholder with the real reports view later.
 */
public class ReportsPanel extends BasePanel {

    private JLabel placeholderLabel;

    // Constructor — sets up the placeholder UI
    public ReportsPanel() {
        setLayout(new BorderLayout());
        Theme.stylePanel(this);

        placeholderLabel = new JLabel("Reports — Coming Soon", SwingConstants.CENTER);
        placeholderLabel.setFont(Theme.FONT_TITLE);
        placeholderLabel.setForeground(Theme.ACCENT);
        add(placeholderLabel, BorderLayout.CENTER);
    }

    /** Refreshes data on this panel (to be implemented by the team member). */
    @Override
    public void refreshData() {
        // Will be implemented when the real reports view is built
        System.out.println("ReportsPanel: refreshData() called");
    }
}
