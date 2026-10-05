package cybershield.gui;

import cybershield.util.Theme;

import java.awt.BorderLayout;
import javax.swing.JLabel;
import javax.swing.SwingConstants;

/**
 * SettingsPanel — Placeholder panel for the Settings tab.
 * Extends BasePanel (INHERITANCE) and implements refreshData() (POLYMORPHISM).
 * A team member will replace this placeholder with the real settings view later.
 */
public class SettingsPanel extends BasePanel {

    private JLabel placeholderLabel;

    // Constructor — sets up the placeholder UI
    public SettingsPanel() {
        setLayout(new BorderLayout());
        Theme.stylePanel(this);

        placeholderLabel = new JLabel("Settings — Coming Soon", SwingConstants.CENTER);
        placeholderLabel.setFont(Theme.FONT_TITLE);
        placeholderLabel.setForeground(Theme.ACCENT);
        add(placeholderLabel, BorderLayout.CENTER);
    }

    /** Refreshes data on this panel (to be implemented by the team member). */
    @Override
    public void refreshData() {
        // Will be implemented when the real settings view is built
        System.out.println("SettingsPanel: refreshData() called");
    }
}
