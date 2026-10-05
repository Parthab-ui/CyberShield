package cybershield.gui;

import javax.swing.JPanel;

/**
 * BasePanel — Abstract base class for all module panels.
 * Demonstrates ABSTRACTION: every panel must implement refreshData(), but how it
 * refreshes is up to the subclass (Dashboard, Threats, Incidents, etc.).
 * Demonstrates INHERITANCE: all module panels extend this class.
 */
public abstract class BasePanel extends JPanel {

    /**
     * Refreshes the data displayed on this panel.
     * Each subclass implements this differently (POLYMORPHISM through overriding).
     */
    public abstract void refreshData();
}
