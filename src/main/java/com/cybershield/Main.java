package com.cybershield;

import com.cybershield.exception.DatabaseOperationException;
import com.cybershield.repository.DatabaseManager;
import com.cybershield.ui.LoginDialog;
import com.cybershield.ui.MainDashboardFrame;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;

/**
 * Entry-point class for the CYBERSHIELD application.
 * 
 * Sets up Swing UI look-and-feel, ensures the local SQLite database
 * schema is initialized, and boots the SOC authentication dialog.
 */
public class Main {

    public static void main(String[] args) {
        // Enable high-DPI scaling and modern font rendering
        System.setProperty("awt.useSystemAAFontSettings", "on");
        System.setProperty("swing.aatext", "true");

        try {
            // Use system look and feel if available
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            // Fallback cleanly to default Java Swing L&F
        }

        // Initialize local SQLite database before launching GUI
        try {
            DatabaseManager.getInstance().initializeDatabase();
            System.out.println("[CyberShield] SQLite Database initialized successfully.");
        } catch (DatabaseOperationException e) {
            JOptionPane.showMessageDialog(null,
                    "Failed to initialize local SQLite database:\n" + e.getMessage() +
                    "\n\nPlease ensure write permissions exist in the application directory.",
                    "Database Initialization Error", JOptionPane.ERROR_MESSAGE);
            System.exit(1);
            return;
        }

        // Launch UI on Event Dispatch Thread (Swing standard practice)
        SwingUtilities.invokeLater(() -> {
            LoginDialog loginDialog = new LoginDialog(null);
            loginDialog.setVisible(true);

            if (loginDialog.isLoginSuccessful()) {
                MainDashboardFrame dashboard = new MainDashboardFrame();
                dashboard.setVisible(true);
            } else {
                System.exit(0);
            }
        });
    }
}
