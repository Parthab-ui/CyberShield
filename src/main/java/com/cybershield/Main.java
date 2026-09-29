package com.cybershield;

import com.cybershield.exception.DatabaseOperationException;
import com.cybershield.repository.DatabaseManager;
import com.cybershield.ui.LoginDialog;
import com.cybershield.ui.MainDashboardFrame;
import com.cybershield.web.CyberShieldWebServer;
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

        // Start built-in Localhost Web Server (http://localhost:8080)
        try {
            CyberShieldWebServer.startServer(8080);
        } catch (Exception e) {
            System.err.println("[CyberShield] Warning: Could not start localhost web server on port 8080: " + e.getMessage());
        }

        // Launch Desktop UI on Event Dispatch Thread (Swing standard practice)
        try {
            if (!java.awt.GraphicsEnvironment.isHeadless()) {
                SwingUtilities.invokeLater(() -> {
                    try {
                        LoginDialog loginDialog = new LoginDialog(null);
                        loginDialog.setVisible(true);

                        if (loginDialog.isLoginSuccessful()) {
                            MainDashboardFrame dashboard = new MainDashboardFrame();
                            dashboard.setVisible(true);
                        }
                    } catch (Exception ex) {
                        System.out.println("[CyberShield] Desktop UI closed or headless: " + ex.getMessage());
                    }
                });
            } else {
                System.out.println("[CyberShield] Running in headless mode. Localhost Web Dashboard active on http://localhost:8080");
            }
        } catch (Exception e) {
            System.out.println("[CyberShield] Localhost Web Dashboard active on http://localhost:8080");
        }
    }
}
