package cybershield;

import cybershield.gui.LoginFrame;
import cybershield.gui.MainFrame;
import cybershield.model.User;
import cybershield.util.DBConnection;

import java.sql.SQLException;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;

/**
 * Main — The entry point of the CyberShield application.
 * Features:
 * - Automatic background database initialization before GUI display.
 * - Auto-detects MySQL or falls back to embedded persistent database.
 * - Idempotently creates tables and seeds default admin account (admin / admin123).
 * - Graceful error notification if an unrecoverable storage failure occurs.
 */
public class Main {

    /** Starts the application. */
    public static void main(String[] args) {
        // Step 1: Pre-flight automatic database initialization
        try {
            DBConnection.initialize();
            System.out.println("[Main] Database engine active: " + DBConnection.getActiveEngine());
        } catch (SQLException e) {
            System.err.println("[Main] Critical database initialization failure: " + e.getMessage());
            JOptionPane.showMessageDialog(null,
                    "CyberShield encountered an issue connecting to the database.\n\n"
                    + "Diagnostic Details: " + e.getMessage() + "\n\n"
                    + "Troubleshooting:\n"
                    + "1. Ensure MySQL is running if using MySQL mode, or\n"
                    + "2. Verify write permissions in the application folder for embedded mode.",
                    "Database Startup Notice", JOptionPane.WARNING_MESSAGE);
        }

        // Step 2: Launch the user interface on the Event Dispatch Thread (EDT)
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                try {
                    System.out.println("[Main] Creating LoginFrame...");
                    LoginFrame loginFrame = new LoginFrame();
                    loginFrame.setLoginCallback(new LoginFrame.LoginCallback() {
                        @Override
                        public void onLoginSuccess(User user) {
                            try {
                                MainFrame mainFrame = new MainFrame();
                                mainFrame.setCurrentUser(user);
                                mainFrame.setVisible(true);
                                mainFrame.toFront();
                                mainFrame.requestFocus();
                            } catch (Throwable t) {
                                System.err.println("[Main] Error displaying MainFrame:");
                                t.printStackTrace();
                            }
                        }
                    });
                    loginFrame.setVisible(true);
                    loginFrame.toFront();
                    loginFrame.requestFocus();
                    System.out.println("[Main] LoginFrame displayed successfully.");
                } catch (Throwable t) {
                    System.err.println("[Main] Critical GUI launch error:");
                    t.printStackTrace();
                }
            }
        });
    }
}
