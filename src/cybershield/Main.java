package cybershield;

import cybershield.gui.MainFrame;
import cybershield.model.User;

import javax.swing.SwingUtilities;

/**
 * Main — The entry point of the CyberShield application.
 * Uses SwingUtilities.invokeLater() to start the GUI on the Event Dispatch Thread (EDT).
 * For now, opens MainFrame directly. The login screen will be added later.
 */
public class Main {

    /** Starts the application. */
    public static void main(String[] args) {
        // SwingUtilities.invokeLater() ensures the GUI is created on the
        // Event Dispatch Thread (EDT), which is the correct thread for Swing.
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                MainFrame frame = new MainFrame();

                // Temporary: set a default user so the status bar shows something.
                // The login module will replace this with a real login dialog later.
                User defaultUser = new User("admin", "admin123", "ADMIN");
                defaultUser.setId(1);
                frame.setCurrentUser(defaultUser);

                frame.setVisible(true);
            }
        });
    }
}
