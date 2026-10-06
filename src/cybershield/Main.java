package cybershield;

import cybershield.gui.LoginFrame;
import cybershield.gui.MainFrame;
import cybershield.model.User;

import javax.swing.SwingUtilities;

/**
 * Main — The entry point of the CyberShield application.
 * Uses SwingUtilities.invokeLater() to start the GUI on the Event Dispatch Thread (EDT).
 * Starts with LoginFrame; after successful authentication, opens MainFrame and passes the User.
 */
public class Main {

    /** Starts the application. */
    public static void main(String[] args) {
        // SwingUtilities.invokeLater() ensures the GUI is created on the
        // Event Dispatch Thread (EDT), which is the correct thread for Swing.
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                LoginFrame loginFrame = new LoginFrame();
                loginFrame.setLoginCallback(new LoginFrame.LoginCallback() {
                    @Override
                    public void onLoginSuccess(User user) {
                        MainFrame mainFrame = new MainFrame();
                        mainFrame.setCurrentUser(user);
                        mainFrame.setVisible(true);
                    }
                });
                loginFrame.setVisible(true);
            }
        });
    }
}
