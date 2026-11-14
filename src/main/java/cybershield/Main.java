package cybershield;

import cybershield.database.DatabaseManager;
import cybershield.server.HttpServerManager;
import cybershield.ui.LoginFrame;

import javax.swing.*;
import java.awt.*;

/**
 * Main — The primary bootstrap entry point for CyberShield.
 *
 * Responsibilities:
 * 1. Initialize persistent SQLite database schema and seed demo records.
 * 2. Start embedded HTTP REST server (serving Web application on http://localhost:8080).
 * 3. Launch Java Swing desktop GUI on the Event Dispatch Thread (EDT).
 *
 * Command Line Arguments:
 * - (default): Starts both HTTP Server and Swing Desktop GUI.
 * - --server-only: Starts embedded HTTP Server and Web app without launching desktop GUI.
 * - --gui-only: Launches desktop Swing GUI only without starting HTTP Server.
 * - --port <number>: Custom port for the HTTP server (default: 8080).
 */
public class Main {

    private static final int DEFAULT_PORT = 8080;

    public static void main(String[] args) {
        System.out.println("======================================================================");
        System.out.println("  CYBERSHIELD: Cybersecurity Monitoring & Incident Management System ");
        System.out.println("  Academic 2nd-Year B.Tech CSE Project Evaluation Edition             ");
        System.out.println("======================================================================");

        boolean serverOnly = false;
        boolean guiOnly = false;
        int port = DEFAULT_PORT;

        // Parse command line arguments
        for (int i = 0; i < args.length; i++) {
            if ("--server-only".equalsIgnoreCase(args[i])) {
                serverOnly = true;
            } else if ("--gui-only".equalsIgnoreCase(args[i])) {
                guiOnly = true;
            } else if ("--port".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                try {
                    port = Integer.parseInt(args[++i]);
                } catch (NumberFormatException e) {
                    System.err.println("[WARN] Invalid port number specified, defaulting to " + DEFAULT_PORT);
                }
            }
        }

        // STEP 1: Initialize Database Layer
        System.out.println("\n[1/3] Initializing SQLite database connection & schema...");
        try {
            DatabaseManager.initialize();
            System.out.println("[OK] SQLite database initialized successfully at: data/cybershield.db");
            System.out.println("[OK] Demo accounts ready: 'admin' (Admin@123) and 'analyst' (Analyst@123)");
        } catch (Exception e) {
            System.err.println("[ERROR] Failed to initialize SQLite database: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }

        int boundPort = port;
        if (!guiOnly) {
            System.out.println("\n[2/3] Starting embedded Java HTTP Web & REST API server...");
            try {
                HttpServerManager serverManager = HttpServerManager.getInstance();
                boundPort = serverManager.start(port);
                System.out.println("[OK] CyberShield Web Application live at: http://localhost:" + boundPort);
                System.out.println("[OK] REST API endpoints available at:   http://localhost:" + boundPort + "/api/");
            } catch (Exception e) {
                System.err.println("[ERROR] Failed to start HTTP server: " + e.getMessage());
                e.printStackTrace();
            }
        } else {
            System.out.println("\n[2/3] Skipping HTTP server (--gui-only mode active).");
        }

        // STEP 3: Launch Java Swing Desktop GUI (Unless --server-only is specified)
        if (!serverOnly) {
            System.out.println("\n[3/3] Launching Java Swing Desktop GUI on Event Dispatch Thread (EDT)...");
            try {
                if (!GraphicsEnvironment.isHeadless()) {
                    launchSwingGui();
                } else {
                    System.out.println("[INFO] Headless environment detected; Swing GUI omitted.");
                }
            } catch (Throwable t) {
                System.err.println("[WARN] Display initialization notice: " + t.getMessage());
            }
        }

        // Keep HTTP Server alive if server is running
        if (!guiOnly) {
            System.out.println("\n[READY] CyberShield Server active at: http://localhost:" + boundPort);
            System.out.println("[READY] Serving Web Dashboard & REST API. Press Ctrl+C to stop.");
            try {
                Thread.currentThread().join();
            } catch (InterruptedException ignored) {}
        }
    }

    /**
     * Initializes Swing Look & Feel and displays the LoginFrame on the Event Dispatch Thread (EDT).
     */
    private static void launchSwingGui() {
        // Set Look and Feel to System or CrossPlatform
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            // Fallback to cross-platform L&F if system L&F fails
            try {
                UIManager.setLookAndFeel(UIManager.getCrossPlatformLookAndFeelClassName());
            } catch (Exception ignored) {}
        }

        // Ensure Swing components are instantiated safely on the Event Dispatch Thread
        SwingUtilities.invokeLater(() -> {
            try {
                LoginFrame loginFrame = new LoginFrame();
                loginFrame.setVisible(true);

                // Ensure the window pops to the front and grabs focus
                loginFrame.toFront();
                loginFrame.requestFocus();

                System.out.println("[OK] Swing Desktop GUI is now visible on screen.");
            } catch (Exception e) {
                System.err.println("[ERROR] Failed to launch Swing Desktop GUI: " + e.getMessage());
                e.printStackTrace();
            }
        });
    }
}
