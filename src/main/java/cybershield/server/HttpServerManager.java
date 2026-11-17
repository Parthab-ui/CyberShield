package cybershield.server;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;

/**
 * HttpServerManager — Configures and runs the embedded Java HTTP Server.
 * Demonstrates: Lightweight micro-server architecture using standard JDK 'com.sun.net.httpserver'.
 * Eliminates heavyweight frameworks like Spring Boot or Tomcat while providing robust REST API and static file serving.
 */
public class HttpServerManager {

    public static final int DEFAULT_PORT = 8080;
    private static final String WEB_DIR = "web";
    private static final HttpServerManager INSTANCE = new HttpServerManager();

    private HttpServer server;
    private int activePort;
    private boolean running = false;

    public HttpServerManager() {
    }

    public static HttpServerManager getInstance() {
        return INSTANCE;
    }

    /**
     * Starts the HTTP server on specified port, or falls back to port+1..port+10 if busy.
     * Returns the port number that was successfully bound.
     */
    public synchronized int start(int preferredPort) throws IOException {
        if (running) {
            System.out.println("[HttpServerManager] Server is already running on port " + activePort);
            return activePort;
        }

        int portToTry = preferredPort > 0 ? preferredPort : DEFAULT_PORT;
        HttpServer createdServer = null;

        for (int i = 0; i < 10; i++) {
            try {
                createdServer = HttpServer.create(new InetSocketAddress(portToTry), 0);
                activePort = portToTry;
                break;
            } catch (IOException e) {
                System.out.println("[HttpServerManager] Port " + portToTry + " busy, trying next port...");
                portToTry++;
            }
        }

        if (createdServer == null) {
            throw new IOException("Could not bind HTTP server on any port between " + preferredPort + " and " + (preferredPort + 10));
        }

        this.server = createdServer;

        // Route 1: REST API endpoints under '/api/'
        ApiHandler apiHandler = new ApiHandler();
        apiHandler.addAllowedOrigin(activePort);
        server.createContext("/api", apiHandler);

        // Route 2: Static web files (HTML, CSS, JS) under root '/'
        server.createContext("/", new StaticFileHandler(WEB_DIR));

        // Use thread pool executor for concurrent HTTP request handling
        server.setExecutor(Executors.newFixedThreadPool(8));
        server.start();
        running = true;

        System.out.println("==================================================================");
        System.out.println("  CyberShield Backend Server active at: http://localhost:" + activePort + "/");
        System.out.println("  REST API available at:                http://localhost:" + activePort + "/api/");
        System.out.println("  Web Dashboard serving from:           ./" + WEB_DIR + "/");
        System.out.println("==================================================================");
        return activePort;
    }

    /**
     * Starts the HTTP server on DEFAULT_PORT (8080), or automatically falls back to 8081..8090 if busy.
     */
    public synchronized void start() throws IOException {
        start(DEFAULT_PORT);
    }

    /**
     * Safely terminates the HTTP server with a graceful 1-second timeout.
     */
    public synchronized void stop() {
        if (server != null && running) {
            server.stop(1);
            running = false;
            System.out.println("[HttpServerManager] Server stopped successfully.");
        }
    }

    public int getActivePort() {
        return activePort;
    }

    public String getServerUrl() {
        return "http://localhost:" + activePort;
    }

    public boolean isRunning() {
        return running;
    }
}
