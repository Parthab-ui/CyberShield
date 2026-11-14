package cybershield.server;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * StaticFileHandler — Serves the HTML, CSS, JavaScript, and asset files
 * from the 'web' directory for the browser interface.
 * Demonstrates: HTTP file delivery, correct MIME type resolution, and 404 handling.
 */
public class StaticFileHandler implements HttpHandler {

    private final String webRoot;

    public StaticFileHandler(String webRoot) {
        this.webRoot = webRoot;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();

        // Default root maps to index.html
        if (path == null || path.equals("/") || path.isEmpty()) {
            path = "/index.html";
        }

        // Prevent path traversal outside the web folder
        File file = new File(webRoot, path.replace('/', File.separatorChar));
        String canonicalPath = file.getCanonicalPath();
        String canonicalRoot = new File(webRoot).getCanonicalPath();

        if (!canonicalPath.startsWith(canonicalRoot) || !file.exists() || file.isDirectory()) {
            // If requested path is not found, fallback to index.html for Single Page App routing
            File indexFile = new File(webRoot, "index.html");
            if (indexFile.exists()) {
                serveFile(exchange, indexFile, "text/html; charset=UTF-8");
                return;
            }
            send404(exchange);
            return;
        }

        String mimeType = getMimeType(file.getName());
        serveFile(exchange, file, mimeType);
    }

    private void serveFile(HttpExchange exchange, File file, String mimeType) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", mimeType);
        exchange.getResponseHeaders().set("Cache-Control", "no-cache, no-store, must-revalidate");
        exchange.sendResponseHeaders(200, file.length());

        try (FileInputStream in = new FileInputStream(file);
             OutputStream out = exchange.getResponseBody()) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
        }
    }

    private void send404(HttpExchange exchange) throws IOException {
        String notFound = "<h1>404 Not Found</h1><p>The requested file does not exist.</p>";
        byte[] bytes = notFound.getBytes();
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
        exchange.sendResponseHeaders(404, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private String getMimeType(String fileName) {
        String lower = fileName.toLowerCase();
        if (lower.endsWith(".html") || lower.endsWith(".htm")) return "text/html; charset=UTF-8";
        if (lower.endsWith(".css")) return "text/css; charset=UTF-8";
        if (lower.endsWith(".js")) return "application/javascript; charset=UTF-8";
        if (lower.endsWith(".json")) return "application/json; charset=UTF-8";
        if (lower.endsWith(".svg")) return "image/svg+xml";
        if (lower.endsWith(".png")) return "image/png";
        if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return "image/jpeg";
        if (lower.endsWith(".ico")) return "image/x-icon";
        return "text/plain; charset=UTF-8";
    }
}
