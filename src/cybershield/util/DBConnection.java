package cybershield.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;

/**
 * DBConnection — Centralized, resilient database connection manager.
 * Supports Zero-Configuration Startup:
 * 1. Checks configuration in config/db.properties or environment variables.
 * 2. In "auto" mode:
 *    - Tries MySQL at localhost:3306.
 *    - If MySQL is available: ensures cybershield_db exists and connects.
 *    - If MySQL is not running or credentials fail: seamlessly falls back to an embedded
 *      persistent database (./data/cybershield) with zero user intervention!
 * 3. Automatically triggers DatabaseInitializer to verify tables and default logins.
 */
public class DBConnection {

    private static final String CONFIG_DIR  = "config";
    private static final String CONFIG_FILE = "config/db.properties";

    private static String dbMode          = "auto";
    private static String mysqlHost       = "localhost";
    private static int    mysqlPort       = 3306;
    private static String mysqlDatabase   = "cybershield_db";
    private static String mysqlUser       = "root";
    private static String mysqlPassword   = "";
    private static String embeddedPath    = "./data/cybershield";

    // Active determined database configuration
    private static String activeEngine    = null;
    private static String activeJdbcUrl   = null;
    private static String activeJdbcUser  = null;
    private static String activeJdbcPass  = null;

    private static boolean schemaInitialized = false;

    // Private constructor prevents instantiation
    private DBConnection() { }

    static {
        loadConfiguration();
    }

    /** Loads settings from file, environment, or creates default config. */
    private static void loadConfiguration() {
        File cfg = new File(CONFIG_FILE);
        if (!cfg.exists()) {
            File alt = new File("db.properties");
            if (alt.exists()) {
                cfg = alt;
            }
        }

        if (cfg.exists()) {
            Properties props = new Properties();
            try (FileInputStream in = new FileInputStream(cfg)) {
                props.load(in);
                dbMode        = props.getProperty("db.mode", dbMode).trim();
                mysqlHost     = props.getProperty("mysql.host", mysqlHost).trim();
                mysqlPort     = Integer.parseInt(props.getProperty("mysql.port", String.valueOf(mysqlPort)).trim());
                mysqlDatabase = props.getProperty("mysql.database", mysqlDatabase).trim();
                mysqlUser     = props.getProperty("mysql.user", mysqlUser).trim();
                mysqlPassword = props.getProperty("mysql.password", mysqlPassword).trim();
                embeddedPath  = props.getProperty("embedded.path", embeddedPath).trim();
            } catch (Exception e) {
                System.out.println("[DBConnection] Note: Using default database configuration.");
            }
        } else {
            createDefaultConfigFile();
        }

        // Environment variable overrides if present
        String envMode = System.getenv("CYBERSHIELD_DB_MODE");
        if (envMode != null && !envMode.isEmpty()) dbMode = envMode;

        String envUser = System.getenv("CYBERSHIELD_DB_USER");
        if (envUser != null) mysqlUser = envUser;

        String envPass = System.getenv("CYBERSHIELD_DB_PASS");
        if (envPass != null) mysqlPassword = envPass;
    }

    /** Generates a starter config/db.properties file. */
    private static void createDefaultConfigFile() {
        try {
            File dir = new File(CONFIG_DIR);
            if (!dir.exists()) {
                dir.mkdirs();
            }
            File file = new File(CONFIG_FILE);
            Properties props = new Properties();
            props.setProperty("db.mode", "auto");
            props.setProperty("mysql.host", "localhost");
            props.setProperty("mysql.port", "3306");
            props.setProperty("mysql.database", "cybershield_db");
            props.setProperty("mysql.user", "root");
            props.setProperty("mysql.password", "");
            props.setProperty("embedded.path", "./data/cybershield");

            try (FileOutputStream out = new FileOutputStream(file)) {
                props.store(out, "CyberShield Database Configuration\n"
                        + "db.mode: 'auto' (try MySQL, fallback to embedded), 'mysql' (force MySQL), 'embedded' (force H2 embedded)");
            }
        } catch (IOException e) {
            // Ignore if directory is read-only
        }
    }

    /** Probes and determines the appropriate database target. */
    private static synchronized void determineDatabaseTarget() throws SQLException {
        loadConfiguration();

        if ("embedded".equalsIgnoreCase(dbMode)) {
            configureEmbedded();
        } else if ("mysql".equalsIgnoreCase(dbMode)) {
            configureMySQL();
        } else {
            // Auto mode: probe MySQL first; fallback to embedded if unavailable
            try {
                configureMySQL();
            } catch (Exception ex) {
                System.out.println("[DBConnection] MySQL unavailable (" + ex.getMessage() + ").");
                System.out.println("[DBConnection] Activating Zero-Setup Embedded Database mode...");
                configureEmbedded();
            }
        }
    }

    private static void configureMySQL() throws SQLException {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            throw new SQLException("MySQL JDBC Driver not found on classpath: " + e.getMessage());
        }

        String serverUrl = String.format("jdbc:mysql://%s:%d/?allowPublicKeyRetrieval=true&useSSL=false&serverTimezone=UTC&connectTimeout=2000",
                mysqlHost, mysqlPort);

        // Probe connection to MySQL server to ensure database exists
        try (Connection serverConn = DriverManager.getConnection(serverUrl, mysqlUser, mysqlPassword);
             Statement st = serverConn.createStatement()) {
            st.execute("CREATE DATABASE IF NOT EXISTS " + mysqlDatabase);
        }

        activeJdbcUrl  = String.format("jdbc:mysql://%s:%d/%s?allowPublicKeyRetrieval=true&useSSL=false&serverTimezone=UTC",
                mysqlHost, mysqlPort, mysqlDatabase);
        activeJdbcUser = mysqlUser;
        activeJdbcPass = mysqlPassword;
        activeEngine   = "MySQL (" + mysqlHost + ":" + mysqlPort + "/" + mysqlDatabase + ")";
        System.out.println("[DBConnection] SUCCESS: Connected to " + activeEngine);
    }

    private static void configureEmbedded() throws SQLException {
        try {
            Class.forName("org.h2.Driver");
        } catch (ClassNotFoundException e) {
            throw new SQLException("Embedded Database Driver (H2) not found in lib folder: " + e.getMessage());
        }

        File dataDir = new File("./data");
        if (!dataDir.exists()) {
            dataDir.mkdirs();
        }

        activeJdbcUrl  = "jdbc:h2:" + embeddedPath + ";MODE=MySQL;DATABASE_TO_LOWER=TRUE;AUTO_SERVER=TRUE;DB_CLOSE_DELAY=-1";
        activeJdbcUser = "sa";
        activeJdbcPass = "";
        activeEngine   = "Embedded Engine (Persistent local file at " + embeddedPath + ")";
        System.out.println("[DBConnection] SUCCESS: Connected to " + activeEngine);
    }

    /**
     * Initializes the database connection and runs schema/table creation.
     * Can be invoked proactively at application launch.
     */
    public static synchronized void initialize() throws SQLException {
        if (activeJdbcUrl == null) {
            determineDatabaseTarget();
        }

        if (!schemaInitialized) {
            try (Connection initConn = DriverManager.getConnection(activeJdbcUrl, activeJdbcUser, activeJdbcPass)) {
                DatabaseInitializer.initializeDatabase(initConn);
                schemaInitialized = true;
            }
        }
    }

    /**
     * Returns an active database connection for the caller.
     * Thread-safe: provides each caller with an independent connection
     * that is safely closed by the caller's try-with-resources.
     */
    public static Connection getConnection() throws SQLException {
        if (activeJdbcUrl == null || !schemaInitialized) {
            initialize();
        }
        return DriverManager.getConnection(activeJdbcUrl, activeJdbcUser, activeJdbcPass);
    }

    /** Returns a readable name of the active database engine (MySQL or Embedded). */
    public static String getActiveEngine() {
        return (activeEngine != null) ? activeEngine : "Not Initialized";
    }

    /** Returns true if running in embedded zero-setup mode. */
    public static boolean isEmbedded() {
        return activeEngine != null && activeEngine.startsWith("Embedded");
    }

    /** Closes any database resources if needed. */
    public static synchronized void closeConnection() {
        System.out.println("[DBConnection] Database resources released.");
    }

    /** Diagnostic test runner. */
    public static void main(String[] args) {
        try {
            initialize();
            System.out.println("Active Database Engine: " + getActiveEngine());
            System.out.println("Database initialization verified.");
        } catch (SQLException e) {
            System.err.println("Database connection failed: " + e.getMessage());
        } finally {
            closeConnection();
        }
    }
}
