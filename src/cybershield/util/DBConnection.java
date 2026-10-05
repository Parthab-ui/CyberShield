package cybershield.util;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

/**
 * DBConnection — Provides a single shared database connection (Singleton pattern).
 * Edit the three constants below to match your MySQL setup.
 */
public class DBConnection {

    // -------- EDIT THESE TO MATCH YOUR MYSQL SETUP --------
    private static final String URL      = "jdbc:mysql://localhost:3306/cybershield_db";
    private static final String USER     = "root";
    private static final String PASSWORD = "";
    // ------------------------------------------------------

    // The single connection instance (Singleton)
    private static Connection connection = null;

    // Private constructor — prevents creating objects from outside
    private DBConnection() { }

    /**
     * Returns the shared database connection. Creates one if it does not exist.
     */
    public static Connection getConnection() throws SQLException {
        if (connection == null || connection.isClosed()) {
            connection = DriverManager.getConnection(URL, USER, PASSWORD);
        }
        return connection;
    }

    /**
     * Closes the database connection if it is open.
     */
    public static void closeConnection() {
        if (connection != null) {
            try {
                connection.close();
                System.out.println("Database connection closed.");
            } catch (SQLException e) {
                System.out.println("Error closing connection: " + e.getMessage());
            }
        }
    }

    /**
     * Test method — run this class directly to check if the database connection works.
     */
    public static void main(String[] args) {
        try {
            Connection conn = getConnection();
            if (conn != null && !conn.isClosed()) {
                System.out.println("SUCCESS: Connected to cybershield_db!");
            }
        } catch (SQLException e) {
            System.out.println("FAILED: Could not connect to database.");
            System.out.println("Reason: " + e.getMessage());
        }
    }
}
