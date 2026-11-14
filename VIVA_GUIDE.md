# CyberShield — Comprehensive Viva Examination Guide

> **Prepared for:** 2nd-Year B.Tech Computer Science and Engineering (CSE) Project Review & Oral Viva Examination.  
> **Course:** Object-Oriented Software Engineering / Advanced Java Programming.

---

## 1. Project Introduction
**CyberShield** is a dual-interface Cybersecurity Monitoring and Incident Management System developed in pure Java. It allows security teams to log, investigate, categorize, prioritize, and resolve cybersecurity incidents in real-time, while continuously monitoring unauthorized access anomalies and brute-force intrusion attempts.

It incorporates both a **modern web application** accessible via any standard web browser and an advanced **Java Swing desktop application**. Both applications communicate seamlessly with the same Java backend and persistent SQLite database.

---

## 2. Problem Statement
Organizations experience regular security alerts ranging from phishing campaigns and credential stuffing to critical malware infections. Small enterprises and SOC teams often lack lightweight, unified tools that:
1. Provide intuitive incident logging and life-cycle triage without demanding heavy enterprise server infrastructure.
2. Synchronously update operational metrics across both browser dashboards and native administrative desktop clients.
3. Enforce strict role-based authorization so that non-administrative operators cannot arbitrarily delete sensitive compliance logs or active incidents.

CyberShield solves this by delivering a lightweight, robust, and understandable application suitable for academic demonstration and real-world understanding.

---

## 3. Project Objectives
* **Unified Dual-Client Architecture:** Develop a single backend system simultaneously serving a web client and a Java Swing desktop interface.
* **Persistent Incident Tracking:** Implement full CRUD (Create, Read, Update, Delete) workflows for security incidents.
* **Intrusion Telemetry & Threat Simulation:** Capture and display unauthorized login attempts and provide an on-demand threat simulation generator for demonstration.
* **Strict Role-Based Access Control (RBAC):** Restrict incident deletion to the Administrator role while permitting analysts to report and investigate incidents.
* **Educational GUI Showcase:** Demonstrate more than 40 core Java Swing components, containers, layout managers, and event-handling mechanisms.

---

## 4. Technologies Used

| Technology | Category | Role in CyberShield |
|---|---|---|
| **Java 17+** | Core Programming Language | Implements domain models, business logic, security hashing, and server. |
| **Java Swing** | Desktop GUI Library | Provides cross-platform desktop UI (`JFrame`, `JTable`, `JTree`, etc.). |
| **com.sun.net.httpserver** | Web & API Server | Built-in JDK HTTP server serving REST endpoints and web assets. |
| **SQLite & JDBC** | Relational Database | File-based persistent storage (`data/cybershield.db`) using JDBC prepared statements. |
| **Google Gson** | JSON Serialization | Converts Java objects to/from JSON strings for API data interchange. |
| **HTML5 / CSS3 / Vanilla JS**| Web Frontend | Clean Dark SOC themed web dashboard with zero framework bloat. |
| **Apache Maven** | Build & Packaging Tool | Compiles source files and packages dependencies into a standalone fat JAR. |

---

## 5. Architecture Overview

CyberShield follows a clean **N-Tier Layered Architecture**:

```
+-------------------------------------------------------------------------+
|                              CLIENT TIER                                |
|   [Web Browser Client (HTML/CSS/JS)]    [Java Swing Desktop Client GUI] |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                           PRESENTATION / API TIER                       |
|   StaticFileHandler (serves /)   |   ApiHandler (serves /api/*)         |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                             BUSINESS SERVICE TIER                       |
|   UserService  |  IncidentService  |  AccessEventService  |  DashService |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                           SECURITY & UTILITY TIER                       |
|   PasswordUtils (Salted SHA-256)   |   SessionManager (Token Tracking)  |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                           PERSISTENCE / DATABASE TIER                   |
|   DatabaseManager (JDBC + PreparedStatements + WAL Concurrency)         |
|   SQLite Database File: data/cybershield.db                             |
+-------------------------------------------------------------------------+
```

---

## 6. Folder and File Explanations

1. `cybershield.Main`: Bootstrap entry point. Parses CLI flags (`--server-only`, `--gui-only`), initializes database, starts HTTP server, and launches Swing GUI on Event Dispatch Thread (EDT).
2. `cybershield.model`: Encapsulates database records into strongly-typed Java POJOs (`User`, `Incident`, `AccessEvent`, `ActivityLog`, `DashboardStats`).
3. `cybershield.security`:
   * `PasswordUtils.java`: Cryptographically secure salting using `SecureRandom` and SHA-256 password hashing.
   * `SessionManager.java`: In-memory session token generator (`UUID`) and role validator.
4. `cybershield.database`:
   * `DatabaseManager.java`: Initializes tables idempotently, enables SQLite WAL mode, and seeds default accounts and sample incidents.
5. `cybershield.service`:
   * `UserService.java`: Authenticates credentials and logs login events.
   * `IncidentService.java`: Executes parameterized SQL CRUD queries for incidents.
   * `AccessEventService.java`: Records failed logins and generates simulated brute-force events.
   * `ActivityLogService.java`: Appends audit logs for compliance tracking.
   * `DashboardService.java`: Runs SQL aggregation queries (`COUNT`, `WHERE`) to produce KPI stats.
6. `cybershield.server`:
   * `HttpServerManager.java`: Creates and manages the embedded `HttpServer` on port 8080.
   * `ApiHandler.java`: Routes REST requests (`/api/auth/*`, `/api/incidents/*`, etc.) and handles JSON serialization.
   * `StaticFileHandler.java`: Serves static web frontend assets (`web/`) with MIME type detection.
7. `cybershield.ui`:
   * `SwingTheme.java`: Central design palette (Dark Navy SOC colors, fonts, button styling).
   * `ApiClient.java`: Desktop abstraction layer accessing business services and database.
   * `LoginFrame.java`: Dedicated authentication window featuring password visibility toggle and quick-demo buttons.
   * `MainFrame.java`: Main frame holding `JMenuBar`, `JToolBar`, `JTabbedPane`, and live timer status bar.
   * `DashboardPanel.java`: Real-time KPI cards (`GridLayout`) and dual split tables (`JSplitPane`).
   * `IncidentPanel.java`: Incident `JTable`, filtering, modal `JDialog` for Add/Edit, and Admin-only deletion.
   * `AccessMonitoringPanel.java`: Security access telemetry and threat simulation button.
   * `ActivityHistoryPanel.java`: Audit trail viewer for compliance forensic checks.
   * `ComponentLabPanel.java`: Comprehensive viva laboratory demonstrating 40+ Swing components.
   * `AboutPanel.java`: Course info, architecture summary, and editable team member placeholders.
8. `web/`: HTML, CSS, and Vanilla JavaScript single-page application dashboard.
9. `data/`: Houses the persistent SQLite database file `cybershield.db`.

---

## 7. Program Execution Flow

1. User executes `run.bat` or `java -jar target/cybershield-1.0.0-jar-with-dependencies.jar`.
2. JVM enters `cybershield.Main.main(String[] args)`.
3. `DatabaseManager.initialize()` ensures `data/` exists, connects to SQLite via JDBC, executes `CREATE TABLE IF NOT EXISTS`, and seeds demo data if tables are empty.
4. `HttpServerManager.getInstance().start(8080)` binds port 8080, registers `/api` and `/` handlers, and starts an 8-thread executor pool.
5. `SwingUtilities.invokeLater()` posts `LoginFrame` construction to Swing's **Event Dispatch Thread (EDT)**.
6. `LoginFrame` is made visible with `toFront()` and `requestFocus()`.
7. Once credentials are submitted, `UserService` checks the password hash. On success, `MainFrame` opens and `LoginFrame` is disposed.

---

## 8. Login Process

```
[User Input] --> Username & Password
                     |
                     v
             [Retrieve User from DB by Username]
                     |
         +-----------+-----------+
         |                       |
    [User Not Found]       [User Found]
         |                       |
         v                       v
[Log Failed Access Event]   [Extract Stored Salt]
[Return 401 Unauthorized]        |
                                 v
                     [Hash Input with Salt using SHA-256]
                                 |
                     +-----------+-----------+
                     |                       |
              [Hashes Match?]         [Hashes Differ]
                     |                       |
                     v                       v
           [Create Session Token]   [Log Failed Access Event]
           [Log User Login]         [Return 401 Unauthorized]
           [Return Token & Role]
```

---

## 9. Database Design

CyberShield uses SQLite with 4 normalized relational tables:

### Table 1: `users`
* `id` INTEGER PRIMARY KEY AUTOINCREMENT
* `username` TEXT UNIQUE NOT NULL
* `password_hash` TEXT NOT NULL (Format: `salt:sha256hex`)
* `role` TEXT NOT NULL (`ADMIN` or `ANALYST`)
* `created_at` TEXT NOT NULL

### Table 2: `incidents`
* `id` INTEGER PRIMARY KEY AUTOINCREMENT
* `title` TEXT NOT NULL
* `description` TEXT
* `severity` TEXT NOT NULL (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
* `status` TEXT NOT NULL (`OPEN`, `INVESTIGATING`, `RESOLVED`, `CLOSED`)
* `created_by` TEXT NOT NULL
* `created_at` TEXT NOT NULL
* `updated_at` TEXT NOT NULL

### Table 3: `access_events`
* `id` INTEGER PRIMARY KEY AUTOINCREMENT
* `attempted_username` TEXT NOT NULL
* `source` TEXT NOT NULL (IP or client identifier)
* `event_type` TEXT NOT NULL (`LOGIN_ATTEMPT`, `BRUTE_FORCE_SIM`, etc.)
* `result` TEXT NOT NULL (`SUCCESS`, `FAILED`, `BLOCKED`)
* `created_at` TEXT NOT NULL

### Table 4: `activity_log`
* `id` INTEGER PRIMARY KEY AUTOINCREMENT
* `username` TEXT NOT NULL
* `action` TEXT NOT NULL (`USER_LOGIN`, `INCIDENT_CREATED`, etc.)
* `details` TEXT NOT NULL
* `created_at` TEXT NOT NULL

---

## 10. CRUD Operations
CRUD (Create, Read, Update, Delete) is implemented for incidents in `IncidentService.java`:

* **Create (INSERT):**
  ```sql
  INSERT INTO incidents (title, description, severity, status, created_by, created_at, updated_at) 
  VALUES (?, ?, ?, ?, ?, ?, ?);
  ```
  Extracts generated key with `statement.getGeneratedKeys()`.
* **Read (SELECT):**
  ```sql
  SELECT * FROM incidents WHERE 1=1 AND (title LIKE ? OR description LIKE ?) AND severity = ? AND status = ? 
  ORDER BY id DESC;
  ```
* **Update (UPDATE):**
  ```sql
  UPDATE incidents SET title = ?, description = ?, severity = ?, status = ?, updated_at = ? WHERE id = ?;
  ```
* **Delete (DELETE):**
  ```sql
  DELETE FROM incidents WHERE id = ?;
  ```
  *Protected by role validation:* Checked in both `ApiClient.java` and `ApiHandler.java`. Only `ADMIN` role is allowed to delete.

---

## 11. Backend Endpoints
* `POST /api/auth/login`: Authenticates username & password.
* `POST /api/auth/logout`: Invalidates session token.
* `GET  /api/dashboard/stats`: Returns live count metrics and recent incident/activity lists.
* `GET  /api/incidents`: Retrieves incidents (supports `q`, `severity`, `status` filters).
* `POST /api/incidents`: Creates a new incident.
* `PUT  /api/incidents/{id}`: Updates existing incident.
* `DELETE /api/incidents/{id}`: Deletes incident (enforces Admin role).
* `GET  /api/access-events`: Returns intrusion attempts and failed logins.
* `POST /api/access-events/simulate`: Injects a simulated brute-force threat event.
* `GET  /api/activity`: Returns chronological audit records.

---

## 12. Frontend-Backend Communication
* **Data Format:** All requests and responses use **JSON** formatted payloads.
* **HTTP Methods:** Adheres to RESTful conventions (`GET`, `POST`, `PUT`, `DELETE`).
* **Headers:** Responses set `Content-Type: application/json; charset=UTF-8`. Protected endpoints inspect `Authorization: Bearer <token>`.
* **Asynchronous Fetch (Web):** The web application uses the modern JavaScript `fetch()` API with `async/await`.
* **Desktop Synchronization:** The Java Swing client uses the `ApiClient` singleton to access the shared service layer and SQLite database, ensuring both Web and Desktop display identical data in real time.

---

## 13. Swing GUI Architecture
* **Event Dispatch Thread (EDT):** All GUI components are instantiated and modified exclusively on Swing's EDT using `SwingUtilities.invokeLater(...)`.
* **Model-View Separation:** Tables utilize `DefaultTableModel`, trees use `DefaultMutableTreeNode`, and spinners use `SpinnerNumberModel`.
* **Window Hierarchy:**
  * Top-level windows: `JFrame` (`MainFrame`, `LoginFrame`).
  * Modal secondary windows: `JDialog` (Add/Edit incident modal with `ModalityType.APPLICATION_MODAL`).
  * Lightweight windows: `JWindow` (Toast notifications).
  * Internal windows: `JInternalFrame` inside `JDesktopPane` (MDI architecture).

---

## 14. Explanations of Swing Components Implemented
* `JFrame`: Main desktop window container (`MainFrame`, `LoginFrame`).
* `JPanel`: Base container for grouping components and nesting layouts.
* `JDialog`: Modal popup for creating and editing incidents.
* `JWindow`: Borderless overlay window for auto-dismissing toast alerts.
* `JScrollPane`: Provides scrollable viewports for tables and multi-line text areas.
* `JSplitPane`: Divides two panels (e.g., Tree + Details, Incidents + Activity) with a draggable splitter.
* `JTabbedPane`: Organizes application views into switchable tabs.
* `JDesktopPane` & `JInternalFrame`: Implements a classic Multi-Document Interface (MDI) allowing draggable sub-windows.
* `JLabel`: Displays text titles, metric numbers, and icons.
* `JTextField`: Single-line text input for usernames and search queries.
* `JPasswordField`: Masks input characters for password entry.
* `JTextArea`: Multi-line plain text editing for descriptions and raw logs.
* `JTextPane`: Displays rich, formatted styled text and forensic reports.
* `JEditorPane`: Renders HTML security bulletins.
* `JFormattedTextField`: Enforces date format validation (`SimpleDateFormat`).
* `JButton`: Standard clickable action buttons.
* `JToggleButton`: Two-state toggle button for sensor activation.
* `JCheckBox`: Independent option toggles for telemetry settings.
* `JRadioButton` & `ButtonGroup`: Mutually exclusive option selection for firewall modes.
* `JComboBox`: Dropdown selection for severity and status filters.
* `JList`: Vertical selectable list for blacklisted IP addresses.
* `JSpinner`: Numerical spin control for port and retry selections.
* `JTable`: Multi-column tabular data rendering with `DefaultTableModel`.
* `JTree`: Hierarchical node view displaying MITRE ATT&CK and NIST frameworks.
* `JMenuBar`, `JMenu`, `JMenuItem`: Application menu bar navigation.
* `JPopupMenu`: Right-click context menu attached to tree nodes.
* `JToolBar`: Clickable quick-action toolbar.
* `JProgressBar`: Determinate and indeterminate visual progress bars.
* `JSlider`: Draggable value slider adjusting sensitivity thresholds.
* `JSeparator`: Visual horizontal divider line.
* `JOptionPane`: Pre-built dialogs for alerts, confirmations, and user input.
* `JFileChooser`: Native file browser for saving exported forensic reports.
* `JColorChooser`: Color palette picker for dynamic UI accent selection.
* `InputMap` & `ActionMap`: Binds keyboard shortcuts (e.g., `Ctrl+S`).

---

## 15. Layout Managers and Event Listeners
* `BorderLayout`: Arranges components in 5 regions (North, South, East, West, Center). Used in `MainFrame` and primary panels.
* `FlowLayout`: Arranges components in a natural line (left-to-right). Used for toolbars and button rows.
* `GridLayout`: Arranges components in an equal-sized matrix of rows and columns. Used in KPI metric cards.
* `GridBagLayout`: Advanced, flexible grid supporting cell spanning (`gridwidth`), weights (`weightx`, `weighty`), and insets. Used in forms and dialogs.
* `BoxLayout`: Arranges components linearly along the X or Y axis.
* `CardLayout`: Stacks panels like a deck of cards, allowing wizard-like next/previous transitions.
* `GroupLayout`: Programmatically groups components horizontally and vertically.
* **Event Listeners:**
  * `ActionListener`: Handles button clicks and combo box selections (`e -> ...`).
  * `ItemListener`: Detects checkbox and toggle button state changes.
  * `ChangeListener`: Detects slider value dragging.
  * `TreeSelectionListener`: Detects tree node clicks.
  * `MouseListener` / `MouseAdapter`: Detects right-clicks for context popups (`isPopupTrigger()`).

---

## 16. Session and Role-Based Authorization
* **Session Tokens:** Upon valid login, a unique `UUID` string is generated in `SessionManager`. Tokens expire after 4 hours of inactivity.
* **Roles:**
  * `ADMIN`: Full administrative privileges, including record deletion and audit trail reviews.
  * `ANALYST`: Incident investigation, reporting, and threat simulation.
* **Enforcement:**
  * Both the desktop client (`ApiClient.deleteIncident`) and the REST API (`ApiHandler.handleDeleteIncident`) enforce that only users with the `ADMIN` role can execute delete operations.
  * Attempting deletion as an analyst returns HTTP `403 Forbidden` on the backend and displays an authorization warning dialog in Swing.

---

## 17. Error Handling
* **Input Validation:** Required fields (e.g., incident title) are verified before submission.
* **Parameterized SQL:** All queries use `PreparedStatement` to eliminate SQL injection vulnerabilities.
* **HTTP Status Codes:** Proper status codes are returned (200 OK, 201 Created, 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found, 500 Internal Error).
* **Graceful Desktop Dialogs:** GUI catches exceptions and displays helpful `JOptionPane.showMessageDialog` error messages instead of crashing or silently failing.

---

## 18. Project Limitations
* **Local Storage Scope:** SQLite is designed for single-host or local workgroup concurrency; for enterprise scale (millions of daily logs), a distributed DBMS like PostgreSQL would be preferred.
* **In-Memory Session Storage:** Active session tokens are retained in memory; restarting the backend clears active web sessions (though user records remain permanently stored in SQLite).
* **Simulated Telemetry:** Intrusion attempts and threat feeds are generated synthetically for academic demonstration rather than capturing live hardware packets from physical network cards.
