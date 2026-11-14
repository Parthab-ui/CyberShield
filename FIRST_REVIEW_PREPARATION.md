# CyberShield — First Review Preparation & Faculty Viva Handbook

> **Project:** CyberShield — Cybersecurity Monitoring and Incident Management System  
> **Course:** 2nd-Year B.Tech Computer Science & Engineering (CSE)  
> **Evaluation Focus:** Object-Oriented Software Engineering, Java Swing GUI, JDBC, REST Architecture, and Code Walkthrough.

---

## Part 1: Comprehensive Java Swing Component Inventory

This table maps every Java Swing component implemented in the CyberShield codebase, the exact source file where it is implemented, and its practical purpose.

| # | Swing Component / Class | Source File Location | Purpose & Implementation in CyberShield |
|---|---|---|---|
| 1 | `JFrame` | `MainFrame.java`, `LoginFrame.java` | Main application top-level window frames. |
| 2 | `JPanel` | All UI classes | Primary container used for layouts, card blocks, and panels. |
| 3 | `JDialog` | `IncidentPanel.java`, `ComponentLabPanel.java` | Modal windows for logging/updating incidents and custom policy prompts. |
| 4 | `JWindow` | `ComponentLabPanel.java` | Borderless overlay window for auto-dismissing toast notifications. |
| 5 | `JScrollPane` | All UI classes | Provides scrollable viewports for tables, text areas, and trees. |
| 6 | `JSplitPane` | `DashboardPanel.java`, `ComponentLabPanel.java` | Divides dual views (e.g., Tree + Details, Incident Table + Activity Feed). |
| 7 | `JTabbedPane` | `MainFrame.java`, `ComponentLabPanel.java` | Tabbed navigation for main application sections and component lab tabs. |
| 8 | `JDesktopPane` | `ComponentLabPanel.java` | Virtual desktop area hosting multiple internal MDI child windows. |
| 9 | `JInternalFrame` | `ComponentLabPanel.java` | Movable, resizable, iconifiable sub-windows (Packet Sniffer, IDS Status). |
| 10 | `JLabel` | All UI classes | Displays metric counters, titles, field labels, and status bar text. |
| 11 | `JTextField` | `LoginFrame.java`, `IncidentPanel.java`, `ComponentLabPanel.java` | Single-line text input for usernames, search filters, and IP addresses. |
| 12 | `JPasswordField` | `LoginFrame.java`, `ComponentLabPanel.java` | Masks input characters for password and API secret key entry. |
| 13 | `JTextArea` | `IncidentPanel.java`, `AboutPanel.java`, `ComponentLabPanel.java` | Multi-line text input/display for incident descriptions and raw logs. |
| 14 | `JTextPane` | `ComponentLabPanel.java` | Styled text component rendering rich HTML forensic threat reports. |
| 15 | `JEditorPane` | `ComponentLabPanel.java` | Displays formatted HTML NIST security bulletin documentation. |
| 16 | `JFormattedTextField` | `ComponentLabPanel.java` | Text field enforcing `SimpleDateFormat` date formatting rules. |
| 17 | `JButton` | All UI classes | Triggers actions (Login, Save, Delete, Refresh, Simulate Threat, etc.). |
| 18 | `JToggleButton` | `ComponentLabPanel.java` | Two-state toggle button switching sensor state between ACTIVE and OFFLINE. |
| 19 | `JCheckBox` | `LoginFrame.java`, `ComponentLabPanel.java` | Checkbox for revealing passwords and toggling audit/telemetry flags. |
| 20 | `JRadioButton` | `ComponentLabPanel.java` | Mutually exclusive radio buttons selecting firewall operational modes. |
| 21 | `ButtonGroup` | `ComponentLabPanel.java` | Groups radio buttons so only one can be selected at a time. |
| 22 | `JComboBox` | `IncidentPanel.java`, `ComponentLabPanel.java` | Dropdown selector for filtering severity and status categories. |
| 23 | `JList` | `ComponentLabPanel.java` | Selectable vertical list showing blacklisted external IP addresses. |
| 24 | `JSpinner` | `ComponentLabPanel.java` | Numerical spinner with `SpinnerNumberModel` selecting network ports. |
| 25 | `JTable` | `DashboardPanel.java`, `IncidentPanel.java`, `AccessMonitoringPanel.java`, `ActivityHistoryPanel.java` | Multi-column table rendering incident records, access telemetry, and audit logs. |
| 26 | `DefaultTableModel` | `DashboardPanel.java`, `IncidentPanel.java`, `AccessMonitoringPanel.java`, `ActivityHistoryPanel.java` | Data model providing row/column manipulation for `JTable`. |
| 27 | `TableCellRenderer` | `IncidentPanel.java`, `AccessMonitoringPanel.java` | Custom cell renderer coloring badges based on severity and outcome. |
| 28 | `JTree` | `ComponentLabPanel.java` | Hierarchical node tree displaying MITRE ATT&CK & NIST CSF categories. |
| 29 | `DefaultMutableTreeNode` | `ComponentLabPanel.java` | Data model node representing tree branch items and leaves. |
| 30 | `JMenuBar` | `MainFrame.java` | Top-level application menu bar container. |
| 31 | `JMenu` | `MainFrame.java` | Dropdown menus (File, Navigation, Security Operations, Help). |
| 32 | `JMenuItem` | `MainFrame.java`, `ComponentLabPanel.java` | Clickable menu options triggering panel navigation and operations. |
| 33 | `JPopupMenu` | `ComponentLabPanel.java` | Right-click context popup menu attached to tree items. |
| 34 | `JToolBar` | `MainFrame.java`, `ComponentLabPanel.java` | Quick-access toolbars with clickable operational shortcuts. |
| 35 | `JProgressBar` | `ComponentLabPanel.java` | Determinate animated scan progress bar and indeterminate hunting bar. |
| 36 | `JSlider` | `ComponentLabPanel.java` | Draggable horizontal slider adjusting IDS heuristic sensitivity percentage. |
| 37 | `JSeparator` | `MainFrame.java`, `ComponentLabPanel.java` | Horizontal divider line visually grouping related controls. |
| 38 | `JOptionPane` | All UI classes | Standardized popups (Message, Confirm, Input dialogs for CRUD and alerts). |
| 39 | `JFileChooser` | `ComponentLabPanel.java` | System file browser allowing user to export forensic reports to a text file. |
| 40 | `JColorChooser` | `ComponentLabPanel.java` | Color picker palette enabling custom UI accent selection. |
| 41 | `InputMap` & `ActionMap` | `ComponentLabPanel.java` | Binds window keyboard shortcuts (`Ctrl + S`) to program actions. |
| 42 | `BorderLayout` | `MainFrame.java`, `IncidentPanel.java`, `DashboardPanel.java`, etc. | 5-region layout manager (North, South, East, West, Center). |
| 43 | `FlowLayout` | `LoginFrame.java`, `IncidentPanel.java`, `MainFrame.java` | Left-to-right linear layout for action buttons and toolbars. |
| 44 | `GridLayout` | `DashboardPanel.java`, `AboutPanel.java`, `ComponentLabPanel.java` | Matrix grid layout used for responsive KPI metric cards. |
| 45 | `GridBagLayout` | `LoginFrame.java`, `IncidentPanel.java`, `ComponentLabPanel.java` | Flexible constraint-based grid layout used for forms and dialogs. |
| 46 | `BoxLayout` | `ComponentLabPanel.java` | Stacks components along a single axis (X or Y). |
| 47 | `CardLayout` | `ComponentLabPanel.java` | Stacks multiple panels with wizard-like next/previous transitions. |
| 48 | `GroupLayout` | `ComponentLabPanel.java` | Hierarchical programmatic grouping layout. |
| 49 | `javax.swing.Timer` | `MainFrame.java`, `ComponentLabPanel.java` | EDT-safe repeating timer driving live clock and scan animations. |

---

## Part 2: Step-by-Step Viva Demonstration Sequence

Follow this exact sequence to demonstrate the system to your faculty reviewers:

### Step 1: System Launch & Architecture Overview (1 Minute)
1. Open PowerShell or CMD and run `.\run.bat`.
2. Select **Option 1: START FULL SYSTEM**.
3. Point out the terminal output:
   * SQLite database verified at `data/cybershield.db`.
   * Embedded Web Server active on port 8080 (`http://localhost:8080/`).
   * Swing Desktop GUI launched on the Event Dispatch Thread (EDT).

### Step 2: Desktop Login & Visibility (1 Minute)
1. Show the `LoginFrame`. Explain the dark navy SOC theme (`SwingTheme.java`).
2. Show the **Show Password** checkbox (`JCheckBox` toggling echo character).
3. Click the **Fill Admin** button to populate `admin` / `Admin@123`.
4. Click **Sign In**. The `MainFrame` opens smoothly and `LoginFrame` closes.

### Step 3: Executive Dashboard & Live Sync (1 Minute)
1. Point out the 4 KPI cards: Total Incidents, Open Incidents, Critical Threats, Unauthorized Probes.
2. Explain that these values are dynamically computed via SQL aggregation (`COUNT`) from `cybershield.db`.
3. Open a browser window to `http://localhost:8080/`. Log in as `admin`.
4. Point out that the Web dashboard and Desktop dashboard show identical numbers.

### Step 4: Incident CRUD & Role-Based Authorization (2 Minutes)
1. In the Swing desktop interface, click the **Incidents** tab.
2. Click **+ New Incident** (`JButton` opens modal `JDialog`).
3. Enter:
   * Title: `Ransomware Test Alert`
   * Description: `Suspicious encryption activity detected in /shared/finance`
   * Severity: `CRITICAL`
   * Status: `OPEN`
4. Click **Save Incident**. Show that the table instantly updates and severity is highlighted in red.
5. Switch to the Web browser and refresh. The incident appears there immediately!
6. Explain Role-Based Access Control (RBAC):
   * Sign out of the desktop and log in as `analyst` (`Analyst@123`).
   * Select an incident and click **Delete Incident**.
   * Show the authorization rejection message: *Only Administrator role can delete incidents.*
   * Sign back in as `admin` and show successful deletion with `JOptionPane.showConfirmDialog`.

### Step 5: Unauthorized Access Telemetry & Threat Simulation (1 Minute)
1. Click the **Access Monitoring** tab in the desktop GUI.
2. Point out the table displaying failed login events.
3. Click the red **Simulate Intrusion Threat** button.
4. Show the dialog confirming the simulated brute-force threat event.
5. Show that the event is immediately saved to SQLite and appears in the table with a red `BLOCKED` badge.

### Step 6: Swing Component Lab Showcase (2 Minutes)
1. Click the **Swing Component Lab** tab. This is your primary college review centerpiece!
2. Tour the sub-tabs:
   * **Tab 1 (Forms & Inputs):** Show `JFormattedTextField` (Date), `JSpinner` (Port), `JToggleButton` (Sensor state), `JTextPane` (HTML forensics), `JList` (Blacklisted IPs).
   * **Tab 2 (JTree & SplitPane):** Show `JTree` displaying MITRE ATT&CK and NIST frameworks. Click a tree node to show live inspection details on the right. Right-click a node to show `JPopupMenu`.
   * **Tab 3 (Progress & Sliders):** Drag the `JSlider` to show the `JProgressBar` moving simultaneously. Click **Run Simulated 0-100% Scan** to show `javax.swing.Timer` animation.
   * **Tab 4 (MDI DesktopPane):** Show `JDesktopPane` and draggable `JInternalFrame` sub-windows (Packet Sniffer, IDS Status). Click **+ Spawn New JInternalFrame**.
   * **Tab 5 (Dialogs & Utilities):** Click **Export Forensic Report...** to demonstrate `JFileChooser`. Click **Select Custom UI Accent...** to demonstrate `JColorChooser`. Press `Ctrl + S` on the keyboard to trigger `InputMap`/`ActionMap` key binding.
   * **Tab 6 (Layout Managers):** Switch between the tabs to show `BorderLayout`, `FlowLayout`, `GridLayout`, `GridBagLayout`, `BoxLayout`, `CardLayout`, and `GroupLayout`.

### Step 7: System Audit Trail & About (1 Minute)
1. Click the **Activity History** tab to show chronological audit logging.
2. Click **About & Review** to show the project architecture and student team member placeholders.

---

## Part 3: 45 Faculty Viva Questions and Accurate Answers

### Section A: Core Java & Object-Oriented Programming (Questions 1–10)

#### Q1: What makes CyberShield an Object-Oriented application?
**Answer:** CyberShield applies all 4 OOP pillars:
1. **Encapsulation:** Domain models (`Incident`, `User`, `AccessEvent`) have private fields with public getters and setters.
2. **Abstraction:** Services (`IncidentService`, `UserService`) hide complex SQL queries behind simple method calls like `create()` and `authenticate()`.
3. **Inheritance:** Swing panels extend `JPanel` or `JFrame`, inheriting window handling and layout capabilities.
4. **Polymorphism:** Method overriding (such as custom `TableCellRenderer` overriding `getTableCellRendererComponent`) and interfaces (`ActionListener`).

#### Q2: Why did you choose SQLite over MySQL or PostgreSQL for this project?
**Answer:** SQLite is an embedded, zero-configuration database that stores all data in a single local file (`data/cybershield.db`). It requires no background database server daemon, eliminating external connection setup errors during college reviews while still providing full SQL syntax, ACID transactions, and JDBC support.

#### Q3: How do you prevent SQL Injection attacks in your code?
**Answer:** In `DatabaseManager.java`, `IncidentService.java`, and other services, we never concatenate raw strings into SQL statements. We strictly use JDBC `PreparedStatement` with parameterized placeholders (`?`). The database driver automatically escapes input parameters, neutralizing SQL injection payloads.

#### Q4: How is password security handled in the database?
**Answer:** Passwords are never stored in plaintext. In `PasswordUtils.java`, we generate a unique 16-byte cryptographically secure salt using `SecureRandom`, concatenate it with the user's password, and compute a SHA-256 hash. The database stores the combined string `salt:sha256hex`. During login, the stored salt is applied to the input password to verify the hash.

#### Q5: What is the Singleton design pattern and where is it used?
**Answer:** The Singleton pattern ensures a class has only one instance and provides a global access point to it. We use it in `ApiClient.getInstance()` and `HttpServerManager.getInstance()` so that components across the desktop application share a single coordinated communication and session manager.

#### Q6: How does the application maintain data consistency between Web and Swing clients?
**Answer:** Both the embedded HTTP backend and the Java Swing desktop application communicate with the same persistent SQLite database file (`data/cybershield.db`). Furthermore, SQLite is configured with Write-Ahead Logging (`PRAGMA journal_mode = WAL;`), which allows concurrent reads and writes without locking.

#### Q7: What collection types are used in CyberShield and why?
**Answer:** 
* `java.util.List` and `ArrayList`: Used for ordered dynamic collections of domain objects (`List<Incident>`).
* `java.util.Map` and `HashMap`: Used for key-value mappings such as query parameters in `ApiHandler.java` and in-memory session tokens in `SessionManager.java`.

#### Q8: How are exceptions handled in the application?
**Answer:** We use structured `try-catch-finally` and try-with-resources blocks. In the backend, exceptions return HTTP 400 or 500 JSON errors. In the desktop interface, caught exceptions are presented to the user through descriptive `JOptionPane.showMessageDialog` error alerts rather than crashing the program.

#### Q9: What is Try-With-Resources and where is it implemented?
**Answer:** Try-with-resources automatically closes resources implementing `java.lang.AutoCloseable` at the end of the block. We use it for JDBC `Connection`, `PreparedStatement`, `ResultSet`, and `BufferedReader` streams to prevent database connection leaks and memory exhaustion.

#### Q10: What version of Java is required and why?
**Answer:** CyberShield is built for Java 17+ (LTS). It takes advantage of modern Java features like enhanced switch expressions, `java.time` APIs, `readAllBytes()` on streams, and improved security defaults.

---

### Section B: Java Swing & Desktop GUI (Questions 11–25)

#### Q11: What is the Event Dispatch Thread (EDT) and why is it important?
**Answer:** Swing is single-threaded; all GUI component creation, rendering, and event handling must occur on a dedicated thread called the Event Dispatch Thread (EDT). Modifying Swing components from worker threads causes race conditions and UI freezing. We launch the GUI safely using `SwingUtilities.invokeLater(() -> ...)` in `Main.java`.

#### Q12: Why did you use `SwingUtilities.invokeLater` instead of calling `new LoginFrame().setVisible(true)` directly in `main`?
**Answer:** The `main` method runs on the JVM main thread, which is not the Event Dispatch Thread. `SwingUtilities.invokeLater` places the GUI initialization task into Swing's event queue so that the window is constructed and displayed safely on the EDT.

#### Q13: What is the difference between `JFrame` and `JDialog`?
**Answer:** A `JFrame` is a top-level primary application window with minimize, maximize, and close controls. A `JDialog` is a secondary window, typically modal (`ModalityType.APPLICATION_MODAL`), meaning it blocks user interaction with the parent frame until it is dismissed (e.g., the Add Incident dialog).

#### Q14: What is `JDesktopPane` and `JInternalFrame`?
**Answer:** They implement a Multi-Document Interface (MDI). `JDesktopPane` acts as a virtual desktop workspace container inside which multiple `JInternalFrame` child windows can be dragged, resized, minimized, or tiled (demonstrated in Lab 4 of `ComponentLabPanel.java`).

#### Q15: How does `JTable` display data from the database?
**Answer:** `JTable` uses a data model—specifically `DefaultTableModel`. In `IncidentPanel.java`, we define column names in the model. When data is retrieved from SQLite, we clear existing rows using `model.setRowCount(0)` and add each record as an array of objects via `model.addRow(new Object[]{ ... })`.

#### Q16: How did you achieve custom badge colors in `JTable` for Incident Severity?
**Answer:** By creating a custom `DefaultTableCellRenderer` and overriding `getTableCellRendererComponent`. Inside this method, we inspect the cell value (e.g., "CRITICAL", "HIGH") and dynamically set the foreground color using `SwingTheme.getSeverityColor(sev)` before returning the component.

#### Q17: What layout manager is used for the overall `MainFrame` and why?
**Answer:** `BorderLayout`. It arranges components into 5 intuitive regions: `NORTH` holds the `JToolBar`, `CENTER` holds the `JTabbedPane`, and `SOUTH` holds the status bar.

#### Q18: What is the difference between `GridLayout` and `GridBagLayout`?
**Answer:** `GridLayout` forces all cells to be of identical size in a uniform grid (used for the 4 KPI metric cards in `DashboardPanel.java`). `GridBagLayout` is much more flexible, allowing cells to span multiple rows or columns (`gridwidth`, `gridheight`) and assign specific expansion weights (`weightx`, `weighty`), which we use for complex dialog forms.

#### Q19: What is `CardLayout` and when is it useful?
**Answer:** `CardLayout` treats each child component as a card in a deck, displaying only one card at a time. It is ideal for wizard interfaces, multi-step configuration assistants, or swapping views without opening new windows (demonstrated in Lab 6 of `ComponentLabPanel.java`).

#### Q20: How does `JTree` organize hierarchical data?
**Answer:** `JTree` uses a tree model composed of `DefaultMutableTreeNode` instances. A root node is created, parent category nodes (e.g., "MITRE ATT&CK Framework") are added as children, and leaf technique nodes are added below parents. We attach a `TreeSelectionListener` to detect when a user clicks a node.

#### Q21: What is a `JPopupMenu` and how is it triggered?
**Answer:** `JPopupMenu` is a context menu that appears at the cursor location. In `ComponentLabPanel.java`, we attach a `MouseListener` to the tree and check `e.isPopupTrigger()` inside `mousePressed()` and `mouseReleased()` to display the menu at `popup.show(component, e.getX(), e.getY())`.

#### Q22: How does the live clock in the status bar update every second?
**Answer:** We use `javax.swing.Timer` initialized with a 1000-millisecond delay and an `ActionListener`. Every second, the timer fires on the EDT, formats the current date and time using `SimpleDateFormat`, and updates the text of `clockLabel`.

#### Q23: How do `InputMap` and `ActionMap` differ from standard `KeyListener`?
**Answer:** A `KeyListener` requires the specific component to have keyboard focus to receive keystrokes. `InputMap` and `ActionMap` bind key combinations (like `Ctrl+S`) at the window level (`WHEN_IN_FOCUSED_WINDOW`), so the shortcut triggers reliably regardless of which child component currently has focus.

#### Q24: What is the purpose of `JFileChooser` in CyberShield?
**Answer:** It provides a standard file system dialog that allows users to select a destination directory and filename to export forensic security incident reports to a text file on disk.

#### Q25: How did you ensure the `LoginFrame` is visibly shown on Windows?
**Answer:** In `LoginFrame.java`, we call:
1. `pack()` to calculate component sizes.
2. `setLocationRelativeTo(null)` to center the window on the active monitor.
3. `setVisible(true)`.
4. `setAlwaysOnTop(true)` briefly followed by `toFront()` and `requestFocus()` to ensure it breaks through background editor windows.

---

### Section C: Backend, Networking & REST API (Questions 26–35)

#### Q26: What web server technology is used in the backend?
**Answer:** We use Java's built-in `com.sun.net.httpserver.HttpServer`. It is part of the standard JDK, requires zero third-party framework overhead, and provides lightweight HTTP handling with custom context routing and thread pool execution.

#### Q27: How does `ApiHandler.java` route incoming HTTP requests?
**Answer:** In `handle(HttpExchange exchange)`, we inspect `exchange.getRequestURI().getPath()` and `exchange.getRequestMethod()`. Based on string matching (e.g., `/api/incidents` with `GET` vs. `POST`), execution is dispatched to modular helper methods like `handleGetIncidents()` or `handleCreateIncident()`.

#### Q28: How does the server handle concurrent requests?
**Answer:** In `HttpServerManager.java`, we configure a thread pool executor:
```java
server.setExecutor(Executors.newFixedThreadPool(8));
```
This allows the server to process up to 8 incoming HTTP requests concurrently across separate worker threads.

#### Q29: How are JSON requests parsed and responses formatted?
**Answer:** Using the Google Gson library. For inbound requests, we read the HTTP request body stream into a string and deserialize it using `gson.fromJson(body, TargetClass.class)`. For responses, we serialize Java objects with `gson.toJson(data)`, set the `Content-Type: application/json` header, and write the byte stream.

#### Q30: What HTTP status codes does the API return?
**Answer:**
* `200 OK`: Successful retrieval or update.
* `201 Created`: Successful creation of a new incident or event.
* `400 Bad Request`: Missing or invalid input data.
* `401 Unauthorized`: Missing or invalid credentials/session token.
* `403 Forbidden`: Authenticated user lacks permission (e.g., non-admin attempting deletion).
* `404 Not Found`: Requested resource ID does not exist.
* `500 Internal Server Error`: Unexpected server or SQL exception.

#### Q31: How are static web assets (HTML, CSS, JS) served?
**Answer:** `StaticFileHandler.java` listens on the root path `/`. It resolves the requested URI against the `web/` directory on disk, determines the appropriate MIME type (e.g., `text/html`, `text/css`, `application/javascript`), and streams the file bytes back in the HTTP response.

#### Q32: How is session-based authentication implemented?
**Answer:** When `/api/auth/login` receives valid credentials, `SessionManager.createSession(user)` generates a random `UUID` token and stores the user and creation timestamp in an in-memory concurrent map. The client includes this token in subsequent requests via the `Authorization: Bearer <token>` header.

#### Q33: How does the server enforce authorization checks?
**Answer:** Endpoints that modify data call `requireAuth(exchange)` to retrieve the authenticated user from the token. For delete operations (`handleDeleteIncident`), the handler checks `if (!user.isAdmin())` and immediately returns HTTP 403 Forbidden if the user's role is not `ADMIN`.

#### Q34: What happens if port 8080 is already in use on the computer?
**Answer:** In `HttpServerManager.java`, the server tests ports in a loop starting at 8080 up to 8090. If port 8080 is occupied, it catches the `IOException` and automatically binds to the next available port (e.g., 8081).

#### Q35: How does the Web frontend interact with the API?
**Answer:** The web application (`web/js/app.js`) is a Single Page Application (SPA) written in Vanilla JavaScript. It uses the standard `fetch()` API with `async/await` to send HTTP requests to `/api/...` endpoints and dynamically updates the DOM without full page reloads.

---

### Section D: Database & Security (Questions 36–45)

#### Q36: What is SQLite WAL mode and why did you enable it?
**Answer:** WAL stands for **Write-Ahead Logging**. In standard rollback journal mode, writing locks the entire database file, preventing concurrent reads. In WAL mode (`PRAGMA journal_mode = WAL;`), changes are appended to a separate WAL file, allowing concurrent readers (e.g., web requests and desktop queries) to read the database simultaneously while a write occurs.

#### Q37: What tables exist in the CyberShield database?
**Answer:** Four tables:
1. `users`: Stores user credentials, roles, and creation timestamps.
2. `incidents`: Stores security incidents, severities, statuses, and authors.
3. `access_events`: Stores unauthorized access telemetry and failed logins.
4. `activity_log`: Stores audit logs for compliance tracking.

#### Q38: How does the database initialize automatically on the first run?
**Answer:** `DatabaseManager.initialize()` executes SQL `CREATE TABLE IF NOT EXISTS` statements for each table. It then checks if the `users` table is empty; if so, it seeds the default `admin` and `analyst` accounts with pre-computed password hashes, along with starter incidents and activity logs.

#### Q39: How is an incident updated in the database?
**Answer:** When an update request is received, `IncidentService.update()` executes:
```sql
UPDATE incidents SET title = ?, description = ?, severity = ?, status = ?, updated_at = ? WHERE id = ?;
```
It binds the new values and current timestamp using a `PreparedStatement` and verifies that `executeUpdate() > 0`.

#### Q40: What happens when an unauthorized login attempt occurs?
**Answer:** When authentication fails in `UserService.authenticate()`, the system immediately logs a record into the `access_events` table with `event_type = 'LOGIN_ATTEMPT'` and `result = 'FAILED'`. This appears in real time on both the Web and Desktop access monitoring tables.

#### Q41: How does the Threat Simulation feature work?
**Answer:** The "Simulate Threat" button triggers `AccessEventService.simulateThreat()`. It generates an entry in the `access_events` table representing a brute-force SSH or HTTP attack from an external IP address (e.g., `198.51.100.12`), marked as `BLOCKED`. This demonstrates real-time incident detection and telemetry alerting during reviews.

#### Q42: What is the purpose of the `activity_log` table?
**Answer:** In cybersecurity frameworks (e.g., NIST, SOC 2), compliance requires an immutable audit trail. The `activity_log` table records every critical action (user login, logout, incident creation, incident update, and incident deletion) with a timestamp and the acting username for non-repudiation.

#### Q43: How does the frontend handle XSS (Cross-Site Scripting)?
**Answer:** In `web/js/app.js`, user-supplied strings (such as incident titles and descriptions) are inserted into the DOM using `textContent` or escaped before rendering, preventing malicious JavaScript injected via incident fields from executing in the browser.

#### Q44: Can a regular Security Analyst delete an incident from the database?
**Answer:** No. Deletion is restricted to the `ADMIN` role. If an analyst attempts to delete an incident via the desktop GUI, `ApiClient.deleteIncident()` throws a `SecurityException`. If an analyst attempts to delete via an API call, `ApiHandler` returns HTTP 403 Forbidden.

#### Q45: How do you explain the project if faculty asks you to change the code live?
**Answer:**
* **To add a new severity level:** Update the `SEVERITY` check in `DatabaseManager.java`, add the string to `Incident.java`, and add the option to the combo boxes in `IncidentPanel.java` and `web/index.html`.
* **To add a new database column:** Add the column to `CREATE TABLE` in `DatabaseManager.java`, add the field with getters/setters in `Incident.java`, and update the `PreparedStatement` mappings in `IncidentService.java`.
* **To adjust desktop theme colors:** Modify the constants in `SwingTheme.java` (e.g., change `BG_DARK` or `ACCENT_BLUE`). All panels automatically inherit the updated theme.
