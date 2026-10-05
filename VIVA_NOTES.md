# CyberShield — Viva Preparation Notes

---

## 1. One-Line Purpose of Every Class

| Class | Purpose |
|---|---|
| `Main` | Entry point — starts the application on the Event Dispatch Thread |
| `DBConnection` | Provides a singleton-style shared MySQL connection using JDBC |
| `Theme` | Stores all UI colors, fonts, and button/panel styling methods |
| `Validator` | Provides simple input validation (empty check, IP format, password length) |
| `User` | Model class representing a system user (admin or analyst) |
| `Threat` | Model class representing a detected cybersecurity threat |
| `Incident` | Model class representing an incident report linked to a threat |
| `BlockedIP` | Model class representing a blocked IP address |
| `LogEntry` | Model class representing one audit log record |
| `GenericDAO<T>` | Interface defining the five standard CRUD operations for any model |
| `UserDAO` | Handles all database operations for the users table |
| `ThreatDAO` | Handles all database operations for the threats table (implements GenericDAO) |
| `IncidentDAO` | Handles all database operations for the incidents table (implements GenericDAO) |
| `BlockedIPDAO` | Handles all database operations for the blocked_ips table (implements GenericDAO) |
| `LogDAO` | Handles all database operations for the logs table (implements GenericDAO) |
| `BasePanel` | Abstract JPanel with an abstract `refreshData()` method — every tab panel extends this |
| `MainFrame` | Main application window with menu bar, toolbar, tabbed pane, and status bar |
| `DashboardPanel` | Placeholder panel for the Dashboard tab (extends BasePanel) |
| `ThreatMonitorPanel` | Placeholder panel for the Threat Monitor tab (extends BasePanel) |
| `IncidentsPanel` | Placeholder panel for the Incidents tab (extends BasePanel) |
| `ReportsPanel` | Placeholder panel for the Reports tab (extends BasePanel) |
| `SettingsPanel` | Placeholder panel for the Settings tab (extends BasePanel) |

---

## 2. Where Each OOP Concept Is Used

### Encapsulation (Private fields + Getters/Setters)
- **All model classes** (`User`, `Threat`, `Incident`, `BlockedIP`, `LogEntry`):  
  Every field is `private`. Data is accessed only through `getXxx()` / `setXxx()` methods.  
  This protects the data from being changed directly from outside the class.
- **DBConnection**: The `connection` field and constructor are private. Access is only through `getConnection()`.

### Inheritance (extends)
- **`MainFrame extends JFrame`**: MainFrame IS-A JFrame, so it inherits all window functionality (title, size, close behavior) from JFrame.
- **All placeholder panels extend `BasePanel`** (e.g., `DashboardPanel extends BasePanel`), and `BasePanel extends JPanel`. This is a two-level inheritance chain.

### Polymorphism (same method name, different behavior)
- **`GenericDAO<T>` interface implemented by ThreatDAO, IncidentDAO, BlockedIPDAO, LogDAO**: Each class implements the same five methods (`add`, `update`, `delete`, `getById`, `getAll`) but writes different SQL for its specific table. If you call `dao.getAll()`, the behavior depends on which DAO object you are using — that is runtime polymorphism.
- **`BasePanel.refreshData()`**: This is an abstract method. `DashboardPanel`, `ThreatMonitorPanel`, etc. each override it with their own behavior. In `MainFrame.refreshAllTabs()`, we call `refreshData()` on each panel without knowing the exact subclass — that is polymorphism.
- **`ActionListener.actionPerformed()`**: Every button and menu item creates its own ActionListener with a different `actionPerformed()` body. Swing calls the same method name, but the behavior differs based on which listener is attached — that is polymorphism through interfaces.
- **`toString()` override**: Every model class overrides `Object.toString()` to return a human-readable string.

### Abstraction (hiding implementation details)
- **`GenericDAO<T>` interface**: The GUI layer calls `dao.getAll()` without knowing whether the data comes from MySQL, a file, or memory. The interface abstracts away the database implementation.
- **`BasePanel` abstract class**: Defines the contract (`refreshData()`) without providing an implementation. Each subclass decides how to refresh its own data.

---

## 3. Ten Likely Viva Questions with Answers

### Q1. What are the five steps to connect to a database using JDBC?
**Answer:**
1. **Load the driver** — In modern Java (JDBC 4+), this happens automatically when the JAR is on the classpath.
2. **Establish the connection** — `DriverManager.getConnection(url, user, password)`.
3. **Create a statement** — `connection.prepareStatement(sql)`.
4. **Execute the query** — `ps.executeQuery()` for SELECT, `ps.executeUpdate()` for INSERT/UPDATE/DELETE.
5. **Close the resources** — Close the ResultSet, PreparedStatement, and Connection (we use try-with-resources for this).

### Q2. What is the difference between Statement and PreparedStatement?
**Answer:**
- **Statement**: Executes plain SQL strings. Vulnerable to **SQL injection** because user input is concatenated directly into the query.
- **PreparedStatement**: Uses `?` placeholders. Values are set with `setString()`, `setInt()`, etc. The database **pre-compiles** the query, so user input is treated as data (not as SQL code). This prevents SQL injection and is also slightly faster for repeated queries.

### Q3. What is the DAO pattern and why do we use it?
**Answer:**  
DAO stands for **Data Access Object**. It is a design pattern that separates database logic (SQL queries) from business logic and GUI code. We use it because:
- **Separation of concerns**: SQL stays in DAO classes, not in GUI classes.
- **Easy to change**: If we switch from MySQL to another database, we only change the DAO classes.
- **Reusability**: Any part of the application can call `dao.getAll()` without knowing the SQL.

### Q4. Why is BasePanel abstract? Why not just a regular class?
**Answer:**  
`BasePanel` is abstract because it declares the `refreshData()` method without implementing it. Every module panel (Dashboard, Threats, Incidents, etc.) must implement `refreshData()` differently — each one loads different data from different tables. Making it abstract forces every subclass to provide its own implementation. You cannot create a `BasePanel` object directly because an "empty" refresh makes no sense.

### Q5. What does SwingUtilities.invokeLater() do and why is it necessary?
**Answer:**  
`invokeLater()` schedules a task (a `Runnable`) to run on the **Event Dispatch Thread (EDT)**. Swing is **not thread-safe** — all GUI updates must happen on the EDT. If we create the JFrame on the main thread, it could cause race conditions and unpredictable behavior. `invokeLater()` ensures the GUI is created and modified only on the EDT.

### Q6. What is the Event Dispatch Thread (EDT)?
**Answer:**  
The EDT is a special thread that Swing uses to process all GUI events (button clicks, key presses, repaints, etc.). Every event listener runs on the EDT. If you run a long operation on the EDT (like a slow database query), the entire GUI freezes because the EDT cannot process any other events until the operation finishes.

### Q7. What is encapsulation? Give an example from this project.
**Answer:**  
Encapsulation means hiding the internal data of a class and providing controlled access through public methods. In our project, every model class (like `User`) has `private` fields and `public` getters/setters. For example, `User.username` is private — you cannot write `user.username = "x"` from outside. You must use `user.setUsername("x")`. This protects the data and lets us add validation later without changing other code.

### Q8. What is polymorphism? Give two examples from this project.
**Answer:**  
Polymorphism means "one name, many forms" — the same method name does different things depending on the object.
1. **GenericDAO implementations**: `ThreatDAO.getAll()` and `IncidentDAO.getAll()` both implement the same interface method but run different SQL queries.
2. **ActionListener**: Each button's `actionPerformed()` method does something different (Exit, Refresh, Logout, About), but they all implement the same `ActionListener` interface.

### Q9. What is try-with-resources? Why do we use it in the DAO classes?
**Answer:**  
Try-with-resources is a Java feature (since Java 7) that automatically closes resources (like `Connection`, `PreparedStatement`, `ResultSet`) when the `try` block finishes, even if an exception occurs. We use it because:
- It prevents **resource leaks** (forgetting to close a connection).
- It is shorter and cleaner than manually writing `finally { conn.close(); }`.
- The resource must implement the `AutoCloseable` interface (JDBC classes do).

### Q10. Why do we use a Singleton pattern for DBConnection?
**Answer:**  
The Singleton pattern ensures only **one database connection** is shared across the entire application. Creating a new connection for every query is slow and wastes resources. With `DBConnection.getConnection()`, we reuse the same connection. The constructor is `private` so nobody can create a second `DBConnection` object. The `getConnection()` method checks if the connection already exists (or has been closed) and creates one only if needed.

---

## 4. Quick Glossary for the Viva

| Term | Meaning |
|---|---|
| JDBC | Java Database Connectivity — the Java API for connecting to databases |
| DriverManager | A class that manages JDBC drivers and creates connections |
| ResultSet | An object that holds the rows returned by a SELECT query |
| PreparedStatement | A pre-compiled SQL statement with `?` placeholders |
| try-with-resources | Automatically closes resources when the block ends |
| EDT | Event Dispatch Thread — the single thread Swing uses for all GUI work |
| Singleton | A pattern that restricts a class to only one instance |
| DAO | Data Access Object — a class that handles all SQL for one table |
| Abstract class | A class that cannot be instantiated; may contain abstract methods |
| Interface | A contract that defines method signatures without implementation |
| FK (Foreign Key) | A column that references the primary key of another table |
