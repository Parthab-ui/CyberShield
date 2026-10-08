# CyberShield — Cybersecurity Threat Monitoring & Incident Response

An Advanced Object-Oriented Programming (AOOP) course capstone project.  
Built with **Java 17**, **Swing**, and **Plain JDBC** (Zero Frameworks).

---

## ⚡ Quick Start (Zero Manual Setup Required)

CyberShield features an **Automatic Database & Schema Engine**.  
You **do NOT need** to open MySQL Workbench, manually execute `schema.sql`, or hard-code passwords into Java files.

### 1. Compile the Project
```bash
javac -cp "lib/*" -d out src/cybershield/model/*.java src/cybershield/util/*.java src/cybershield/dao/*.java src/cybershield/gui/*.java src/cybershield/Main.java
```

### 2. Run the Application
```bash
# Windows
java -cp "out;lib/*" cybershield.Main

# macOS / Linux
java -cp "out:lib/*" cybershield.Main
```

### 3. Log In
- **Username:** `admin`
- **Password:** `admin123`
- **Role:** `ADMIN`

*(Analyst account: `analyst` / `analyst123`)*

---

## 🏗️ Architecture & Database Auto-Configuration

The application automatically initializes its database upon startup using `cybershield.util.DatabaseInitializer` and `cybershield.util.DBConnection`:

1. **Dual-Mode Resilient Database:**
   - **Auto Mode (Default):** Checks if MySQL is reachable at `localhost:3306`. If connected, it automatically runs `CREATE DATABASE IF NOT EXISTS cybershield_db` and connects.
   - **Zero-Setup Embedded Fallback:** If MySQL is not running or access is denied, CyberShield seamlessly activates an embedded persistent database engine (`./data/cybershield`) without crashing or requiring any manual setup.
2. **Automatic Idempotent Schema Creation:**
   - Automatically executes the equivalent of `schema.sql` (`users`, `threats`, `incidents`, `blocked_ips`, `logs`).
   - Seeds the default admin account and realistic sample data only when tables are first created.
   - Fully idempotent and non-destructive: existing user records and password changes are preserved across restarts.
3. **External Configuration:**
   - Optional database credentials can be configured in `config/db.properties` or environment variables (`CYBERSHIELD_DB_URL`, `CYBERSHIELD_DB_USER`, `CYBERSHIELD_DB_PASS`) without touching Java source code.

---

## 📁 Project Structure

```text
cybershield/
├── config/
│   └── db.properties             ← Centralized database configuration
├── lib/
│   ├── mysql-connector-j-8.4.0.jar ← MySQL JDBC driver
│   └── h2-2.3.232.jar             ← Embedded database driver
├── out/                          ← Compiled bytecode classes
├── src/cybershield/
│   ├── Main.java                 ← Application entry point & preflight init
│   ├── gui/                      ← Swing UI components (Frames, Dialogs, Panels)
│   ├── model/                    ← Domain entities (User, Threat, Incident, BlockedIP, LogEntry)
│   ├── dao/                      ← Data Access Objects (Plain JDBC)
│   └── util/                     ← DatabaseInitializer, DBConnection, Theme, Validator
├── schema.sql                    ← Reference SQL schema specification
├── README.md                     ← Project documentation
└── VIVA_NOTES.md                 ← Viva examination preparation guide
```

---

## 🎓 Core AOOP Concepts Demonstrated

| Concept | Implementation in CyberShield |
| :--- | :--- |
| **Encapsulation** | Private entity fields with typed getters and setters across all model classes. |
| **Inheritance** | `MainFrame extends JFrame`, dialogs extending `JDialog`, all feature panels extending `BasePanel`. |
| **Polymorphism** | `GenericDAO<T>` interface implementations (`ThreatDAO`, `IncidentDAO`, `LogDAO`, `BlockedIPDAO`). |
| **Abstraction** | Separation of UI Presentation (`gui`), Business logic (`util`), and Storage Layer (`dao`). |
| **Multithreading** | Responsive UI execution with `SwingWorker` and `javax.swing.Timer` for live threat feeds. |
| **Resilience** | Automatic database fallback and dynamic schema verification preventing runtime failures. |
