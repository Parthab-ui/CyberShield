# CyberShield — Cybersecurity Threat Monitoring & Incident Response

A college project for the **Advanced Object-Oriented Programming (AOOP)** course.  
Built with **Java 17**, **Swing**, and **MySQL** (plain JDBC, no frameworks).

---

## Folder Structure

```
cybershield/
├── lib/                          ← Place mysql-connector-j-X.X.X.jar here
│   └── README.txt
├── out/                          ← Compiled .class files go here (created by javac)
├── src/
│   └── cybershield/
│       ├── Main.java             ← Entry point
│       ├── gui/
│       │   ├── BasePanel.java    ← Abstract panel (abstraction)
│       │   ├── MainFrame.java    ← Main window (inheritance from JFrame)
│       │   ├── DashboardPanel.java
│       │   ├── ThreatMonitorPanel.java
│       │   ├── IncidentsPanel.java
│       │   ├── ReportsPanel.java
│       │   └── SettingsPanel.java
│       ├── model/
│       │   ├── User.java
│       │   ├── Threat.java
│       │   ├── Incident.java
│       │   ├── BlockedIP.java
│       │   └── LogEntry.java
│       ├── dao/
│       │   ├── GenericDAO.java   ← Interface (abstraction)
│       │   ├── UserDAO.java
│       │   ├── ThreatDAO.java
│       │   ├── IncidentDAO.java
│       │   ├── BlockedIPDAO.java
│       │   └── LogDAO.java
│       └── util/
│           ├── DBConnection.java ← Singleton DB connection
│           ├── Theme.java        ← UI colors, fonts, styling
│           └── Validator.java    ← Input validation helpers
├── schema.sql                    ← MySQL database setup script
├── README.md                     ← This file
└── VIVA_NOTES.md                 ← Viva preparation guide
```

---

## Step-by-Step Run Instructions

### Prerequisites

- **Java JDK 17** (or later) installed → verify with `java -version`
- **MySQL 8.x** installed and running → verify with `mysql --version`

### Step 1 — Download the MySQL JDBC Driver

1. Go to https://dev.mysql.com/downloads/connector/j/
2. Select **Platform Independent** → Download the **.zip** file.
3. Extract it. Find the file named something like `mysql-connector-j-9.1.0.jar`.
4. Copy that `.jar` file into the `lib/` folder of this project.

### Step 2 — Create the Database

Open a terminal / command prompt and run:

```bash
mysql -u root -p < schema.sql
```

Or open MySQL Workbench, paste the contents of `schema.sql`, and execute it.

This creates the `cybershield_db` database with all tables and sample data.

### Step 3 — Edit Database Credentials (if needed)

Open `src/cybershield/util/DBConnection.java` and edit the three constants at the top:

```java
private static final String URL      = "jdbc:mysql://localhost:3306/cybershield_db";
private static final String USER     = "root";
private static final String PASSWORD = "";   // ← put your MySQL password here
```

### Step 4 — Test the Database Connection

```bash
# From the project root folder:

# Compile just the connection test class
javac -cp "lib/*" -d out src/cybershield/util/DBConnection.java

# Run the test
java -cp "out;lib/*" cybershield.util.DBConnection
```

You should see: `SUCCESS: Connected to cybershield_db!`

> **Note (macOS/Linux):** Replace `;` with `:` in the classpath, e.g. `"out:lib/*"`

### Step 5 — Compile the Full Project

```bash
javac -cp "lib/*" -d out src/cybershield/util/*.java src/cybershield/model/*.java src/cybershield/dao/*.java src/cybershield/gui/*.java src/cybershield/Main.java
```

### Step 6 — Run the Application

```bash
java -cp "out;lib/*" cybershield.Main
```

The CyberShield main window should appear, centered on your screen, with the dark theme and five placeholder tabs.

---

## For Team Members

Each team member should:
1. Pull this foundation code.
2. Create their own panel class that **extends `BasePanel`**.
3. Implement `refreshData()` to load data from the database using the DAO classes.
4. Replace the placeholder panel in `MainFrame.java`'s `createTabbedPane()` method.
5. **Never put SQL in GUI classes** — always use the DAO layer.

---

## OOP Concepts Used

| Concept         | Where                                              |
|-----------------|-----------------------------------------------------|
| Encapsulation   | All model classes (private fields + getters/setters)|
| Inheritance     | `MainFrame extends JFrame`, all panels `extends BasePanel` |
| Polymorphism    | `ActionListener.actionPerformed()`, `GenericDAO` implementations |
| Abstraction     | `GenericDAO<T>` interface, `BasePanel` abstract class |
