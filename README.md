# CyberShield — Cybersecurity Monitoring and Incident Management System

> **Academic Project Edition:** Designed and structured specifically for **2nd-Year B.Tech Computer Science and Engineering (CSE)** College Review and Viva Evaluation.

---

## 1. Project Overview

**CyberShield** is a unified, lightweight cybersecurity monitoring and incident management system designed to showcase robust Object-Oriented Software Engineering, modern client-server communication, database persistence, and advanced Java Swing desktop GUI programming.

Unlike complex enterprise solutions, CyberShield is intentionally built without bloated third-party frameworks (no Spring Boot, React, Docker, or Kubernetes). It relies strictly on standard Java, lightweight embedded HTTP server APIs, vanilla web technologies, and standard Swing components that second-year students can easily explain and defend line-by-line during a faculty viva.

### Key Architecture Highlights
* **Dual-Interface Architecture:** Both a **modern Web Application** and a feature-rich **Java Swing Desktop GUI** interact seamlessly with the same application backend and persistent database.
* **Persistent Storage:** Backed by an embedded SQLite database (`data/cybershield.db`) configured with Write-Ahead Logging (WAL) for safe multi-client concurrency.
* **REST API:** Standard HTTP endpoints providing authentication, real-time dashboard metrics, CRUD incident management, threat telemetry, and audit history.
* **Swing Component Lab:** A dedicated, comprehensive laboratory section demonstrating **40+ authentic Java Swing components**, MDI desktop windows, tree hierarchies, progress bars, sliders, dialogs, and layout managers.
* **Role-Based Access Control (RBAC):** Distinct administrative and security analyst roles with server-enforced authorization rules.

---

## 2. Technology Stack

| Layer | Technology | Rationale |
|---|---|---|
| **Programming Language** | Java (JDK 17+) | Core OOP foundation, native cross-platform support |
| **Desktop GUI** | Java Swing (`javax.swing.*`) | Demonstrates desktop GUI lifecycle, EDT thread safety, 40+ components |
| **Backend Web Server** | `com.sun.net.httpserver.HttpServer` | Built-in JDK HTTP server; zero bulky framework dependencies |
| **Database** | SQLite via JDBC (`sqlite-jdbc` 3.45.2.0) | Zero-configuration, file-based persistence at `data/cybershield.db` |
| **Data Exchange** | JSON via Google Gson (2.10.1) | Clean serialization between clients and REST endpoints |
| **Web Frontend** | Vanilla HTML5, CSS3, JavaScript | Clean Dark SOC aesthetic, responsive, zero frontend build tools |
| **Build System** | Apache Maven 3.8+ | Standardized dependency management and fat-jar packaging |

---

## 3. Demonstration Accounts

The database is automatically created and seeded with two pre-configured accounts on initial startup:

| Username | Password | Role | Permissions |
|---|---|---|---|
| `admin` | `Admin@123` | **ADMINISTRATOR** | Full access: View, Add, Update, **Delete** incidents, view audit logs |
| `analyst` | `Analyst@123` | **SECURITY ANALYST** | Operational access: View, Add, Update incidents, simulate threats (**Deletion blocked**) |

> **Security Note:** Passwords are never stored in plaintext. They are hashed using a **salted SHA-256** algorithm (`PasswordUtils.java`).

---

## 4. Quick Start & Launch Guide

### Prerequisites
* **Java Development Kit (JDK):** Version 17 or higher (`java -version`).
* **Apache Maven:** Version 3.8 or higher (`mvn -version`).
* **Operating System:** Windows 10/11, macOS, or Linux.

### Method 1: Using the Master Batch Launcher (Windows)
Double-click `run.bat` in the project root folder, or execute it in PowerShell/CMD:
```cmd
.\run.bat
```
The interactive menu allows you to:
1. **Option 1:** Start Full System (Launches embedded backend server and opens Swing GUI).
2. **Option 2:** Start Web Server Only (`http://localhost:8080`).
3. **Option 3:** Launch Swing Desktop GUI Only.
4. **Option 4:** Open Web App in default web browser.
5. **Option 5:** Rebuild and Package with Maven (`mvn clean package`).
6. **Option 6:** Run Automated System Verification Tests.

### Method 2: Command Line (Maven & Java)
1. **Compile and Package the Project:**
   ```bash
   mvn clean package -DskipTests
   ```
2. **Launch Both Backend & Swing Desktop GUI:**
   ```bash
   java -jar target/cybershield-1.0.0-jar-with-dependencies.jar
   ```
3. **Launch Server Only (for Web access):**
   ```bash
   java -jar target/cybershield-1.0.0-jar-with-dependencies.jar --server-only
   ```
4. **Launch Swing GUI Only:**
   ```bash
   java -jar target/cybershield-1.0.0-jar-with-dependencies.jar --gui-only
   ```

### Web Application URL
Open any web browser and navigate to:
```
http://localhost:8080/
```

---

## 5. REST API Endpoints

All REST API endpoints are served under `/api/`:

| Method | Endpoint | Authentication | Description |
|---|---|---|---|
| `POST` | `/api/auth/login` | None | Authenticates user; returns bearer token and user role |
| `POST` | `/api/auth/logout` | Token | Invalidates active user session |
| `GET` | `/api/auth/me` | Token | Returns current authenticated user metadata |
| `GET` | `/api/dashboard/stats` | None | Returns aggregated counts (total, open, critical, probes) and recent feeds |
| `GET` | `/api/incidents` | None | Returns incidents filtered by search query, severity, and status |
| `POST` | `/api/incidents` | Token | Logs a new security incident |
| `GET` | `/api/incidents/{id}` | None | Retrieves detailed metadata for a single incident |
| `PUT` | `/api/incidents/{id}` | Token | Updates an incident's title, description, severity, or status |
| `DELETE`| `/api/incidents/{id}` | **Admin Only** | Deletes an incident record (**strictly rejected for analyst role**) |
| `GET` | `/api/access-events` | None | Retrieves unauthorized login attempts and intrusion telemetry |
| `POST` | `/api/access-events/simulate` | Optional | Simulates an external intrusion attack for demonstration |
| `GET` | `/api/activity` | None | Retrieves chronological system activity and compliance audit logs |
| `GET` | `/api/alerts` | None | Retrieves recent automated intrusion detection alerts |
| `GET` | `/api/alerts/latest` | None | Retrieves the latest active security alert for the dashboard banner |
| `GET` | `/api/intrusion/config` | None | Returns active IDS detection parameters and sliding-window thresholds |
| `POST` | `/api/intrusion/simulate-attack` | Optional | Simulates a burst of 5 failed logins to demonstrate automated incident creation |

---

## 6. Project Directory Structure

```text
cybershield/
├── pom.xml                                   # Maven dependencies, build, and fat-jar assembly config
├── run.bat                                   # Windows interactive master launcher
├── README.md                                 # Main project documentation and setup guide
├── REVIEW_2_IMPLEMENTATION.md                # Comprehensive Review 2 technical specification & viva guide
├── FIRST_REVIEW_PREPARATION.md               # Historical Review 1 component inventory & viva handbook
├── VIVA_GUIDE.md                             # Comprehensive 18-topic viva evaluation guide
├── test_review2.ps1                          # Automated Review 2 end-to-end integration test suite
├── test_system.ps1                           # Automated endpoint and CRUD verification script
├── test_roles.ps1                            # Automated role-based access control test
├── data/
│   └── cybershield.db                        # Persistent SQLite database (WAL enabled, 6 tables)
├── web/                                      # Modern Web Application (Frontend)
│   ├── index.html                            # Dark SOC-themed dashboard single-page app
│   ├── css/
│   │   └── style.css                         # Navy styling, alert banner, cards, tables, modals
│   └── js/
│       └── app.js                            # Vanilla JS API router, state, CRUD handlers, IDS banner
└── src/
    ├── main/
    │   └── java/
    │       └── cybershield/
    │           ├── Main.java                 # Main application entry point & CLI parser
    │           ├── database/                 # Persistence & JDBC Layer
    │           │   └── DatabaseManager.java  # SQLite connection, schema creation, demo data
    │           ├── model/                    # Domain Data Models
    │           │   ├── User.java             # User account and role definition
    │           │   ├── Incident.java         # Security incident model
    │           │   ├── AccessEvent.java      # Telemetry intrusion event model
    │           │   ├── ActivityLog.java      # Audit trail log model
    │           │   ├── DashboardStats.java   # Aggregated KPI metric container
    │           │   ├── SecurityAlert.java    # Automated IDS security alert model
    │           │   └── IntrusionDetectionConfig.java # Detection threshold configuration
    │           ├── security/                 # Authentication & Session Management
    │           │   ├── PasswordUtils.java    # Salted SHA-256 hashing and verification
    │           │   └── SessionManager.java   # Token generation and session validation
    │           ├── service/                  # Business Logic Layer
    │           │   ├── UserService.java      # Authentication logic and credential validation
    │           │   ├── IncidentService.java  # Incident CRUD and search operations
    │           │   ├── AccessEventService.java# Telemetry recording and threat simulation
    │           │   ├── ActivityLogService.java# Audit logging service
    │           │   ├── DashboardService.java # Metric computation and KPI aggregation
    │           │   └── IntrusionDetectionService.java # Rule-based automated IDS engine
    │           ├── server/                   # Embedded HTTP Backend Layer
    │           │   ├── HttpServerManager.java# JDK HttpServer configuration and port binding
    │           │   ├── ApiHandler.java       # REST API endpoint routing and JSON handling
    │           │   └── StaticFileHandler.java# Static web asset serving (HTML, CSS, JS)
    │           └── ui/                       # Java Swing Desktop GUI Layer
    │               ├── SwingTheme.java       # Central design system, fonts, colors, styling
    │               ├── ApiClient.java        # Desktop-to-backend bridge service
    │               ├── LoginFrame.java       # Visible login window with quick demo buttons
    │               ├── MainFrame.java        # Master frame (JMenuBar, JToolBar, JTabbedPane)
    │               ├── DashboardPanel.java   # Executive metrics cards and recent feeds
    │               ├── IncidentPanel.java    # Incident table, search, filters, modal dialogs
    │               ├── AccessMonitoringPanel.java# Intrusion telemetry & threat simulator
    │               ├── ActivityHistoryPanel.java # Audit trail viewer
    │               ├── ComponentLabPanel.java# 40+ Swing Component Laboratory
    │               └── AboutPanel.java       # Architecture details & student placeholders
    └── test/
        └── java/
            └── cybershield/
                └── IntrusionDetectionTest.java # Automated JUnit 5 test suite (13 test scenarios)
```

---

## 7. How to Safely Stop the System

* **Web Server Console:** Press `Ctrl + C` in the console window running the server.
* **Desktop GUI:** Click the window close button (`X`) or navigate to **File -> Exit Application**.
* **Database File:** SQLite automatically flushes the Write-Ahead Log (WAL) into `cybershield.db` upon connection close. No database daemon shutdown is required.
