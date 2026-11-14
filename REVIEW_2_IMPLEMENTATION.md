# CyberShield — Review 2 Implementation & Technical Specification

> **Project Title:** CyberShield — Cybersecurity Monitoring and Incident Management System  
> **Course:** 2nd-Year B.Tech Computer Science & Engineering (CSE)  
> **Evaluation Phase:** Review 2 — Automated Intrusion Detection & Incident Generation  
> **Academic Focus:** Object-Oriented Software Engineering, Rule-Based Threat Detection, Sliding-Window Analytics, Concurrency, and Dual-Client Synchronization.

---

## 1. Review 1 Project Summary

During the initial Review 1 implementation, CyberShield was established as a lightweight, framework-free cybersecurity platform featuring:
* **Dual-Interface Client-Server Architecture:** A modern Web application (Vanilla HTML5, CSS3, JavaScript) and a native Java Swing desktop GUI interacting seamlessly with an embedded JDK HTTP server (`com.sun.net.httpserver.HttpServer`) and a persistent SQLite database (`data/cybershield.db`).
* **Role-Based Access Control (RBAC):** Distinct `ADMINISTRATOR` (`admin`) and `SECURITY ANALYST` (`analyst`) roles with server-side authorization enforcement (e.g., analyst incident deletion blocked with HTTP 403 Forbidden).
* **Incident Management (CRUD):** Creating, viewing, filtering, updating, and deleting security incidents with audit trail logging in SQLite.
* **Component Laboratory:** An authentic Java Swing showcase featuring **40+ native Swing components** (including `JFrame`, `JDialog`, `JTable`, `JTree`, `JDesktopPane`, `JInternalFrame`, custom table cell renderers, and layout managers).
* **Cryptographic Security:** Salted SHA-256 password hashing via `PasswordUtils.java` with constant-time verification to prevent timing attacks.

---

## 2. New Features Added in Review 2

Review 2 advances CyberShield from a manual monitoring and reporting tool into an **automated, rule-based Security Operations Center (SOC) defense system**:

1. **Automated Failed Login Monitoring:**
   * Direct extraction of remote connection IP addresses from active HTTP sockets without blindly trusting spoofable headers.
   * Persistent logging of every authentication failure with timestamps into SQLite (`failed_logins` table).
   * Strict adherence to zero-credential leakage: passwords are never stored in access logs, detection tables, or audit logs.

2. **Rule-Based Brute-Force Intrusion Detection:**
   * Implementation of the academic detection rule: **$\ge 5$ failed login attempts from the same IP address within a 2-minute sliding time window** ($\Delta t \le 120\text{ s}$).
   * Configurable thresholds encapsulated within `IntrusionDetectionConfig.java`:
     * `MAX_FAILED_ATTEMPTS = 5`
     * `TIME_WINDOW_MINUTES = 2`
     * `ALERT_COOLDOWN_MINUTES = 10`

3. **Automatic Security Incident Generation:**
   * Automated creation of a **HIGH** severity incident in SQLite via `IncidentService.java` immediately upon threshold violation.
   * Incident metadata includes Source IP, failed attempt count, exact detection timestamp, and triggered heuristic rule.
   * Automatic creation of an alert entry in the `security_alerts` table and non-repudiable audit logging in `activity_log`.

4. **Intelligent Cooldown & De-duplication:**
   * 10-minute suppression cooldown per source IP address prevents incident flooding from subsequent failed attempts during an active attack burst.
   * Independent tracking: activity from different IP addresses is tracked strictly in isolation.

5. **Dedicated Executive Security Alert Section:**
   * Prominent, dark SOC-themed alert banner on both Web and Java Swing dashboards displaying live threat forensics:
     `BRUTE FORCE ATTACK DETECTED | Source IP: 192.168.1.105 | 5 Attempts | Severity: HIGH | Status: OPEN`.

6. **Live Multi-Client State Synchronization:**
   * Both Web and Swing interfaces query the shared SQLite database and REST API, ensuring identical threat metrics and zero architectural divergence.

---

## 3. Updated System Architecture

CyberShield maintains a clean, four-layer Object-Oriented architecture:

```
+-----------------------------------------------------------------------+
|                           PRESENTATION LAYER                          |
|   +-------------------------------+   +---------------------------+   |
|   |    Modern Web SOC Console     |   |    Java Swing Desktop     |   |
|   |  (HTML5, CSS3, Vanilla JS)    |   |  (40+ Components, EDT)    |   |
|   +---------------+---------------+   +-------------+-------------+   |
+-------------------|---------------------------------|-----------------+
                    | REST / JSON                     | In-Memory Client
                    v                                 v
+-----------------------------------------------------------------------+
|                          CONTROLLER LAYER                             |
|          +-------------------------------------------------+          |
|          |    ApiHandler (REST Endpoint Router & CORS)     |          |
|          |    ApiClient  (Swing Desktop Service Adapter)   |          |
|          +------------------------+------------------------+          |
+-----------------------------------|-----------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|                            SERVICE LAYER                              |
|   +--------------------------+     +-------------------------------+  |
|   |       UserService        |---->|   IntrusionDetectionService   |  |
|   +--------------------------+     | (Rule Engine & Cooldown Mgr)  |  |
|   +--------------------------+     +---------------+---------------+  |
|   |     IncidentService      |<--------------------+                  |
|   +--------------------------+                                        |
|   +--------------------------+     +-------------------------------+  |
|   |    AccessEventService    |     |      ActivityLogService       |  |
|   +--------------------------+     +-------------------------------+  |
|   +----------------------------------------------------------------+  |
|   |           DashboardService (Metrics & Aggregation)             |  |
|   +----------------------------------------------------------------+  |
+-----------------------------------|-----------------------------------+
                                    | JDBC / Parameterized SQL
                                    v
+-----------------------------------------------------------------------+
|                            DATABASE LAYER                             |
|          +-------------------------------------------------+          |
|          |   DatabaseManager (SQLite WAL Engine: 6 Tables)  |          |
|          |   - users          - incidents       - access_events    |  |
|          |   - activity_log   - failed_logins   - security_alerts  |  |
|          +-------------------------------------------------+          |
+-----------------------------------------------------------------------+
```

---

## 4. Intrusion Detection Algorithm & Sliding-Window Logic

### Formal Mathematical Specification

Let $\mathcal{F}$ be the set of all recorded failed login attempts:
$$\mathcal{F} = \{ (ip_k, u_k, t_k) \mid k \in \mathbb{N} \}$$
where $ip_k$ is the remote connection IP, $u_k$ is the target username, and $t_k \in \mathbb{R}^+$ is the epoch timestamp in milliseconds.

When a failed login attempt occurs at time $t_{\text{current}}$ from IP $ip^*$:
1. **Persistence:** Insert $(ip^*, u^*, t_{\text{current}})$ into `failed_logins`.
2. **Window Evaluation:** Compute the sliding window threshold:
   $$t_{\text{window\_start}} = t_{\text{current}} - (W \times 60 \times 1000)$$
   where $W = 2\text{ minutes}$.
3. **Attempt Aggregation:** Count qualifying attempts within the window:
   $$C(ip^*) = \left| \{ (ip, u, t) \in \mathcal{F} \mid ip = ip^* \land t \ge t_{\text{window\_start}} \} \right|$$
4. **Threshold Test:** If $C(ip^*) \ge M$ (where $M = 5\text{ attempts}$):
   * **Cooldown Check:** Query the timestamp $t_{\text{last\_alert}}(ip^*)$ of the most recent alert for $ip^*$.
   * If $(t_{\text{current}} - t_{\text{last\_alert}}(ip^*)) < (D \times 60 \times 1000)$ where $D = 10\text{ minutes}$:
     $$\text{Action} = \text{SUPPRESS\_DUPLICATE (Log warning only)}$$
   * Else:
     $$\text{Action} = \text{TRIGGER\_ALERT} \implies \begin{cases} 
     \text{Create Incident (Severity: HIGH, Status: OPEN)} \\
     \text{Insert Record in security\_alerts} \\
     \text{Log Non-Repudiable Entry in activity\_log}
     \end{cases}$$

---

## 5. Database Modifications & Migration Strategy

The SQLite schema was updated in a strictly backward-compatible, idempotent manner. Existing tables (`users`, `incidents`, `access_events`, `activity_log`) remain completely unaffected.

### New Tables Added

#### Table 1: `failed_logins`
Stores granular authentication failure timestamps for sliding-window evaluation.
```sql
CREATE TABLE IF NOT EXISTS failed_logins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    username TEXT NOT NULL,
    attempted_at TEXT NOT NULL,
    timestamp_epoch INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_failed_logins_ip_time ON failed_logins (ip_address, timestamp_epoch);
```

#### Table 2: `security_alerts`
Stores automated threat detections correlated with created incidents.
```sql
CREATE TABLE IF NOT EXISTS security_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    incident_id INTEGER,
    details TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_at_epoch INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_security_alerts_ip ON security_alerts (source_ip);
```

---

## 6. Java Classes: New and Modified

### New Classes Created

| Class | Package | Purpose |
|---|---|---|
| `SecurityAlert.java` | `cybershield.model` | Domain entity representing an automated security alert with source IP, failed attempts, and linked incident ID. |
| `IntrusionDetectionConfig.java` | `cybershield.model` | Encapsulates detection parameters (`MAX_FAILED_ATTEMPTS`, `TIME_WINDOW_MINUTES`, `ALERT_COOLDOWN_MINUTES`). |
| `IntrusionDetectionService.java` | `cybershield.service` | Core rule-based IDS engine managing failed attempt history, sliding window queries, cooldowns, and automatic incident triggering. |
| `IntrusionDetectionTest.java` | `cybershield` (test) | Automated JUnit 5 test suite verifying all 12 academic test scenarios. |

### Existing Classes Modified

| Class | Key Modifications Made |
|---|---|
| `DatabaseManager.java` | Added safe schema generation for `failed_logins` and `security_alerts` with indexes and starter seed data. |
| `UserService.java` | Injected `IntrusionDetectionService`, overloaded `authenticate` to receive client connection IP and forward failures to the IDS. |
| `IncidentService.java` | Integrated seamlessly as the persistent target for auto-generated incidents created by `IDS_ENGINE`. |
| `DashboardStats.java` | Added fields for detected threats, active alerts, auto-generated incidents, and latest alert entity. |
| `DashboardService.java` | Aggregated dynamic counts for automated threats, active alerts, and latest alert entity. |
| `ApiHandler.java` | Extracted client connection socket IP (`exchange.getRemoteAddress()`), added `/api/alerts`, `/api/alerts/latest`, `/api/intrusion/config`, and `/api/intrusion/simulate-attack` endpoints. |
| `ApiClient.java` | Added desktop proxy methods for latest alert, alert history, and brute-force threat simulation. |
| `DashboardPanel.java` | Redesigned desktop layout to feature a dedicated Security Alert Banner, 6 metric cards, and live EDT synchronization. |
| `AccessMonitoringPanel.java` | Added 1-click brute-force simulation button with confirmation dialogs. |
| `pom.xml` | Added JUnit 5 Jupiter and Maven Surefire plugin for automated testing. |
| `run.bat` | Upgraded test launcher option to execute JUnit 5 tests, REST tests, and RBAC tests. |

---

## 7. REST API Modifications

The following new and enhanced endpoints were added under `/api/`:

| Method | Endpoint | Auth Required | Description |
|---|---|---|---|
| `POST` | `/api/auth/login` | No | Authenticates user; extracts remote IP; records failed login; triggers IDS on 5th attempt. |
| `GET` | `/api/dashboard/stats` | No | Returns aggregated metrics including `totalDetectedThreats`, `activeSecurityAlerts`, `autoGeneratedIncidents`, and `latestAlert`. |
| `GET` | `/api/alerts` | No | Returns recent security alerts ordered newest first. |
| `GET` | `/api/alerts/latest` | No | Returns the most recent active security alert or system normal status. |
| `GET` | `/api/intrusion/config` | No | Returns active detection parameters (thresholds, time window, cooldown). |
| `POST` | `/api/intrusion/simulate-attack` | No | Simulates a 5-failure brute-force burst from target IP for demonstration. |

---

## 8. Web Application Modifications

1. **Dedicated Security Alert Banner:**
   * Dynamically renders glowing red/amber threat telemetry when an active alert exists:
     * Category: `SECURITY ALERT`
     * Title: `BRUTE FORCE ATTACK DETECTED`
     * Badge: `HIGH SEVERITY`
     * Telemetry: Source IP address, failed attempts count, status, timestamp, and triggered rule.
     * One-click navigation button linking directly to the auto-generated incident record.
   * Gracefully displays `SYSTEM NORMAL — IDS HEURISTICS MONITORING` with a green shield when no active threats are present.
2. **KPI Metrics Grid Expansion:**
   * Added 3 new dynamic SOC metrics:
     * `Detected Threats` (icon: 🛡️)
     * `Active Alerts` (icon: ⚡)
     * `Auto-Incidents` (icon: 🤖)
3. **Threat Simulation Integration:**
   * Added `🚨 Simulate Brute-Force Attack (5 Failures)` button in Unauthorized Access Monitoring view for instant faculty evaluation.

---

## 9. Java Swing Desktop Modifications

1. **Executive Security Alert Section (`DashboardPanel.java`):**
   * Prominently placed at the top of the dashboard center panel with high-contrast borders and severity badges.
   * Displays Source IP, Attempt Count, Severity (`HIGH`), Status (`OPEN`), and Detection Timestamp.
2. **Expanded KPI Metrics Grid:**
   * Six balanced cards: Total Incidents, Active Incidents, Critical Threats, Unauthorized Probes, Detected Threats, and Auto-Incidents.
3. **Interactive Simulation (`AccessMonitoringPanel.java`):**
   * Dedicated `Simulate Brute-Force (5 Failures)` button triggering desktop alert dialogs and instant table updates.
4. **EDT Safety:**
   * All GUI updates are dispatched strictly via `SwingUtilities.invokeLater()`, guaranteeing zero thread contention or UI freezes.

---

## 10. Automated Test Results

The project includes both a Maven JUnit 5 test suite (`IntrusionDetectionTest.java`) and a comprehensive PowerShell integration script (`test_review2.ps1`).

### Test Execution Summary

| # | Test Scenario | Verified Behavior | Status |
|---|---|---|:---:|
| 1 | 1 incorrect login | Recorded persistently in `failed_logins`; no alert triggered. | **PASS** |
| 2 | 2 incorrect logins | Both recorded in SQLite; no alert triggered. | **PASS** |
| 3 | 4 failures within 2 minutes | All 4 recorded; threshold (5) not reached; no alert. | **PASS** |
| 4 | 5 failures within 2 minutes | HIGH severity alert generated; incident created in SQLite. | **PASS** |
| 5 | 6th failure during cooldown | 6th attempt recorded; duplicate incident suppressed. | **PASS** |
| 6 | Failures from different IPs | IP A (5 failures) triggers alert; IP B (3 failures) does not. | **PASS** |
| 7 | Failures outside 2-min window | 3 old attempts (3 min ago) excluded; only 2 counted; no alert. | **PASS** |
| 8 | Valid login | Successful authentication; no brute-force alert triggered. | **PASS** |
| 9 | Auto-generated incident in SQLite | Record verified in `incidents` table with title, HIGH severity, and IP. | **PASS** |
| 10 | Dashboard refresh | Metrics reflect detected threats, active alerts, and latest alert data. | **PASS** |
| 11 | Analyst RBAC restrictions | Analyst can log in but deletion is blocked (403 Forbidden). | **PASS** |
| 12 | Admin functionality | Admin can log in, create incidents, and delete incidents. | **PASS** |
| 13 | Zero credential leakage | Passwords verified to NEVER be stored in any log table. | **PASS** |

**JUnit 5 Execution Result:** `Tests run: 13, Failures: 0, Errors: 0, Skipped: 0 (BUILD SUCCESS)`  
**PowerShell Integration Result:** `ALL 8 ENDPOINT & CRUD TESTS PASSED WITH 100% SUCCESS`

---

## 11. Faculty Viva Demonstration Script

Follow this step-by-step procedure during the review:

### Step 1: Launch Full System
```cmd
.\run.bat
```
Select **Option 1: START FULL SYSTEM**. Observe in the terminal:
* SQLite database initialized at `data/cybershield.db`.
* Embedded HTTP server active on `http://localhost:8080/`.
* Swing Desktop GUI launched on the EDT.

### Step 2: Web Dashboard Inspection
1. Open browser to `http://localhost:8080/`.
2. Click **Fill Admin** (`admin` / `Admin@123`) and click **Sign In**.
3. Point out the dashboard:
   * System status indicates normal or shows existing baseline alerts.
   * Point out the 7 metric cards including **Detected Threats** and **Auto-Incidents**.

### Step 3: Trigger Failed Login Attempts (Brute-Force Attack)
1. Open an incognito browser window or sign out.
2. Enter username `admin` and an incorrect password (e.g., `wrongpassword`).
3. Click **Sign In** 5 times in rapid succession (within 2 minutes).
4. On the 5th attempt, the backend logs:
   `[IDS ALERT] *** BRUTE FORCE ATTACK DETECTED *** Source IP: 127.0.0.1 | Failures: 5`

### Step 4: Verify Automated Detection on Dashboard
1. Sign in as `admin`.
2. Inspect the **SECURITY ALERT** banner on the dashboard:
   * Title: `BRUTE FORCE ATTACK DETECTED`
   * Source IP: `127.0.0.1`
   * Failed Attempts: `5 Attempts`
   * Severity: `HIGH`
   * Status: `OPEN`
   * Detection Timestamp: Current live time.

### Step 5: Verify Incident Management Table
1. Click **Incident Management** in the sidebar.
2. Observe the auto-generated incident at the top of the table:
   * Title: `Brute Force Login Attack Detected`
   * Severity: `HIGH` (highlighted in orange/red)
   * Status: `OPEN`
   * Reported By: `IDS_ENGINE`
3. Click to view details: point out the forensic summary including IP address and detection rule.

### Step 6: Verify De-Duplication Cooldown
1. Attempt a 6th failed login from the same IP.
2. Check the server console or incident table:
   * The attempt is recorded, but **no duplicate incident is created** because the 10-minute cooldown is active.

### Step 7: Verify Audit Trail
1. Click **Activity History** in the sidebar.
2. Point out the audit record:
   * User: `IDS_ENGINE`
   * Action: `INTRUSION_ALERT`
   * Details: `Detected brute-force attack from IP 127.0.0.1 (5 failures). Generated Incident #...`

### Step 8: Verify Desktop Swing Synchronization
1. Switch to the Java Swing desktop application.
2. Click **🔄 Refresh Metrics** on the Dashboard tab.
3. Show that the desktop dashboard reflects the exact same Security Alert Banner, Source IP, and metrics.
4. Switch to the **Incidents** tab: show that the auto-generated incident appears in the Swing `JTable`!

---

## 12. Limitations & Future Roadmap

* **In-Memory IP Blocking:** Currently, the system functions as an Intrusion *Detection* System (IDS), generating alerts and incidents rather than an Intrusion *Prevention* System (IPS) that drops TCP packets. A future enhancement could introduce temporary IP blacklisting (e.g., blocking after 10 failures).
* **Distributed Brute-Force (Botnet):** The current rule tracks attacks by single source IP. A future version could correlate failures across multiple IPs targeting the same username (horizontal brute-force / password spraying).
* **Geo-IP Resolution:** Future builds could incorporate offline MaxMind GeoIP databases to map attacker IP addresses to geographic coordinates on an interactive threat map.

