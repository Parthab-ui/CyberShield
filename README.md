# CyberShield — Automated Cybersecurity Monitoring and Incident Response System

> **Academic Project Edition:** Designed and structured specifically for **2nd-Year B.Tech Computer Science and Engineering (CSE)** College Review and Viva Evaluation.

---

## 1. Project Overview

**CyberShield** is a unified, lightweight cybersecurity monitoring and incident response system designed to showcase robust Object-Oriented Software Engineering, modern client-server communication, database persistence, and advanced Java Swing desktop GUI programming.

Unlike complex enterprise solutions, CyberShield is intentionally built without bloated third-party frameworks (no Spring Boot, React, Docker, or Kubernetes). It relies strictly on standard Java, lightweight embedded HTTP server APIs, vanilla web technologies, and standard Swing components that second-year students can easily explain and defend line-by-line during a faculty viva.

### Key Architecture Highlights
* **Dual-Interface Architecture:** Both a **modern Web Application** and a feature-rich **Java Swing Desktop GUI** interact seamlessly with the same application backend and persistent database.
* **Persistent Storage:** Backed by an embedded SQLite database (`data/cybershield.db`) configured with Write-Ahead Logging (WAL) for safe multi-client concurrency. Connections are handled on-demand via JDBC DriverManager (no external connection pool).
* **REST API:** Standard HTTP endpoints providing authentication, real-time dashboard metrics, CRUD incident management, threat telemetry, automated threat responses, firewall/IP block management, and audit history.
* **Swing Component Lab:** A dedicated laboratory section demonstrating **40+ authentic Java Swing components**, MDI desktop windows, tree hierarchies, progress bars, sliders, dialogs, and layout managers.
* **Role-Based Access Control (RBAC):** Distinct administrative (`ADMIN`) and security analyst (`ANALYST`) roles with server-enforced authorization rules.
* **Hardened Security Posture:** PBKDF2 password hashing with HMAC-SHA256, 32-byte cryptographically secure session tokens with idle/absolute timeouts, IP rate limiting, input validation, and defensive headers.

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
| `admin` | `Admin@123` | **ADMINISTRATOR** | Full access: View, Add, Update, **Delete** incidents, IP blocking/unblocking, account unlock, view audit logs |
| `analyst` | `Analyst@123` | **SECURITY ANALYST** | Operational access: View, Add, Update incidents, investigate cases, simulate threats (**Admin operations blocked**) |

> **Security Note:** Passwords are never stored in plaintext. They are hashed using **PBKDF2WithHmacSHA256** (120,000 iterations, 16-byte SecureRandom salt, 256-bit key) with self-describing format `pbkdf2$<iterations>$<saltHex>$<hashHex>`. Legacy SHA-256 hashes are automatically verified and upgraded upon first login.

### Environment Variable Overrides

Override default demo passwords at startup using environment variables:
```bash
CYBERSHIELD_ADMIN_PASSWORD="MyCustomAdminPassword123!" java -jar target/cybershield-1.0.0-jar-with-dependencies.jar
CYBERSHIELD_ANALYST_PASSWORD="MyCustomAnalystPassword123!" java -jar target/cybershield-1.0.0-jar-with-dependencies.jar
```

---

## 4. Security Features

| Feature | Implementation Details |
|---|---|
| **Password Hashing** | `PBKDF2WithHmacSHA256`, 120,000 iterations, 16-byte random salt, constant-time verification, automatic legacy hash upgrade |
| **Session Management** | 32-byte `SecureRandom` URL-safe Base64 tokens (43 characters); 30-minute idle timeout; 8-hour absolute maximum lifetime; background daemon cleaner |
| **Authentication Enforcement** | All sensitive API endpoints strictly require HTTP `Authorization: Bearer <token>` header (HTTP 401 unauthenticated) |
| **Role-Based Access Control** | Server-side role validation (`ADMIN` vs `ANALYST`); administrative actions return HTTP 403 Forbidden for non-admins |
| **Global IP Block Gate** | Enforced at gateway level before route processing; blocked IPs receive HTTP 403 |
| **Login Rate Limiting** | 10 login attempts per 60-second sliding window per IP address; excess attempts return HTTP 429 with `Retry-After: 60` |
| **Request Body Limit** | Enforced 64 KB maximum payload limit on all incoming POST/PUT bodies to prevent DoS (HTTP 413) |
| **Security Response Headers** | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` |
| **Input Validation** | Severity & status allowlists, field length limits (title: 200, desc: 2000, notes: 5000), username regex, IP format checking |
| **Path Traversal Protection** | Canonical path validation + strict extension allowlist (`.html`, `.css`, `.js`, `.json`, `.svg`, `.png`, `.jpg`, `.ico`) |
| **Audit Logging** | Activity audit log records failed logins, account lockouts, rate limit hits, manual/automated IP blocks, and unblocks |
| **Data Hygiene** | Password hashes and salts are strictly stripped from all client-facing API responses (`/api/auth/me`, `/api/investigators`) |

---

## 5. Known Limitations

* **HTTP Only (No TLS/HTTPS):** CyberShield uses the standard JDK HTTP server without TLS. Intended for local academic evaluation, laboratory demonstrations, and internal networks.
* **In-Memory Active Sessions:** Session state is maintained in-memory via `ConcurrentHashMap`; active sessions are invalidated upon application restart.
* **Single-Node Embedded SQLite:** Database concurrency is managed via SQLite WAL mode; designed for single-node deployments.
* **Demo Credentials in Source:** Standard demo accounts are provided for review convenience; production environments should use environment variable overrides.

---

## 6. Quick Start & Launch Guide

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
Open any modern web browser and navigate to:
```
http://localhost:8080/
```

---

## 7. REST API Endpoints

All REST API endpoints are served under `/api/`:

| Method | Endpoint | Required Role | Description |
|---|---|---|---|
| `POST` | `/api/auth/login` | Public | Authenticates credentials; returns bearer token and user role |
| `POST` | `/api/auth/logout` | Token | Invalidates active user session |
| `GET` | `/api/auth/me` | Token | Returns current authenticated user metadata |
| `GET` | `/api/auth/locked-accounts` | **ADMIN** | Lists all accounts currently locked by lockout policy |
| `POST` | `/api/auth/unlock` | **ADMIN** | Unlocks a locked account and invalidates active sessions |
| `GET` | `/api/auth/lock-status/{username}`| Token | Retrieves lockout status for a specific user |
| `GET` | `/api/firewall/blocked-ips` | Token | Lists active and historical blocked IPs |
| `POST` | `/api/firewall/block` | **ADMIN** | Manually blocks an IP address with expiration duration |
| `POST` | `/api/firewall/unblock` | **ADMIN** | Manually unblocks a previously blocked IP |
| `GET` | `/api/dashboard/stats` | Token | Returns aggregated counts (total, open, critical, probes) and metrics |
| `GET` | `/api/investigators` | Token | Lists eligible security analyst accounts for assignment |
| `GET` | `/api/incidents` | Token | Returns incidents filtered by search query, severity, and status |
| `POST` | `/api/incidents` | Token | Logs a new security incident with input validation |
| `GET` | `/api/incidents/{id}` | Token | Retrieves detailed metadata for a single incident |
| `PUT` | `/api/incidents/{id}` | Token | Updates an incident's title, description, severity, or status |
| `DELETE`| `/api/incidents/{id}` | **ADMIN** | Deletes an incident record (**strictly rejected for analyst role**) |
| `GET` | `/api/incidents/{id}/investigations` | Token | Retrieves investigation notes and evidence for an incident |
| `POST` | `/api/incidents/{id}/investigations` | Token | Appends an investigation note and optional evidence |
| `GET` | `/api/incidents/{id}/timeline` | Token | Retrieves chronological investigation timeline items |
| `GET` | `/api/incidents/{id}/investigation-summary` | Token | Retrieves complete investigation summary dossier |
| `POST` | `/api/incidents/{id}/assign` | **ADMIN** | Assigns a designated security analyst to the incident |
| `POST` | `/api/incidents/{id}/root-cause` | Token | Classifies root cause category and rationale |
| `POST` | `/api/incidents/{id}/resolve` | Token | Formally resolves incident with technical resolution summary |
| `GET` | `/api/access-events` | Token | Retrieves unauthorized login attempts and intrusion telemetry |
| `POST` | `/api/access-events/simulate` | Token | Simulates an external intrusion attack for demonstration |
| `GET` | `/api/activity` | Token | Retrieves chronological system activity and compliance audit logs |
| `GET` | `/api/alerts` | Token | Retrieves recent automated intrusion detection alerts |
| `GET` | `/api/alerts/latest` | Token | Retrieves the latest active security alert for the dashboard banner |
| `GET` | `/api/intrusion/config` | Token | Returns active IDS detection parameters and sliding-window thresholds |
| `POST` | `/api/intrusion/simulate-attack` | Token | Simulates a burst of 5 failed logins to trigger automated response |
| `GET` | `/api/threat-responses` | Token | Retrieves automated defensive countermeasures history |
| `GET` | `/api/threat-responses/stats` | Token | Retrieves aggregated metrics on executed defenses |

---

## 8. Automated Test Suites (14 Suites)

Run the full automated test suite via Maven:
```bash
mvn clean test
```

| # | Test Suite Class | Focus Area |
|---|---|---|
| 1 | `DatabaseArchitectureTest` | SQLite schema, WAL mode, table creation, idempotent seeding |
| 2 | `PasswordUtilsTest` | PBKDF2 hashing, HMAC-SHA256 verification, legacy migration |
| 3 | `SessionManagerTest` | Token entropy, idle timeout, absolute lifetime, user invalidation |
| 4 | `AuthenticationAndRbacEndpointsTest` | 401 unauth enforcement, 403 role enforcement on admin endpoints |
| 5 | `GatewayProtectionsTest` | Global IP block gate, rate limiting (429), body size (413), headers |
| 6 | `InputValidationTest` | Title/desc length limits, severity/status allowlists, path traversal |
| 7 | `DataHygieneTest` | Verification that credentials/hashes are never exposed in API responses |
| 8 | `IpBlockServiceTest` | Application-level IP blocking, whitelist protection, auto-expiration |
| 9 | `AccountLockoutServiceTest` | 5-failure account lockout, auto-unlock timer, administrative unlock |
| 10 | `IntrusionDetectionTest` | Sliding-window brute force detection, duplicate alert suppression |
| 11 | `ThreatResponseServiceTest` | Automated defense triggering, countermeasure execution, stats |
| 12 | `IncidentInvestigationServiceTest` | Investigation notes, evidence JSON, root cause, resolution flow |
| 13 | `CrossApplicationSyncTest` | Real-time cross-client synchronization between Web and Desktop |
| 14 | `ApiHandlerIntegrationTest` | Comprehensive end-to-end REST API integration verification |

---

## 9. How to Safely Stop the System

* **Web Server Console:** Press `Ctrl + C` in the console window running the server.
* **Desktop GUI:** Click the window close button (`X`) or navigate to **File -> Exit Application**.
* **Database File:** SQLite automatically flushes the Write-Ahead Log (WAL) into `cybershield.db` upon connection close. No database daemon shutdown is required.
