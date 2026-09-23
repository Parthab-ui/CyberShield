# CYBERSHIELD — Project Structure & Codebase Guide

This document breaks down every package, class, and component in **CYBERSHIELD** in simple, clear language tailored for undergraduate AOOP viva preparation.

---

## 1. Directory Tree Overview

```
cybershield/
├── pom.xml                     # Maven project descriptor (Java 17, SQLite JDBC, JUnit 5)
├── README.md                   # Complete architectural guide & installation
├── PROJECT_STRUCTURE.md        # This class-by-class technical breakdown
├── DEMO_SCRIPT.md              # 5-7 minute presentation script for 3 members
├── VIVA_QA.md                  # 20+ likely AOOP examination questions and answers
├── run.bat                     # Windows CMD runner script
├── run.ps1                     # PowerShell runner script
├── data/
│   └── cybershield.db          # Embedded SQLite database file (created on startup)
└── src/
    ├── main/
    │   └── java/com/cybershield/
    │       ├── Main.java       # Application entry point
    │       ├── model/          # Domain entity models
    │       │   ├── User.java
    │       │   ├── SecurityEvent.java
    │       │   ├── Threat.java (Abstract Base)
    │       │   ├── BruteForceThreat.java
    │       │   ├── PhishingThreat.java
    │       │   ├── MalwareThreat.java
    │       │   ├── SuspiciousLoginThreat.java
    │       │   ├── Incident.java
    │       │   ├── ResponseAction.java
    │       │   └── enums/
    │       │       ├── Severity.java
    │       │       ├── EventType.java
    │       │       ├── ThreatType.java
    │       │       ├── ThreatStatus.java
    │       │       ├── IncidentStatus.java
    │       │       ├── ResponseActionType.java
    │       │       └── UserRole.java
    │       ├── service/        # Business logic & detection engine
    │       │   ├── AuthService.java
    │       │   ├── ThreatDetectionEngine.java
    │       │   ├── IncidentService.java
    │       │   ├── SimulationService.java
    │       │   └── detector/
    │       │       ├── ThreatDetector.java (Interface)
    │       │       ├── BruteForceDetector.java
    │       │       ├── PhishingDetector.java
    │       │       ├── MalwareDetector.java
    │       │       └── SuspiciousLoginDetector.java
    │       ├── repository/     # Data Access Layer (JDBC + SQLite)
    │       │   ├── DatabaseManager.java
    │       │   ├── UserRepository.java
    │       │   ├── SecurityEventRepository.java
    │       │   ├── ThreatRepository.java
    │       │   ├── IncidentRepository.java
    │       │   └── ResponseActionRepository.java
    │       ├── exception/      # Custom domain exceptions
    │       │   ├── CyberShieldException.java
    │       │   ├── DatabaseOperationException.java
    │       │   ├── AuthenticationException.java
    │       │   ├── ThreatDetectionException.java
    │       │   └── IncidentManagementException.java
    │       ├── util/           # Helper utilities
    │       │   ├── SecurityUtils.java
    │       │   ├── DateTimeUtils.java
    │       │   ├── ValidationUtils.java
    │       │   └── SimulationDataGenerator.java
    │       └── ui/             # Java Swing Graphical User Interface
    │           ├── CyberTheme.java
    │           ├── LoginDialog.java
    │           ├── MainDashboardFrame.java
    │           ├── components/
    │           │   ├── MetricCard.java
    │           │   ├── StyledButton.java
    │           │   └── CyberTable.java
    │           └── panels/
    │               ├── TelemetryPanel.java
    │               ├── ThreatMonitorPanel.java
    │               ├── IncidentConsolePanel.java
    │               ├── AttackSimulatorPanel.java
    │               ├── AnalyticsPanel.java
    │               └── UsersPanel.java
    └── test/
        └── java/com/cybershield/
            └── SmokeTest.java  # Automated test suite verifying all 9 core requirements
```

---

## 2. Package-by-Package Detailed Breakdown

### A. `com.cybershield` (Root)
- **`Main.java`**:
  - The entry point containing `public static void main(String[] args)`.
  - Sets system font anti-aliasing.
  - Calls `DatabaseManager.getInstance().initializeDatabase()`.
  - Launches `LoginDialog` on the Swing Event Dispatch Thread (`SwingUtilities.invokeLater`).
  - If login succeeds, opens `MainDashboardFrame`.

---

### B. `com.cybershield.model` (Domain Entities & OOP Core)
- **`User.java`**:
  - Encapsulates operator identity: `id`, `username`, `passwordHash`, `fullName`, `role` (`ADMIN`/`ANALYST`), `active`, and timestamps.
- **`SecurityEvent.java`**:
  - Represents a raw simulated log ingested by the system: `eventId`, `timestamp`, `eventType`, `sourceIp`, `username`, `description`, `rawPayload`, `severity`.
- **`Threat.java` (Abstract Class)**:
  - Base class for all detected cyber threats.
  - Common attributes: `threatId`, `threatType`, `severity`, `status`, `sourceIp`, `targetAsset`, `detectedAt`, `description`.
  - Abstract methods defining the polymorphic contract:
    - `public abstract Severity evaluateSeverity();`
    - `public abstract String generateIncidentReport();`
    - `public abstract ResponseActionType getRecommendedAction();`
- **`BruteForceThreat.java`** *(extends Threat)*:
  - Adds `failedAttempts`, `targetAccount`, `windowDurationSeconds`.
  - Overrides `evaluateSeverity()` ($\ge 10$ Critical, $\ge 5$ High).
  - Overrides `getRecommendedAction()` $\to$ `BLOCK_IP`.
- **`PhishingThreat.java`** *(extends Threat)*:
  - Adds `senderEmail`, `suspiciousUrl`, `List<String> keywordHits`.
  - Overrides `getRecommendedAction()` $\to$ `MARK_FOR_REVIEW`.
- **`MalwareThreat.java`** *(extends Threat)*:
  - Adds `fileHash`, `filePath`, `quarantinedFlag`.
  - Overrides `getRecommendedAction()` $\to$ `QUARANTINE_SIMULATION`.
- **`SuspiciousLoginThreat.java`** *(extends Threat)*:
  - Adds `geoAnomaly`, `unusualHour`, `deviceFingerprint`.
  - Overrides `getRecommendedAction()` $\to$ `DISABLE_USER`.
- **`Incident.java`**:
  - Demonstrates **Composition**: holds reference to a `Threat` (`associatedThreat`), and a composed collection of response actions (`List<ResponseAction>`).
- **`ResponseAction.java`**:
  - Models a simulated mitigation action: `actionId`, `incidentId`, `actionType`, `target`, `executedBy`, `status`, `executedAt`.

#### `model.enums` Package
- **`Severity.java`**: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` with badge hex colors.
- **`EventType.java`**: `AUTH_FAILURE`, `AUTH_SUCCESS`, `SUSPICIOUS_EMAIL`, `FILE_ACCESS`, `NETWORK_SCAN`, `PRIVILEGE_ESCALATION`.
- **`ThreatType.java`**: `BRUTE_FORCE`, `PHISHING`, `MALWARE`, `SUSPICIOUS_LOGIN`.
- **`ThreatStatus.java`**: `NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`.
- **`IncidentStatus.java`**: `OPEN`, `INVESTIGATING`, `RESOLVED`, `CLOSED`.
- **`ResponseActionType.java`**: `BLOCK_IP`, `DISABLE_USER`, `MARK_FOR_REVIEW`, `QUARANTINE_SIMULATION`.
- **`UserRole.java`**: `ADMIN`, `ANALYST`.

---

### C. `com.cybershield.service` (Business Logic & Detection Engine)
- **`detector/ThreatDetector.java` (Interface)**:
  - Specifies:
    - `boolean canDetect(SecurityEvent event);`
    - `Threat detect(SecurityEvent event) throws ThreatDetectionException;`
    - `String getName();`
- **`detector/BruteForceDetector.java`**:
  - Tracks failed attempts in a sliding 120-second window using `Map<String, List<LocalDateTime>>`.
- **`detector/PhishingDetector.java`**:
  - Scans emails for suspicious keywords (`verify`, `payroll`, `suspended`) and domain spoofing.
- **`detector/MalwareDetector.java`**:
  - Evaluates file extension (`.exe`, `.dll`) and process creation signatures.
- **`detector/SuspiciousLoginDetector.java`**:
  - Identifies impossible travel speed anomalies and unusual login hours.
- **`ThreatDetectionEngine.java`**:
  - Holds `List<ThreatDetector>`.
  - Iterates through detectors polymorphically: dispatches events without knowing concrete classes.
- **`IncidentService.java`**:
  - Business operations: `escalateThreatToIncident()`, `executeResponseAction()`, `resolveIncident()`.
- **`SimulationService.java`**:
  - Triggers end-to-end simulated scenarios (Brute Force, Phishing, Malware, Suspicious Login).
- **`AuthService.java`**:
  - Authenticates users, validates SHA-256 hashes, maintains active in-memory session.

---

### D. `com.cybershield.repository` (Data Access Layer / JDBC)
- **`DatabaseManager.java`**:
  - Singleton managing SQLite connection via `DriverManager.getConnection("jdbc:sqlite:data/cybershield.db")`.
  - Creates tables automatically and seeds initial demo users and baseline events.
- **`UserRepository.java`**:
  - Prepared statements for user query, insertion, and last login updates.
- **`SecurityEventRepository.java`**:
  - Batch insertion (`saveAll`) with transaction rollback, paginated querying, and keyword search.
- **`ThreatRepository.java`**:
  - Polymorphically persists and reads `Threat` subclasses using factory reconstruction.
- **`IncidentRepository.java`**:
  - Persists and queries `Incident` cases, hydrating composed `Threat` and `ResponseAction`s.
- **`ResponseActionRepository.java`**:
  - Stores and queries containment audit history.

---

### E. `com.cybershield.exception` (Exception Hierarchy)
- **`CyberShieldException.java`**: Base checked exception extending `java.lang.Exception`.
- **`DatabaseOperationException.java`**: Wraps underlying SQL exceptions with domain context.
- **`AuthenticationException.java`**: User login or credential failures.
- **`ThreatDetectionException.java`**: Rule engine evaluation failures.
- **`IncidentManagementException.java`**: Case escalation and containment action errors.

---

### F. `com.cybershield.util` (Static Utilities)
- **`SecurityUtils.java`**: Pure Java SHA-256 password hashing and random UUID generators.
- **`DateTimeUtils.java`**: Standardized date-time formatting for UI and database.
- **`ValidationUtils.java`**: Regex verification for IP addresses, usernames, and email formats.
- **`SimulationDataGenerator.java`**: Predefined realistic security log payloads.

---

### G. `com.cybershield.ui` (Java Swing Interface)
- **`CyberTheme.java`**: Central palette (`#0B1120`, `#1E293B`, `#06B6D4`, `#10B981`, `#EF4444`) and font tokens.
- **`components/MetricCard.java`**: Rounded card showing title, big metric counter, and subtitle.
- **`components/StyledButton.java`**: Anti-aliased buttons with hover color transition.
- **`components/CyberTable.java`**: Custom `JTable` with alternating dark rows and severity badge renderer.
- **`LoginDialog.java`**: Modal authentication window with credential hints.
- **`MainDashboardFrame.java`**: Top header, sidebar navigation, metric cards, and `CardLayout` container.
- **`panels/TelemetryPanel.java`**: Event table, live search filter, and raw protocol payload viewer.
- **`panels/ThreatMonitorPanel.java`**: Threat queue, polymorphic dossier viewer, and escalation button.
- **`panels/IncidentConsolePanel.java`**: Active cases, containment buttons (Block IP, etc.), and audit log.
- **`panels/AttackSimulatorPanel.java`**: Scenario trigger cards with live console trace output.
- **`panels/AnalyticsPanel.java`**: Category and severity breakdown bars, plus full audit table.
- **`panels/UsersPanel.java`**: Operator table with ADMIN-restricted user addition.
