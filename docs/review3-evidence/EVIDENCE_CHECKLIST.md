# CyberShield Review 3 - Demonstration Evidence & Screenshot Guide
**Target Review Date:** 16 November 2026  
**System:** CyberShield - Automated Cybersecurity Monitoring & Incident Response System  
**Version:** 1.0.0 (Release Candidate - Review 3 Final)

This document provides a structured guide and verification checklist for capturing the 10 core faculty demonstration evidence items and screenshots required for the CyberShield Review 3 examination.

---

## Evidence Checklist Matrix

| # | Demonstration Evidence Item | Component | Verification Command / URL | Status |
|---|-----------------------------|-----------|----------------------------|--------|
| **01** | Web SOC Console with Review 3 Navigation | Web Application | `http://localhost:8080/` (Admin Login) | Verified Ready |
| **02** | Manual & Automated IP Blocking in Web SOC | Web Application | `http://localhost:8080/` &rarr; IP Management Tab | Verified Ready |
| **03** | Account Lockout & Admin Unlock in Web SOC | Web Application | `http://localhost:8080/` &rarr; Account Security Tab | Verified Ready |
| **04** | Automated Threat Response History & Counters | Web Application | `http://localhost:8080/` &rarr; Threat Response Tab | Verified Ready |
| **05** | Incident Investigation Dossier & JSON Evidence | Web Application | `http://localhost:8080/` &rarr; Forensic Dossier Modal | Verified Ready |
| **06** | Java Swing Desktop Application IP Management | Desktop GUI | `IpManagementPanel.java` &rarr; Block/Unblock Dialogs | Verified Ready |
| **07** | Java Swing Threat Response History & Telemetry | Desktop GUI | `ThreatResponsePanel.java` &rarr; Live KPI Cards | Verified Ready |
| **08** | Java Swing Account Security & Unlock Actions | Desktop GUI | `AccountSecurityPanel.java` &rarr; Lock State Table | Verified Ready |
| **09** | Java Swing Forensic Investigation Dossier | Desktop GUI | `InvestigationDialog.java` &rarr; JSON Viewer | Verified Ready |
| **10** | Cross-Application Synchronization Proof | Full Stack | `CrossApplicationSyncTest.java` & Live Demo | Verified Ready |

---

## Detailed Evidence Capture Procedures

### 1. Web SOC Console with Review 3 Navigation
- **Target URL:** `http://localhost:8080/`
- **User Role:** `admin` (Credentials: `admin` / `Admin@123`)
- **Key Visual Elements:**
  - Dark-mode SOC Cyber-Grid navigation bar showing: **Dashboard**, **Incidents**, **IP Management**, **Threat Response**, **Account Security**, **Forensics / Audit**.
  - Review 3 KPI metric tiles: Active Blocked IPs, Locked Accounts, Autonomous Responses, Response Success Rate.
  - Active Security Alert Banner alerting to real-time brute-force triggers.

### 2. Manual and Automated IP Blocking in Web SOC
- **Target Section:** IP Management tab (`#ip-management`)
- **Key Visual Elements:**
  - Dual data tables: **Active IP Blocks** and **Whitelisted IP Addresses / Subnets**.
  - Manual block modal supporting IPv4, CIDR blocks (e.g., `192.168.1.0/24`), and IP ranges (`10.0.0.1-10.0.0.50`).
  - Active block attributes: Target IP/Range, Block Type (`AUTO_THREAT_RESPONSE` vs `MANUAL`), Expiry countdown, Reason, Actions (Unblock button).
  - Built-in CIDR Whitelist preservation (`127.0.0.1`, `::1`, `10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`) with deletion lock preventing self-denial of service.

### 3. Account Lockout Notification & Admin Unlock in Web SOC
- **Target Section:** Account Security tab (`#account-security`)
- **Key Visual Elements:**
  - Locked Accounts table listing: Username, Failed Login Attempts, Locked At timestamp, Auto-Unlock Expiration time, Remaining Lock Duration, Manual Unlock button.
  - Live login testing evidence showing rejection with `HTTP 423 Locked`: *"Account is temporarily locked due to consecutive failed login attempts."*
  - Instant admin unlock action resetting attempts to `0` and removing locked status.

### 4. Automated Threat Response History & Counters
- **Target Section:** Threat Response tab (`#threat-response`)
- **Key Visual Elements:**
  - Executive response metrics: Total Autonomous Mitigations, Successful Blocks, Skipped (Whitelisted), Block Expiration Rate.
  - Comprehensive Threat Response audit table: Response ID, Linked Incident ID, Triggering Alert ID, Target IP, Action (`AUTO_BLOCK_IP`), Status (`EXECUTED` / `SKIPPED_WHITELIST`), Execution Timestamp, Forensic Details.

### 5. Incident Investigation Dossier with Forensic Notes & JSON Evidence Viewer
- **Target Section:** Incident Triage modal (`#investigation-modal`) accessed from Incidents table
- **Key Visual Elements:**
  - Incident Header: ID, Title, Severity badge, Lifecycle Status (`INVESTIGATING` / `CONTAINED` / `RESOLVED`), Assigned Investigator dropdown (`admin`, `analyst`).
  - Chronological Investigation Timeline: Incident Created &rarr; Assigned &rarr; Forensic Evidence Attached &rarr; Status Escalation &rarr; Resolution.
  - Forensic Notes Feed: Author, Timestamp, Root Cause Classification tag, Investigation Findings text, Structured JSON Evidence snippet viewer with formatted syntax highlighting.
  - Add Forensic Note form with root cause dropdown (`BRUTE_FORCE`, `CREDENTIAL_STUFFING`, `PHISHING`, `MALWARE`, `UNAUTHORIZED_ACCESS`).

### 6. Java Swing Desktop Application IP Management Panel
- **Target Component:** `IpManagementPanel.java` in desktop launcher
- **Key Visual Elements:**
  - Swing Table with custom SOC Dark Theme renderer showing active blocked IPs.
  - Toolbar buttons: "Block IP / Subnet", "Unblock Selected", "Refresh".
  - Whitelist viewer panel displaying protected management subnets.
  - Status bar showing active block count and background auto-refresh indicator.

### 7. Java Swing Threat Response History Panel
- **Target Component:** `ThreatResponsePanel.java` in desktop launcher
- **Key Visual Elements:**
  - Top summary cards: Executed Responses, Whitelist Protected, Failed Responses.
  - JTable listing autonomous responses with columns: Response ID, Incident #, Target IP, Action, Execution Time, Status.
  - Search/filter field and manual refresh trigger.

### 8. Java Swing Account Security Panel
- **Target Component:** `AccountSecurityPanel.java` in desktop launcher
- **Key Visual Elements:**
  - Dual view: Locked Accounts list and All System Accounts directory.
  - Table columns: User ID, Username, Role, Failed Attempts, Lock Status, Lock Expiration.
  - Dedicated "Unlock Selected Account" action with confirmation prompt.

### 9. Java Swing Forensic Investigation Dialog
- **Target Component:** `InvestigationDialog.java` launched from Desktop Incidents table
- **Key Visual Elements:**
  - Split-pane interface: Incident Details and Investigator Assignment on left; Forensic Notes and Timeline on right.
  - Structured evidence viewer showing parsed JSON payloads (e.g., failed attempts breakdown, source user agents, timestamps).
  - Status change dropdown enforcing formal investigation transitions (`OPEN` &rarr; `INVESTIGATING` &rarr; `CONTAINED` &rarr; `RESOLVED`).

### 10. Cross-Application Synchronization Proof
- **Target Verification:** Concurrent execution of Web Console (`http://localhost:8080`) and Java Swing GUI
- **Key Visual Elements:**
  - **Scenario A (Web &rarr; Swing):** Admin blocks IP `198.51.100.42` in Web SOC. Within 5 seconds (or upon manual refresh), the IP appears in the Java Swing `IpManagementPanel` table.
  - **Scenario B (Swing &rarr; Web):** Analyst adds a forensic note to Incident #100 with JSON evidence in Java Swing `InvestigationDialog`. The note immediately displays in the Web SOC Console dossier timeline.
  - **Scenario C (Autonomous &rarr; Both):** Automated IDS detects 5 failed logins &rarr; triggers `ThreatResponseService` &rarr; both Web SOC and Swing Desktop simultaneously reflect the new Incident, Security Alert, Blocked IP, and Threat Response record.
