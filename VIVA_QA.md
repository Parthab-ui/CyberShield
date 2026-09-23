# CYBERSHIELD — AOOP Viva Questions & Answers (Master Reference)

This document contains **22 high-yield viva questions and concise, confident answers** tailored specifically to the design and code of **CYBERSHIELD**.

---

### Q1: Why did you choose an abstract class for `Threat` instead of an interface or normal class?
**Answer:**  
`Threat` represents an *is-a* relationship where all threats share common state (`threatId`, `severity`, `sourceIp`, `detectedAt`, `status`) and common logic, but have distinct behaviors that subclasses must implement (`evaluateSeverity()`, `generateIncidentReport()`, `getRecommendedAction()`).  
- An interface cannot hold non-static instance fields.
- A concrete class would allow instantiating a generic, meaningless "Threat".  
An **abstract class** is the exact object-oriented construct designed to provide shared state and partial implementation while enforcing polymorphic behavior in subclasses.

---

### Q2: Why did you use an interface for `ThreatDetector`?
**Answer:**  
`ThreatDetector` represents a *capability* or behavioral contract (`canDetect(event)` and `detect(event)`), rather than shared state. Using an interface allows completely independent detection algorithms (`BruteForceDetector`, `PhishingDetector`, `MalwareDetector`) to be added or modified without being forced into an inheritance hierarchy. It implements the **Strategy Pattern** and adheres to the **Open/Closed Principle** (open for extension, closed for modification).

---

### Q3: Where is Inheritance demonstrated in your project?
**Answer:**  
In the model package:
```text
abstract class Threat
 ├── class BruteForceThreat extends Threat
 ├── class PhishingThreat extends Threat
 ├── class MalwareThreat extends Threat
 └── class SuspiciousLoginThreat extends Threat
```
Each subclass inherits common attributes and methods from `Threat` while adding specialized fields (e.g. `failedAttempts` in `BruteForceThreat`, `fileHash` in `MalwareThreat`).

---

### Q4: Where is Polymorphism demonstrated in your project?
**Answer:**  
We demonstrate both **Compile-time** and **Runtime Polymorphism**:
1. **Method Overriding (Runtime Polymorphism):** In `Threat`, the method `generateIncidentReport()` is overridden by each subclass. When `threat.generateIncidentReport()` is called from UI or service, Java resolves the call dynamically at runtime based on the actual concrete object.
2. **Interface-based Polymorphic Dispatch:** In `ThreatDetectionEngine`, we maintain `List<ThreatDetector>`. The engine iterates through the list calling `detector.canDetect(event)` and `detector.detect(event)` polymorphically without needing `instanceof` or manual type casting.

---

### Q5: What is the exact difference between Abstraction and Encapsulation?
**Answer:**  
- **Abstraction** is about *hiding complexity* and showing only essential features (e.g., `ThreatDetector` exposes `detect()`, hiding internal heuristic complexity). It asks: *"What does the object do?"*
- **Encapsulation** is about *data hiding and bundling*—restricting direct access to an object's internal fields by making them `private` and exposing public getters and validated setters. It asks: *"How does the object protect its data?"*

---

### Q6: Why did you use Composition, and where is it in the codebase?
**Answer:**  
Composition represents a **HAS-A** relationship where an object is composed of other objects.  
In our project:
- `Incident` **HAS-A** `Threat` (`private Threat associatedThreat;`)
- `Incident` **HAS-MANY** `ResponseAction`s (`private List<ResponseAction> responseActions;`)
- `ThreatDetectionEngine` **HAS-MANY** `ThreatDetector`s (`private List<ThreatDetector> detectors;`)  
Composition is preferred here over inheritance because an Incident is *not* a Threat; it *contains* a Threat along with response history.

---

### Q7: Why did you use `ArrayList` in the project?
**Answer:**  
We use `ArrayList` to store linear collections where rapid indexed retrieval and dynamic appending are required—such as log streams (`List<SecurityEvent>`), active threat queues (`List<Threat>`), and response actions (`List<ResponseAction>`). `ArrayList` provides $O(1)$ amortized insertion and $O(1)$ random access.

---

### Q8: Where did you use `HashMap`, and why?
**Answer:**  
In `BruteForceDetector`, we use `Map<String, List<LocalDateTime>> attemptsByUser = new HashMap<>();`.  
It stores failed attempt timestamps keyed by target username. This allows $O(1)$ average time complexity lookup to check and update the failed login counter whenever an authentication event is evaluated.

---

### Q9: Why did you use Enums? Why not just integer constants or Strings?
**Answer:**  
We use Java Enums (`Severity`, `EventType`, `ThreatType`, `ThreatStatus`, `IncidentStatus`, `ResponseActionType`, `UserRole`) to provide:
1. **Type Safety:** Prevents invalid values (e.g., passing `"SUPER_CRITICAL"` or `999` where `Severity` is expected).
2. **Readability & Maintainability:** Enums bundle display names, numerical levels, and hex colors together.
3. **Compile-time checking:** Typos in status strings are caught at compile-time rather than causing silent bugs at runtime.

---

### Q10: How does your Custom Exception hierarchy work?
**Answer:**  
We created a domain-specific hierarchy rooted in `CyberShieldException` (which extends checked `Exception`):
```text
CyberShieldException
 ├── DatabaseOperationException
 ├── AuthenticationException
 ├── ThreatDetectionException
 └── IncidentManagementException
```
This enables granular error recovery (e.g., differentiating an invalid password from a database I/O lockup) and ensures raw SQL stack traces are never exposed directly to the end user.

---

### Q11: What is JDBC, and how does CYBERSHIELD use it?
**Answer:**  
**Java Database Connectivity (JDBC)** is standard Java API for connecting and executing queries against relational databases. In CYBERSHIELD, we use the `org.xerial:sqlite-jdbc` driver. `DatabaseManager` opens connections via `DriverManager.getConnection()`, executes DDL to create tables, and DAO repositories execute SQL operations.

---

### Q12: Why did you use `PreparedStatement` instead of `Statement`?
**Answer:**  
1. **SQL Injection Prevention:** `PreparedStatement` uses parameterized inputs (`?`), ensuring user inputs are treated strictly as data literals, never executable SQL commands.
2. **Pre-compilation & Performance:** The database compiles the SQL template once and executes it repeatedly with different parameters.
3. **Proper Type Handling:** Automatically handles escaping, dates, and null values without error-prone string concatenation.

---

### Q13: Why did you choose SQLite?
**Answer:**  
1. **Serverless & Zero-Configuration:** SQLite runs in-process as a local file (`data/cybershield.db`) without requiring an external server daemon (like MySQL or PostgreSQL).
2. **Reliable College Demo:** The application runs offline on any computer without network dependencies or local database setup issues.
3. **Full ACID Compliance:** Supports atomic transactions, foreign keys, and reliable persistence.

---

### Q14: How does your rule-based threat detection work?
**Answer:**  
When raw events arrive, `ThreatDetectionEngine` dispatches them to registered `ThreatDetector` modules:
- `BruteForceDetector`: Counts failed login attempts within a 120-second window. If $\ge 5$, triggers `BruteForceThreat`.
- `PhishingDetector`: Inspects inbound email payload for deceptive keywords (`verify`, `payroll`) and spoofed links.
- `MalwareDetector`: Checks file extension (`.exe`, `.dll`) and process creation flags.
- `SuspiciousLoginDetector`: Evaluates impossible travel velocity and atypical login hours.

---

### Q15: How does Threat Escalation to an Incident work?
**Answer:**  
When an analyst or simulator escalates a threat:
1. `IncidentService.escalateThreatToIncident(threat, title)` creates a new `Incident` entity containing the threat reference.
2. The incident is saved into the `incidents` table.
3. The threat status is updated from `NEW` to `INVESTIGATING`.
4. The incident appears in the Incident Console for response actions.

---

### Q16: How does Swing Event Handling work in your GUI?
**Answer:**  
Swing uses the **Observer / Event Listener pattern**:
- Components generate events (e.g., `ActionEvent`, `ListSelectionEvent`).
- We attach listeners using lambda expressions (`btn.addActionListener(e -> ...)`) or anonymous classes.
- All GUI updates are dispatched on the **Event Dispatch Thread (EDT)** using `SwingUtilities.invokeLater()` to avoid concurrency and UI freezing issues.

---

### Q17: Why did you use a Layered Architecture?
**Answer:**  
Layered architecture enforces **Separation of Concerns**:
- `model`: Holds domain data and OOP relationships.
- `repository`: Handles database queries and JDBC persistence.
- `service`: Contains business rules, detection logic, and orchestration.
- `ui`: Handles presentation and user events.
- `util` & `exception`: Provides shared helpers and error contracts.  
This makes the code modular, readable, maintainable, and easy to explain in an exam.

---

### Q18: Why did you not hard-code all logic directly inside the GUI classes?
**Answer:**  
Hard-coding database calls and detection algorithms directly inside Swing buttons violates the **Single Responsibility Principle (SRP)**. If the database schema changes, the entire GUI would break. By separating repositories and services from UI panels, the business logic can be tested independently (as proven by our `SmokeTest`), and UI remains lightweight and focused solely on presentation.

---

### Q19: Why is this system an educational simulation rather than a real intrusion tool?
**Answer:**  
1. **Safety & Ethics:** Real exploit tools, packet sniffers, or offensive scripts can cause system instability, breach computer misuse policies, and trigger antivirus flags.
2. **Reliability:** Real network traffic is non-deterministic and can fail during an evaluation. A simulation produces predictable, repeatable results every single time.
3. **Academic Scope:** The goal of an AOOP project is to evaluate Java design principles, data structures, and architecture—not to build a commercial security product.

---

### Q20: How are passwords protected in the database?
**Answer:**  
Passwords are never stored in plaintext. In `SecurityUtils.hashPassword()`, we hash passwords using `MessageDigest.getInstance("SHA-256")`. During login, the entered password is hashed and compared using `MessageDigest` against the stored hash in the SQLite `users` table.

---

### Q21: What happens if an incident response action like "Block IP" is triggered?
**Answer:**  
In our educational simulation:
1. `IncidentService.executeResponseAction()` creates a `ResponseAction` record.
2. The action is persisted in the `response_actions` SQLite table.
3. The action is added to the Incident's composed list (`incident.addResponseAction(action)`).
4. The incident status is updated to `INVESTIGATING`.
5. The audit log table in the GUI updates immediately to reflect the containment record.

---

### Q22: What future improvements could be added to CYBERSHIELD?
**Answer:**  
1. **Network Syslog Listener:** Accepting incoming RFC 5424 Syslog UDP packets from real or virtual network appliances.
2. **Report Exporting:** Generating PDF or CSV post-incident reports using libraries like OpenPDF or Apache Commons CSV.
3. **MITRE ATT&CK Matrix Tagging:** Mapping each detected threat category to formal industry attack technique IDs (e.g., T1110 for Brute Force).
