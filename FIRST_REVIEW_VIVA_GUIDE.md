# CYBERSHIELD — First Review Viva & Code Defense Guide (October 1st)

**Project Title:** CYBERSHIELD — Cybersecurity Threat Monitoring & Incident Response System  
**Course:** Advanced Object-Oriented Programming (AOOP) — Java  
**Evaluation Date:** October 1st, 2026 (First Review: Front-End Java Swing GUI & Code Viva)  
**Team Members:**
- **Member 1 (Team Lead & Database/Architecture):** Parthab Sarkar (Roll: `23BCSE0101` - Editable in-app)
- **Member 2 (Detection & Heuristic Simulation):** Team Member 2 (Roll: `23BCSE0102` - Editable in-app)
- **Member 3 (UI & Incident Workflows):** Team Member 3 (Roll: `23BCSE0103` - Editable in-app)

---

## 🎯 Review Evaluation Criteria & How CYBERSHIELD Scores 10/10

| Criterion | Professor / Examiner Focus | CYBERSHIELD Implementation & Code Defense |
| :--- | :--- | :--- |
| **1. Number of GUI Components** | *"Marks will be awarded based on how many components you added in the GUI (you have to add almost all Java Swing components)."* | **35 distinct Java Swing components** fully implemented, styled in dark SOC theme, and active in the functional workflows. A live audit checklist is embedded directly in the running application under **Review 1 Team Dossier**! |
| **2. Answering Questions from Code** | *"Marks will be awarded based on how you are answering the questions (Questions will be asked from Code)."* | Every subsystem is cleanly mapped to its exact Java source files, line numbers, event listeners, layout managers, and AOOP principles. |

---

## PART 1: The 35 Java Swing Components & Code Mapping

When the examiner asks: *"Show me the Swing components you added in the code"*, navigate to the corresponding files or open the running application and click **"🎓 Review 1 Team Dossier" $\to$ "📋 Swing Components Audit"**.

```
Component Category breakdown:
├── Top-Level Windows: JFrame, JDialog
├── Structural Containers: JPanel, JScrollPane, JSplitPane, JTabbedPane
├── Menu & Toolbars: JMenuBar, JMenu, JMenuItem, JCheckBoxMenuItem, JRadioButtonMenuItem, JToolBar, JSeparator
├── Interactive Selectors: JComboBox, JRadioButton, ButtonGroup, JCheckBox, JToggleButton, JSlider, JSpinner
├── Text & Inputs: JLabel, JButton, JTextField, JPasswordField, JTextArea, JTextPane
├── Complex Data Displays: JTable, JTree, JList
├── Dynamic Feedback: JProgressBar, JToolTip, JOptionPane
└── System Dialogs: JFileChooser, JColorChooser
```

### Detailed Component Inventory:

#### 1. `JFrame` (`javax.swing.JFrame`)
- **File:** [`MainDashboardFrame.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/MainDashboardFrame.java)
- **Role:** Top-level application window hosting header, toolbar, sidebar, and center views.
- **Code Highlights:**
  ```java
  public class MainDashboardFrame extends JFrame {
      super(ProjectMetadata.getProjectTitle());
      setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
      setSize(1320, 880);
      setMinimumSize(new Dimension(1080, 720));
      setLocationRelativeTo(null);
  ```

#### 2. `JDialog` (`javax.swing.JDialog`)
- **Files:** [`LoginDialog.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/LoginDialog.java), [`ProjectTeamDialog.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/dialogs/ProjectTeamDialog.java)
- **Role:** Modal dialog windows that block parent input until completed.
- **Code Highlights:**
  ```java
  public class ProjectTeamDialog extends JDialog {
      public ProjectTeamDialog(Frame owner) {
          super(owner, "CYBERSHIELD — Project Team & Evaluation Details (Review 1)", true);
  ```

#### 3. `JMenuBar`, `JMenu`, `JMenuItem`, `JCheckBoxMenuItem`, `JRadioButtonMenuItem`
- **File:** [`MainDashboardFrame.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/MainDashboardFrame.java)
- **Role:** Desktop menu bar offering File, View, Simulation, Tools, and Review menus.
- **Code Highlights:**
  ```java
  JMenuBar menuBar = new JMenuBar();
  JMenu menuFile = new JMenu("File");
  JMenuItem miExport = new JMenuItem("📁 Export Incident Cases to CSV");
  JCheckBoxMenuItem chkAutoRefresh = new JCheckBoxMenuItem("Auto-Refresh Metrics Timer", true);
  JRadioButtonMenuItem rbStandard = new JRadioButtonMenuItem("Standard Heuristic Engine", true);
  ButtonGroup profileGroup = new ButtonGroup();
  profileGroup.add(rbStandard);
  ```

#### 4. `JToolBar` (`javax.swing.JToolBar`)
- **File:** [`MainDashboardFrame.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/MainDashboardFrame.java)
- **Role:** Rapid action toolbar directly under the header with quick shortcuts.
- **Code Highlights:**
  ```java
  JToolBar bar = new JToolBar("SOC Rapid Action Bar");
  bar.setFloatable(false);
  bar.add(btnTeam);
  bar.addSeparator(new Dimension(8, 20));
  bar.add(tglLiveStream);
  ```

#### 5. `JToggleButton` (`javax.swing.JToggleButton`)
- **File:** [`MainDashboardFrame.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/MainDashboardFrame.java)
- **Role:** Real-time Telemetry Live Stream Pause/Resume toggle switch.
- **Code Highlights:**
  ```java
  tglLiveStream = new JToggleButton("⚡ Live Stream: ON", true);
  tglLiveStream.addActionListener(e -> {
      if (tglLiveStream.isSelected()) {
          tglLiveStream.setText("⚡ Live Stream: ON");
          autoRefreshTimer.start();
      } else {
          tglLiveStream.setText("⏸ Live Stream: PAUSED");
          autoRefreshTimer.stop();
      }
  });
  ```

#### 6. `JTree` (`javax.swing.JTree`) & `TreeSelectionListener`
- **File:** [`MitreAssetTreePanel.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/components/MitreAssetTreePanel.java)
- **Role:** Visualizes hierarchical Enterprise Infrastructure Assets & MITRE ATT&CK Matrix tactics.
- **Code Highlights:**
  ```java
  DefaultMutableTreeNode root = new DefaultMutableTreeNode("🛡 CYBERSHIELD Enterprise SOC Realm");
  DefaultMutableTreeNode perimeter = new DefaultMutableTreeNode("🌐 Perimeter & DMZ Gateway");
  perimeter.add(new DefaultMutableTreeNode("Edge Firewall (198.51.100.1)"));
  root.add(perimeter);

  assetTree = new JTree(root);
  assetTree.addTreeSelectionListener(e -> {
      DefaultMutableTreeNode selected = (DefaultMutableTreeNode) assetTree.getLastSelectedPathComponent();
      if (selected != null) updateInspector(selected);
  });
  ```

#### 7. `JList` (`javax.swing.JList`) & `DefaultListModel`
- **File:** [`BlockedIpsListPanel.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/components/BlockedIpsListPanel.java)
- **Role:** Active perimeter firewall blocked IP droplist with live add and unblock triggers.
- **Code Highlights:**
  ```java
  DefaultListModel<String> listModel = new DefaultListModel<>();
  JList<String> ipList = new JList<>(listModel);
  ipList.addListSelectionListener(e -> {
      String selected = ipList.getSelectedValue();
      lblSelectedInfo.setText("Selected rule: " + selected);
  });
  ```

#### 8. `JSlider` (`javax.swing.JSlider`) & `ChangeListener`
- **Files:** [`ThreatMonitorPanel.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/panels/ThreatMonitorPanel.java), [`AttackSimulatorPanel.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/panels/AttackSimulatorPanel.java)
- **Role:** Threat sensitivity threshold filter (0-100%) and simulation pacing delay slider.
- **Code Highlights:**
  ```java
  sliderSeverity = new JSlider(0, 100, 0);
  sliderSeverity.addChangeListener(e -> {
      lblSliderVal.setText(sliderSeverity.getValue() + "%");
      applyFilters();
  });
  ```

#### 9. `JSpinner` (`javax.swing.JSpinner`) & `SpinnerNumberModel`
- **Files:** [`MainDashboardFrame.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/MainDashboardFrame.java), [`TelemetryPanel.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/panels/TelemetryPanel.java)
- **Role:** Auto-refresh rate spinner (1-60s) and telemetry row fetch limit (10-500).
- **Code Highlights:**
  ```java
  spinAutoRefresh = new JSpinner(new SpinnerNumberModel(5, 1, 60, 1));
  spinAutoRefresh.addChangeListener(e -> {
      int secs = (int) spinAutoRefresh.getValue();
      autoRefreshTimer.setDelay(secs * 1000);
  });
  ```

#### 10. `JProgressBar` (`javax.swing.JProgressBar`)
- **Files:** [`AnalyticsPanel.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/panels/AnalyticsPanel.java), [`AttackSimulatorPanel.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/panels/AttackSimulatorPanel.java)
- **Role:** Threat category metric meters and live animated simulation execution progress.
- **Code Highlights:**
  ```java
  progressBar = new JProgressBar(0, 100);
  progressBar.setStringPainted(true);
  // Updated across thread steps:
  SwingUtilities.invokeLater(() -> {
      progressBar.setValue(val);
      progressBar.setString(status + " (" + val + "%)");
  });
  ```

#### 11. `JTextPane` (`javax.swing.JTextPane`)
- **File:** [`ThreatMonitorPanel.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/panels/ThreatMonitorPanel.java)
- **Role:** Renders rich HTML-formatted threat investigative dossiers with colored status badges.
- **Code Highlights:**
  ```java
  txtHtmlDossier = new JTextPane();
  txtHtmlDossier.setContentType("text/html");
  txtHtmlDossier.setEditable(false);
  txtHtmlDossier.setText("<html>...<h2>THREAT DOSSIER</h2>...</html>");
  ```

#### 12. `JSplitPane` (`javax.swing.JSplitPane`)
- **Files:** [`ThreatMonitorPanel.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/panels/ThreatMonitorPanel.java), [`TelemetryPanel.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/panels/TelemetryPanel.java)
- **Role:** Resizable divider between upper master table and lower detailed dossier/payload views.
- **Code Highlights:**
  ```java
  JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, bottomTabs);
  splitPane.setResizeWeight(0.50);
  splitPane.setDividerSize(6);
  ```

#### 13. `JTabbedPane` (`javax.swing.JTabbedPane`)
- **Files:** [`AnalyticsPanel.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/panels/AnalyticsPanel.java), [`ThreatMonitorPanel.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/panels/ThreatMonitorPanel.java), [`ProjectTeamDialog.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/dialogs/ProjectTeamDialog.java)
- **Role:** Multi-tab views organizing tables, charts, trees, and viva checklists.
- **Code Highlights:**
  ```java
  JTabbedPane tabbedPane = new JTabbedPane();
  tabbedPane.addTab("📊 Visual Progress Metrics", pnlMetricsTab);
  tabbedPane.addTab("📋 Swing Components Catalog", createComponentsCatalogTab());
  tabbedPane.addTab("💡 Code Viva Defense Cheat Sheet", createVivaGuideTab());
  ```

#### 14. `JPopupMenu` (`javax.swing.JPopupMenu`)
- **Files:** [`ThreatMonitorPanel.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/panels/ThreatMonitorPanel.java), [`TelemetryPanel.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/panels/TelemetryPanel.java)
- **Role:** Right-click context menus on table rows (Escalate, Copy IP, Block, Inspect).
- **Code Highlights:**
  ```java
  JPopupMenu popupMenu = new JPopupMenu();
  JMenuItem miEscalate = new JMenuItem("▲ Escalate to Incident Case");
  miEscalate.addActionListener(e -> escalateSelectedThreat());
  popupMenu.add(miEscalate);
  threatTable.setComponentPopupMenu(popupMenu);
  ```

#### 15. `JFileChooser` (`javax.swing.JFileChooser`)
- **Files:** [`MainDashboardFrame.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/MainDashboardFrame.java), [`TelemetryPanel.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/panels/TelemetryPanel.java)
- **Role:** Native OS file chooser dialog allowing export of incident reports and telemetry logs to real `.csv` files.
- **Code Highlights:**
  ```java
  JFileChooser chooser = new JFileChooser();
  chooser.setDialogTitle("Export Incident Cases to CSV (JFileChooser)");
  chooser.setFileFilter(new FileNameExtensionFilter("CSV Files (*.csv)", "csv"));
  int ret = chooser.showSaveDialog(this);
  if (ret == JFileChooser.APPROVE_OPTION) {
      File target = chooser.getSelectedFile();
      // writes data to CSV
  }
  ```

#### 16. `JColorChooser` (`javax.swing.JColorChooser`)
- **File:** [`MainDashboardFrame.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/MainDashboardFrame.java)
- **Role:** Live interactive color chooser dialog allowing the examiner to select and apply custom SOC accent colors in real time.
- **Code Highlights:**
  ```java
  Color newColor = JColorChooser.showDialog(this, "Select SOC Terminal Accent Color", CyberTheme.ACCENT_CYAN);
  if (newColor != null) {
      CyberTheme.setAccentColor(newColor);
      repaint();
  }
  ```

---

## PART 2: Core Code Viva Questions & Exact Answers

### Category A: Java Swing Front-End Architecture

#### Q1: "What is the Event Dispatch Thread (EDT) and how do you guarantee thread safety?"
**Answer:**
> *"Java Swing components are single-threaded and are not thread-safe. All modifications to GUI components (such as updating labels, repainting, or adding table rows) must occur on the **Event Dispatch Thread (EDT)**.  
> In our project:
> 1. In `Main.java`, we bootstrap the application using:
>    ```java
>    SwingUtilities.invokeLater(() -> {
>        LoginDialog login = new LoginDialog(null);
>        ...
>    });
>    ```
> 2. In `AttackSimulatorPanel.java`, attack scenarios involve waiting periods and heavy heuristics. If executed on the EDT, the GUI would freeze. Hence, we spawn a background worker thread:
>    ```java
>    new Thread(() -> {
>        // background simulation
>        updateProgress(50, "Evaluating heuristics");
>    }).start();
>    ```
> 3. Inside `updateProgress()`, we dispatch the update back onto the EDT:
>    ```java
>    SwingUtilities.invokeLater(() -> {
>        progressBar.setValue(val);
>        progressBar.setString(status + " (" + val + "%)");
>    });
>    ```
> This guarantees the UI remains responsive without concurrency conflicts."*

#### Q2: "Which Layout Managers did you use and why didn't you use Absolute Positioning (null layout)?"
**Answer:**
> *"We strictly avoided `setLayout(null)` because absolute positioning breaks across different screen resolutions, OS scaling factors, and font sizes. Instead, we combined four standard layout managers:
> - **`BorderLayout`**: Used in `MainDashboardFrame`, dividing the window into NORTH (Header & ToolBar), WEST (Sidebar navigation), and CENTER (Dynamic views).
> - **`CardLayout`**: Used in `centerCardContainer`. It allows instantaneous switching between views (`DASHBOARD`, `TELEMETRY`, `THREATS`, `INCIDENTS`, `SIMULATOR`, `ANALYTICS`, `TREE`, `DROPLIST`, `USERS`) by key without re-instantiating panels.
> - **`GridLayout`**: Used for the top 5 Metric Cards and scenario buttons, guaranteeing uniform sizes.
> - **`FlowLayout`**: Used for search bars, action toolbars, and button strips."*

#### Q3: "Explain how `JTable` and `DefaultTableModel` work together in your project."
**Answer:**
> *"Swing follows the Model-View-Controller (MVC) pattern. `CyberTable` extends `JTable` (the View), while `DefaultTableModel` acts as the Model holding rows and column vectors.  
> To make tables read-only so analysts cannot accidentally overwrite security logs in the grid, we override `isCellEditable()`:
> ```java
> tableModel = new DefaultTableModel(columns, 0) {
>     @Override
>     public boolean isCellEditable(int row, int col) {
>         return false;
>     }
> };
> ```
> We also attached `ListSelectionListener` to `threatTable.getSelectionModel()` to listen for row selection and update the dossier pane below."*

---

### Category B: Advanced Object-Oriented Programming (AOOP)

#### Q4: "Where is Runtime Polymorphism used in your project? Show me the exact lines of code."
**Answer:**
> *"Runtime polymorphism is used in two key places:
> 1. **Detection Engine (`ThreatDetectionEngine.java`)**:
>    Our engine holds a generic list of detectors:
>    ```java
>    private final List<ThreatDetector> detectors = new ArrayList<>();
>    ```
>    When an event arrives, the engine loops:
>    ```java
>    for (ThreatDetector detector : detectors) {
>        if (detector.canDetect(event)) {
>            Threat threat = detector.detect(event, recentHistory);
>            if (threat != null) detected.add(threat);
>        }
>    }
>    ```
>    At runtime, Java dynamically binds the `detect()` call to `BruteForceDetector`, `PhishingDetector`, `MalwareDetector`, or `SuspiciousLoginDetector`.
>
> 2. **Threat Dossier Generation (`ThreatMonitorPanel.java`)**:
>    When an analyst selects a threat in the `JTable`:
>    ```java
>    selectedThreat = displayedThreats.get(selectedRow);
>    txtReportPreview.setText(selectedThreat.generateIncidentReport());
>    ```
>    Even though `selectedThreat` is of type `Threat`, Java dynamically dispatches to the overridden `generateIncidentReport()` method of `BruteForceThreat`, `PhishingThreat`, etc., without any `if-else` or `instanceof` cascades!"*

#### Q5: "What is the difference between Abstraction and Inheritance in CYBERSHIELD?"
**Answer:**
> *"Abstraction defines contracts without implementation.  
> - `Threat.java` is an **abstract class** that declares abstract methods:
>   ```java
>   public abstract Severity evaluateSeverity();
>   public abstract String generateIncidentReport();
>   public abstract ResponseActionType getRecommendedAction();
>   ```
> - `ThreatDetector.java` is an **interface** that specifies `canDetect()` and `detect()`.
>
> **Inheritance** is code reuse through specialization:
> - Concrete classes like `BruteForceThreat extends Threat` inherit all common state (`threatId`, `sourceIp`, `targetAsset`, `detectedAt`), while providing specialized fields (`failedAttempts`, `windowDurationSeconds`) and implementing the abstract methods."*

#### Q6: "How did you demonstrate Composition in your domain model?"
**Answer:**
> *"Composition models a strong **'HAS-A'** relationship rather than deep inheritance.  
> In [`Incident.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/model/Incident.java):
> - An `Incident` **HAS-A** `Threat`:
>   ```java
>   private Threat associatedThreat;
>   ```
> - An `Incident` **HAS-MANY** `ResponseAction`s:
>   ```java
>   private final List<ResponseAction> responseActions = new ArrayList<>();
>   ```
> An incident cannot exist without its originating threat, and response containment actions belong strictly to that case."*

---

### Category C: Database, JDBC & Persistence

#### Q7: "How do you connect to SQLite and prevent SQL Injection?"
**Answer:**
> *"1. We use the official Xerial SQLite JDBC driver (`sqlite-jdbc`).  
> 2. `DatabaseManager` is implemented as a thread-safe **Singleton**:
>    ```java
>    public static synchronized DatabaseManager getInstance() {
>        if (instance == null) instance = new DatabaseManager();
>        return instance;
>    }
>    ```
> 3. We exclusively use **`PreparedStatement` with parameterized queries (`?`)**:
>    ```java
>    String sql = "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)";
>    try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
>        pstmt.setString(1, user.getUsername());
>        pstmt.setString(2, user.getPasswordHash());
>        pstmt.setString(3, user.getRole().name());
>        pstmt.executeUpdate();
>    }
>    ```
> 4. We use **`try-with-resources`** on all `Connection`, `PreparedStatement`, and `ResultSet` objects, ensuring automatic cleanup even if an exception occurs."*

---

## PART 3: Individual 3-Member Viva Speaking Cards

### 👤 Member 1: Parthab Sarkar (Team Lead & Data Architecture)
- **Subsystem:** Relational SQLite Database, JDBC Repositories, Entity Models, Project Metadata & Custom Checked Exceptions.
- **Key Files to Walk Through:**
  - [`DatabaseManager.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/repository/DatabaseManager.java) (Singleton & Schema initialization)
  - [`SecurityEventRepository.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/repository/SecurityEventRepository.java) (Batch SQL transactions)
  - [`ProjectMetadata.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/util/ProjectMetadata.java) (Properties persistence)
  - [`CyberShieldException.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/exception/CyberShieldException.java) (Exception hierarchy)
- **Viva Opening Line:**
  > *"Respected examiner, I led the core architecture and data layer. I built a decoupled data access layer using native SQLite JDBC. All SQL statements use PreparedStatement to ensure zero vulnerability to SQL Injection, and connections are managed using Java try-with-resources. Our custom exception hierarchy ensures database failures never crash the UI or leak raw stack traces."*

### 👤 Member 2: Team Member 2 (Detection & Heuristic Simulation)
- **Subsystem:** Threat Hierarchy, ThreatDetector Interface, Polymorphic Detection Engine & Attack Simulator.
- **Key Files to Walk Through:**
  - [`Threat.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/model/Threat.java) & concrete subclasses (`BruteForceThreat.java`, etc.)
  - [`ThreatDetector.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/service/detector/ThreatDetector.java) & `BruteForceDetector.java`
  - [`ThreatDetectionEngine.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/service/ThreatDetectionEngine.java)
  - [`AttackSimulatorPanel.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/panels/AttackSimulatorPanel.java)
- **Viva Opening Line:**
  > *"Respected examiner, I implemented the threat hierarchy and heuristic detection engine. We defined an abstract class Threat and concrete attack subclasses. In ThreatDetectionEngine, we maintain a collection of ThreatDetectors and demonstrate genuine runtime polymorphism without hardcoded instanceof checks. On the simulator GUI, I integrated a JProgressBar, execution profile radio buttons, delay slider, and background multithreading."*

### 👤 Member 3: Team Member 3 (Java Swing GUI & Incident Response)
- **Subsystem:** Front-End Java Swing Architecture, 35+ Component Suite, Containment Workflows & Incident Service.
- **Key Files to Walk Through:**
  - [`MainDashboardFrame.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/MainDashboardFrame.java) (JMenuBar, JToolBar, CardLayout)
  - [`ProjectTeamDialog.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/dialogs/ProjectTeamDialog.java) (Review 1 Dossier)
  - [`MitreAssetTreePanel.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/components/MitreAssetTreePanel.java) (`JTree` hierarchy)
  - [`BlockedIpsListPanel.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/components/BlockedIpsListPanel.java) (`JList` droplist)
  - [`IncidentConsolePanel.java`](file:///c:/Users/parth/.gemini/antigravity-ide/scratch/cybershield/src/main/java/com/cybershield/ui/panels/IncidentConsolePanel.java) (Incident containment)
- **Viva Opening Line:**
  > *"Respected examiner, I developed the Java Swing front-end architecture. For our First Review, we implemented 35 distinct Java Swing components, including JTree for asset mapping, JList for active firewall rules, JSplitPane, JTabbedPane, JTextPane for rich HTML dossiers, JPopupMenu for right-click table triggers, and JFileChooser for CSV report export. All UI updates adhere strictly to the Swing Event Dispatch Thread."*
