package cybershield;

import cybershield.database.DatabaseManager;
import cybershield.model.Incident;
import cybershield.model.InvestigationNote;
import cybershield.model.InvestigationSummary;
import cybershield.model.InvestigationTimelineItem;
import cybershield.model.ThreatResponse;
import cybershield.model.User;
import cybershield.security.PasswordUtils;
import cybershield.service.AccessEventService;
import cybershield.service.AccountLockoutService;
import cybershield.service.ActivityLogService;
import cybershield.service.IncidentInvestigationService;
import cybershield.service.IncidentService;
import cybershield.service.IntrusionDetectionService;
import cybershield.service.IpBlockService;
import cybershield.service.ThreatResponseService;
import cybershield.service.UserService;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * IncidentInvestigationServiceTest — Automated validation suite for Review 3 Phase 5.
 *
 * Verifies all 20 requirements:
 * TEST 1: Add an investigation note to an existing incident.
 * TEST 2: Retrieve investigation notes in chronological order.
 * TEST 3: Attempt to add a note to a nonexistent incident rejected.
 * TEST 4: Add multiple notes to the same incident preserved.
 * TEST 5: Assign an existing analyst to an incident.
 * TEST 6: Attempt to assign a nonexistent analyst rejected.
 * TEST 7: Update the root cause category.
 * TEST 8: Add valid structured JSON evidence.
 * TEST 9: Submit malformed JSON evidence rejected.
 * TEST 10: Verify investigator attribution.
 * TEST 11: Resolve an incident with a resolution summary.
 * TEST 12: Verify investigation history survives status changes.
 * TEST 13: Retrieve investigation timeline.
 * TEST 14: Verify activity_log entries.
 * TEST 15: Verify unauthorized or invalid assignment is rejected.
 * TEST 16: Verify database migration preserves existing incidents.
 * TEST 17: Verify deleted incident behavior follows the foreign-key cascade delete.
 * TEST 18: Verify HIGH-severity automatically generated IDS incidents can be investigated.
 * TEST 19: Verify associated threat response records remain accessible.
 * TEST 20: Verify invalid incident status values are rejected.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class IncidentInvestigationServiceTest {

    private static IncidentInvestigationService investigationService;
    private static IncidentService incidentService;
    private static UserService userService;
    private static ActivityLogService activityLogService;
    private static ThreatResponseService threatResponseService;
    private static IpBlockService ipBlockService;

    @BeforeAll
    public static void setUpClass() throws Exception {
        DatabaseManager.initialize();

        activityLogService = new ActivityLogService();
        incidentService = new IncidentService(activityLogService);
        ipBlockService = new IpBlockService();
        threatResponseService = new ThreatResponseService(ipBlockService, incidentService, activityLogService);
        userService = new UserService(new AccessEventService(), activityLogService, new IntrusionDetectionService(), new AccountLockoutService(activityLogService));
        investigationService = new IncidentInvestigationService(incidentService, userService, activityLogService, threatResponseService);

        // Ensure a regular USER role account exists for role-check tests
        ensureUser("standard_user", "User@123", "USER");
    }

    @BeforeEach
    public void setUp() {
        // Safe between-test cleanup if necessary
    }

    private static void ensureUser(String username, String password, String role) throws SQLException {
        try (Connection conn = DatabaseManager.getConnection()) {
            String check = "SELECT id FROM users WHERE username = ?";
            try (PreparedStatement pstmt = conn.prepareStatement(check)) {
                pstmt.setString(1, username);
                try (ResultSet rs = pstmt.executeQuery()) {
                    if (rs.next()) return;
                }
            }
            String salt = PasswordUtils.generateSalt();
            String hash = PasswordUtils.hashPassword(password, salt);
            String now = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            String insert = "INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)";
            try (PreparedStatement pstmt = conn.prepareStatement(insert)) {
                pstmt.setString(1, username);
                pstmt.setString(2, hash);
                pstmt.setString(3, salt);
                pstmt.setString(4, role);
                pstmt.setString(5, now);
                pstmt.executeUpdate();
            }
        }
    }

    private Incident createTestIncident(String title, String severity, String status) {
        Incident inc = new Incident();
        inc.setTitle(title);
        inc.setDescription("Synthetic test incident description for " + title);
        inc.setSeverity(severity);
        inc.setStatus(status);
        return incidentService.create(inc, "admin");
    }

    @Test
    @Order(1)
    @DisplayName("TEST 1: Add an investigation note to an existing incident")
    public void test1_AddInvestigationNoteToExistingIncident() {
        Incident incident = createTestIncident("Phishing Campaign Alert", "MEDIUM", "OPEN");
        assertNotNull(incident);
        assertTrue(incident.getId() > 0);

        InvestigationNote note = investigationService.addInvestigationNote(
                incident.getId(), "analyst", "Initial triage initiated: Analyzing phishing email headers.", null
        );

        assertNotNull(note);
        assertTrue(note.getId() > 0);
        assertEquals(incident.getId(), note.getIncidentId());
        assertEquals("analyst", note.getAnalystUsername());
        assertEquals("Initial triage initiated: Analyzing phishing email headers.", note.getNotes());
        assertNull(note.getEvidenceData());
        assertTrue(note.getCreatedAt() > 0);
    }

    @Test
    @Order(2)
    @DisplayName("TEST 2: Retrieve investigation notes in chronological order")
    public void test2_RetrieveInvestigationNotesChronological() throws Exception {
        Incident incident = createTestIncident("Suspicious SSH Logins", "HIGH", "OPEN");

        investigationService.addInvestigationNote(incident.getId(), "analyst", "First chronological note: port scan identified", null);
        Thread.sleep(15);
        investigationService.addInvestigationNote(incident.getId(), "analyst", "Second chronological note: malicious IP matched threat list", null);

        List<InvestigationNote> notes = investigationService.getInvestigationNotes(incident.getId());
        assertNotNull(notes);
        assertEquals(2, notes.size());
        assertTrue(notes.get(0).getCreatedAt() <= notes.get(1).getCreatedAt());
        assertTrue(notes.get(0).getNotes().contains("First chronological note"));
        assertTrue(notes.get(1).getNotes().contains("Second chronological note"));
    }

    @Test
    @Order(3)
    @DisplayName("TEST 3: Attempt to add a note to a nonexistent incident rejected")
    public void test3_AttemptToAddNoteToNonexistentIncident_Rejected() {
        assertThrows(IllegalArgumentException.class, () -> {
            investigationService.addInvestigationNote(999999, "analyst", "Testing non-existent incident", null);
        });
    }

    @Test
    @Order(4)
    @DisplayName("TEST 4: Add multiple notes to the same incident preserved")
    public void test4_AddMultipleNotesToSameIncident() {
        Incident incident = createTestIncident("DDoS Activity Detected", "HIGH", "OPEN");

        investigationService.addInvestigationNote(incident.getId(), "analyst", "Evidence 1: Rate limiter triggered", null);
        investigationService.addInvestigationNote(incident.getId(), "admin", "Evidence 2: Upstream ISP notified", null);
        investigationService.addInvestigationNote(incident.getId(), "analyst", "Evidence 3: Packet capture stored", null);

        List<InvestigationNote> notes = investigationService.getInvestigationNotes(incident.getId());
        assertEquals(3, notes.size());
        assertEquals("Evidence 1: Rate limiter triggered", notes.get(0).getNotes());
        assertEquals("Evidence 2: Upstream ISP notified", notes.get(1).getNotes());
        assertEquals("Evidence 3: Packet capture stored", notes.get(2).getNotes());
    }

    @Test
    @Order(5)
    @DisplayName("TEST 5: Assign an existing analyst to an incident")
    public void test5_AssignExistingAnalystToIncident() {
        Incident incident = createTestIncident("Malware Outbreak Host 14", "CRITICAL", "OPEN");
        assertEquals("OPEN", incident.getStatus());
        assertNull(incident.getAssignedTo());

        Incident updated = investigationService.assignInvestigator(incident.getId(), "analyst", "admin");
        assertNotNull(updated);
        assertEquals("analyst", updated.getAssignedTo());
        assertEquals("INVESTIGATING", updated.getStatus(), "Assigning investigator to OPEN incident transitions status to INVESTIGATING");

        Incident reloaded = incidentService.getById(incident.getId());
        assertEquals("analyst", reloaded.getAssignedTo());
        assertEquals("INVESTIGATING", reloaded.getStatus());
    }

    @Test
    @Order(6)
    @DisplayName("TEST 6: Attempt to assign a nonexistent analyst rejected")
    public void test6_AttemptToAssignNonexistentAnalyst_Rejected() {
        Incident incident = createTestIncident("Ransomware Note Found", "CRITICAL", "OPEN");

        assertThrows(IllegalArgumentException.class, () -> {
            investigationService.assignInvestigator(incident.getId(), "ghost_analyst_not_real", "admin");
        });
    }

    @Test
    @Order(7)
    @DisplayName("TEST 7: Update the root cause category")
    public void test7_UpdateRootCauseCategory() {
        Incident incident = createTestIncident("Repeated Auth Failures", "HIGH", "OPEN");

        Incident updated = investigationService.updateRootCause(
                incident.getId(), "BRUTE_FORCE_ATTACK", "Dictionary attack on admin portal from single subnet", "analyst"
        );

        assertNotNull(updated);
        assertEquals("BRUTE_FORCE_ATTACK", updated.getRootCauseCategory());

        Incident reloaded = incidentService.getById(incident.getId());
        assertEquals("BRUTE_FORCE_ATTACK", reloaded.getRootCauseCategory());
    }

    @Test
    @Order(8)
    @DisplayName("TEST 8: Add valid structured JSON evidence")
    public void test8_AddValidStructuredJsonEvidence() {
        Incident incident = createTestIncident("API Abuse Spike", "MEDIUM", "OPEN");
        String validJson = "{\"evidenceType\":\"LOGIN_ACTIVITY\",\"sourceIp\":\"198.51.100.50\",\"attempts\":5,\"reference\":\"FAILED_LOGIN_EVENT\"}";

        InvestigationNote note = investigationService.addInvestigationNote(
                incident.getId(), "analyst", "Extracted structured login attempt evidence", validJson
        );

        assertNotNull(note);
        assertEquals(validJson, note.getEvidenceData());

        List<InvestigationNote> notes = investigationService.getInvestigationNotes(incident.getId());
        assertEquals(1, notes.size());
        assertEquals(validJson, notes.get(0).getEvidenceData());
    }

    @Test
    @Order(9)
    @DisplayName("TEST 9: Submit malformed JSON evidence rejected")
    public void test9_SubmitMalformedJsonEvidence_Rejected() {
        Incident incident = createTestIncident("Database Tampering Alert", "CRITICAL", "OPEN");
        String brokenJson = "{\"evidenceType\": \"UNTERMINATED_JSON, missing closing bracket";

        assertThrows(IllegalArgumentException.class, () -> {
            investigationService.addInvestigationNote(incident.getId(), "analyst", "Corrupt payload test", brokenJson);
        });
    }

    @Test
    @Order(10)
    @DisplayName("TEST 10: Verify investigator attribution")
    public void test10_VerifyInvestigatorAttribution() {
        Incident incident = createTestIncident("Unauthorized File Modification", "HIGH", "OPEN");

        InvestigationNote analystNote = investigationService.addInvestigationNote(
                incident.getId(), "analyst", "Note from security analyst", null
        );
        InvestigationNote adminNote = investigationService.addInvestigationNote(
                incident.getId(), "admin", "Note from SOC administrator", null
        );

        assertEquals("analyst", analystNote.getAnalystUsername());
        assertEquals("admin", adminNote.getAnalystUsername());

        List<InvestigationNote> notes = investigationService.getInvestigationNotes(incident.getId());
        assertEquals(2, notes.size());
        assertEquals("analyst", notes.get(0).getAnalystUsername());
        assertEquals("admin", notes.get(1).getAnalystUsername());
    }

    @Test
    @Order(11)
    @DisplayName("TEST 11: Resolve an incident with a resolution summary")
    public void test11_ResolveIncidentWithResolutionSummary() {
        Incident incident = createTestIncident("Compromised Workstation", "HIGH", "OPEN");

        boolean resolved = investigationService.resolveIncident(
                incident.getId(), "Host isolated, credentials rotated, antivirus full scan completed clean.", "analyst"
        );
        assertTrue(resolved);

        Incident reloaded = incidentService.getById(incident.getId());
        assertNotNull(reloaded);
        assertEquals("RESOLVED", reloaded.getStatus());
        assertEquals("Host isolated, credentials rotated, antivirus full scan completed clean.", reloaded.getResolutionSummary());
    }

    @Test
    @Order(12)
    @DisplayName("TEST 12: Verify investigation history survives status changes")
    public void test12_VerifyInvestigationHistorySurvivesStatusChanges() {
        Incident incident = createTestIncident("Data Exfiltration Attempt", "CRITICAL", "OPEN");

        // Add 2 notes while OPEN
        investigationService.addInvestigationNote(incident.getId(), "analyst", "Note 1: Wireshark packet capture analysis", "{\"bytes\":4096}");
        investigationService.addInvestigationNote(incident.getId(), "admin", "Note 2: Firewall egress rule engaged", null);

        // Transition through lifecycle: OPEN -> INVESTIGATING -> RESOLVED -> CLOSED
        incident.setStatus("INVESTIGATING");
        incidentService.update(incident.getId(), incident, "analyst");

        investigationService.resolveIncident(incident.getId(), "Outbound connections dropped, target IP blocked.", "analyst");

        Incident resolvedIncident = incidentService.getById(incident.getId());
        resolvedIncident.setStatus("CLOSED");
        incidentService.update(incident.getId(), resolvedIncident, "admin");

        Incident closedIncident = incidentService.getById(incident.getId());
        assertEquals("CLOSED", closedIncident.getStatus());

        // Verify notes and evidence are completely preserved
        List<InvestigationNote> notes = investigationService.getInvestigationNotes(incident.getId());
        assertEquals(2, notes.size());
        assertEquals("Note 1: Wireshark packet capture analysis", notes.get(0).getNotes());
        assertEquals("{\"bytes\":4096}", notes.get(0).getEvidenceData());
        assertEquals("Note 2: Firewall egress rule engaged", notes.get(1).getNotes());
    }

    @Test
    @Order(13)
    @DisplayName("TEST 13: Retrieve investigation timeline")
    public void test13_RetrieveInvestigationTimeline() {
        Incident incident = createTestIncident("Timeline Verification Incident", "MEDIUM", "OPEN");

        investigationService.assignInvestigator(incident.getId(), "analyst", "admin");
        investigationService.addInvestigationNote(incident.getId(), "analyst", "Timeline note added by analyst", null);

        // Record a mock defensive response linked to this incident
        ThreatResponse tr = new ThreatResponse(
                incident.getId(), "BRUTE_FORCE_ATTACK", "AUTO_BLOCK_IP", "192.0.2.11", "EXECUTED",
                System.currentTimeMillis(), "Automated 15-minute defensive block"
        );
        threatResponseService.recordResponse(tr);

        List<InvestigationTimelineItem> timeline = investigationService.getInvestigationTimeline(incident.getId());
        assertNotNull(timeline);
        assertTrue(timeline.size() >= 3, "Timeline must aggregate incident creation, assignments, notes, and threat responses");

        // Verify chronological ordering
        for (int i = 0; i < timeline.size() - 1; i++) {
            assertTrue(timeline.get(i).getTimestamp() <= timeline.get(i + 1).getTimestamp(),
                    "Timeline item " + i + " must occur before or equal to item " + (i + 1));
        }

        // Verify events exist
        boolean hasCreation = timeline.stream().anyMatch(item -> "INCIDENT_CREATED".equals(item.getEventType()));
        boolean hasNote = timeline.stream().anyMatch(item -> "INVESTIGATION_NOTE_ADDED".equals(item.getEventType()));
        boolean hasThreat = timeline.stream().anyMatch(item -> item.getEventType().startsWith("THREAT_RESPONSE"));

        assertTrue(hasCreation, "Timeline must contain INCIDENT_CREATED milestone");
        assertTrue(hasNote, "Timeline must contain INVESTIGATION_NOTE_ADDED milestone");
        assertTrue(hasThreat, "Timeline must contain THREAT_RESPONSE milestone");
    }

    @Test
    @Order(14)
    @DisplayName("TEST 14: Verify activity_log entries")
    public void test14_VerifyActivityLogEntries() {
        Incident incident = createTestIncident("Audit Log Verification Incident", "LOW", "OPEN");

        investigationService.assignInvestigator(incident.getId(), "analyst", "admin");
        investigationService.addInvestigationNote(incident.getId(), "analyst", "Audit check note", null);
        investigationService.updateRootCause(incident.getId(), "SUSPICIOUS_LOGIN_ACTIVITY", "Irregular hours login", "analyst");
        investigationService.resolveIncident(incident.getId(), "User confirmed legitimate off-hours work.", "analyst");

        List<cybershield.model.ActivityLog> logs = activityLogService.getAll(50);
        assertNotNull(logs);

        boolean hasAssignment = logs.stream().anyMatch(l -> "INVESTIGATOR_ASSIGNED".equals(l.getAction()) && l.getDetails().contains("#" + incident.getId()));
        boolean hasNoteAdded = logs.stream().anyMatch(l -> "INVESTIGATION_NOTE_ADDED".equals(l.getAction()) && l.getDetails().contains("#" + incident.getId()));
        boolean hasRootCause = logs.stream().anyMatch(l -> "ROOT_CAUSE_UPDATED".equals(l.getAction()) && l.getDetails().contains("#" + incident.getId()));
        boolean hasResolved = logs.stream().anyMatch(l -> "INCIDENT_RESOLVED".equals(l.getAction()) && l.getDetails().contains("#" + incident.getId()));

        assertTrue(hasAssignment, "Must log INVESTIGATOR_ASSIGNED in activity_log");
        assertTrue(hasNoteAdded, "Must log INVESTIGATION_NOTE_ADDED in activity_log");
        assertTrue(hasRootCause, "Must log ROOT_CAUSE_UPDATED in activity_log");
        assertTrue(hasResolved, "Must log INCIDENT_RESOLVED in activity_log");
    }

    @Test
    @Order(15)
    @DisplayName("TEST 15: Verify unauthorized or invalid assignment is rejected")
    public void test15_VerifyUnauthorizedOrInvalidAssignmentRejected() {
        Incident incident = createTestIncident("Privilege Escalation Check", "HIGH", "OPEN");

        // standard_user has role "USER", which is not allowed to be an investigator
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> {
            investigationService.assignInvestigator(incident.getId(), "standard_user", "admin");
        });
        assertTrue(ex.getMessage().contains("role must be ANALYST or ADMIN") || ex.getMessage().contains("not authorized"));

        // Non-analyst adding notes should also be rejected
        assertThrows(IllegalArgumentException.class, () -> {
            investigationService.addInvestigationNote(incident.getId(), "standard_user", "Unauthorized note", null);
        });
    }

    @Test
    @Order(16)
    @DisplayName("TEST 16: Verify database migration preserves existing incidents")
    public void test16_VerifyDatabaseMigrationPreservesExistingIncidents() throws SQLException {
        // Query database directly to confirm schema columns and record preservation
        try (Connection conn = DatabaseManager.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT id, title, assigned_to, root_cause_category, resolution_summary FROM incidents LIMIT 5")) {

            int count = 0;
            while (rs.next()) {
                count++;
                assertTrue(rs.getInt("id") > 0);
                assertNotNull(rs.getString("title"));
                // New columns exist and can be safely read as null or string without error
                rs.getString("assigned_to");
                rs.getString("root_cause_category");
                rs.getString("resolution_summary");
            }
            assertTrue(count > 0, "Pre-existing incidents must be preserved after Review 3 migration");
        }
    }

    @Test
    @Order(17)
    @DisplayName("TEST 17: Verify deleted incident behavior follows the foreign-key cascade")
    public void test17_VerifyDeletedIncidentFollowsCascadeDelete() throws SQLException {
        Incident incident = createTestIncident("Transient Incident to Delete", "LOW", "OPEN");
        int incId = incident.getId();

        investigationService.addInvestigationNote(incId, "analyst", "Transient Note 1", null);
        investigationService.addInvestigationNote(incId, "analyst", "Transient Note 2", null);

        assertEquals(2, investigationService.getInvestigationNotes(incId).size());

        // Delete incident
        boolean deleted = incidentService.delete(incId, "admin");
        assertTrue(deleted, "Incident deletion must succeed");

        // Verify investigation notes were cascade deleted
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement("SELECT COUNT(*) FROM incident_investigations WHERE incident_id = ?")) {
            pstmt.setInt(1, incId);
            try (ResultSet rs = pstmt.executeQuery()) {
                assertTrue(rs.next());
                assertEquals(0, rs.getInt(1), "Investigation notes must be cascade deleted when incident is deleted");
            }
        }
        assertTrue(investigationService.getInvestigationNotes(incId).isEmpty());
    }

    @Test
    @Order(18)
    @DisplayName("TEST 18: Verify HIGH-severity automatically generated IDS incidents can be investigated")
    public void test18_VerifyHighSeverityIdsIncidentCanBeInvestigated() {
        // Simulate auto-generated IDS incident
        Incident idsIncident = new Incident();
        idsIncident.setTitle("Automated IDS: Brute-Force Attack Detected (198.51.100.77)");
        idsIncident.setDescription("Automated intrusion detection: 5 failed logins within sliding window");
        idsIncident.setSeverity("HIGH");
        idsIncident.setStatus("OPEN");
        Incident created = incidentService.create(idsIncident, "SYSTEM_IDS");
        assertNotNull(created);

        // SOC Triage Workflow
        investigationService.assignInvestigator(created.getId(), "analyst", "admin");
        investigationService.addInvestigationNote(
                created.getId(), "analyst", "Corroborated 5 consecutive failed logins for target user 'admin'",
                "{\"sourceIp\":\"198.51.100.77\",\"attempts\":5,\"rule\":\"BRUTE_FORCE_DETECTION\"}"
        );
        investigationService.updateRootCause(created.getId(), "BRUTE_FORCE_ATTACK", "Password spray from external IP", "analyst");
        investigationService.resolveIncident(created.getId(), "Source IP blocked for 15 minutes, analyst verified no lateral movement.", "analyst");

        InvestigationSummary summary = investigationService.getInvestigationSummary(created.getId());
        assertNotNull(summary);
        assertEquals(created.getId(), summary.getIncidentId());
        assertEquals("HIGH", summary.getSeverity());
        assertEquals("RESOLVED", summary.getStatus());
        assertEquals("analyst", summary.getAssignedInvestigator());
        assertEquals("BRUTE_FORCE_ATTACK", summary.getRootCauseCategory());
        assertEquals(1, summary.getTotalInvestigationNotes());
        assertTrue(summary.getResolutionSummary().contains("Source IP blocked"));
    }

    @Test
    @Order(19)
    @DisplayName("TEST 19: Verify associated threat response records remain accessible")
    public void test19_VerifyAssociatedThreatResponseRecordsRemainAccessible() {
        Incident incident = createTestIncident("Linked Threat Response Incident", "HIGH", "OPEN");

        ThreatResponse tr = new ThreatResponse(
                incident.getId(), "BRUTE_FORCE_ATTACK", "AUTO_BLOCK_IP", "203.0.113.88", "EXECUTED",
                System.currentTimeMillis(), "Automated containment active"
        );
        threatResponseService.recordResponse(tr);

        List<ThreatResponse> responses = threatResponseService.getResponseHistory(incident.getId(), null, "ALL");
        assertNotNull(responses);
        assertEquals(1, responses.size());
        assertEquals("203.0.113.88", responses.get(0).getTargetIdentifier());

        InvestigationSummary summary = investigationService.getInvestigationSummary(incident.getId());
        assertNotNull(summary);
        assertTrue(summary.getTotalThreatResponses() >= 1);
    }

    @Test
    @Order(20)
    @DisplayName("TEST 20: Verify invalid incident status values are rejected")
    public void test20_VerifyInvalidIncidentStatusValuesAreRejected() {
        Incident incident = createTestIncident("Strict Status Validation Incident", "MEDIUM", "OPEN");

        // IN_PROGRESS is strictly forbidden by Review 3 requirements
        incident.setStatus("IN_PROGRESS");
        assertThrows(IllegalArgumentException.class, () -> {
            incidentService.update(incident.getId(), incident, "analyst");
        });

        // Arbitrary bogus status values must also be rejected
        incident.setStatus("PENDING_REVIEW");
        assertThrows(IllegalArgumentException.class, () -> {
            incidentService.update(incident.getId(), incident, "analyst");
        });

        // Valid canonical statuses must succeed
        incident.setStatus("INVESTIGATING");
        assertTrue(incidentService.update(incident.getId(), incident, "analyst"));

        incident.setStatus("RESOLVED");
        assertTrue(incidentService.update(incident.getId(), incident, "analyst"));

        incident.setStatus("CLOSED");
        assertTrue(incidentService.update(incident.getId(), incident, "analyst"));
    }
}
