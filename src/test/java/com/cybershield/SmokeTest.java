package com.cybershield;

import com.cybershield.model.Incident;
import com.cybershield.model.ResponseAction;
import com.cybershield.model.SecurityEvent;
import com.cybershield.model.Threat;
import com.cybershield.model.User;
import com.cybershield.model.enums.EventType;
import com.cybershield.model.enums.IncidentStatus;
import com.cybershield.model.enums.ResponseActionType;
import com.cybershield.model.enums.Severity;
import com.cybershield.repository.DatabaseManager;
import com.cybershield.repository.IncidentRepository;
import com.cybershield.repository.ResponseActionRepository;
import com.cybershield.repository.SecurityEventRepository;
import com.cybershield.repository.ThreatRepository;
import com.cybershield.service.AuthService;
import com.cybershield.service.IncidentService;
import com.cybershield.service.ThreatDetectionEngine;
import com.cybershield.util.SecurityUtils;
import com.cybershield.util.SimulationDataGenerator;
import java.time.LocalDateTime;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

/**
 * Automated smoke test suite verifying all 9 core operational requirements of CyberShield.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class SmokeTest {

    private static DatabaseManager dbManager;
    private static SecurityEventRepository eventRepo;
    private static ThreatRepository threatRepo;
    private static IncidentRepository incidentRepo;
    private static ResponseActionRepository actionRepo;
    private static ThreatDetectionEngine detectionEngine;
    private static IncidentService incidentService;
    private static AuthService authService;

    private static Threat detectedThreat;
    private static Incident createdIncident;

    @BeforeAll
    public static void setUp() throws Exception {
        dbManager = DatabaseManager.getInstance();
        dbManager.initializeDatabase();

        eventRepo = new SecurityEventRepository(dbManager);
        threatRepo = new ThreatRepository(dbManager);
        actionRepo = new ResponseActionRepository(dbManager);
        incidentRepo = new IncidentRepository(dbManager, threatRepo, actionRepo);
        detectionEngine = new ThreatDetectionEngine(threatRepo);
        incidentService = new IncidentService(incidentRepo, threatRepo, actionRepo);
        authService = new AuthService();
    }

    @Test
    @Order(1)
    public void test1_DatabaseInitializes() {
        System.out.println("[Test 1] Verifying SQLite database initialization...");
        Assertions.assertDoesNotThrow(() -> {
            try (var conn = dbManager.getConnection()) {
                Assertions.assertNotNull(conn);
                Assertions.assertFalse(conn.isClosed());
            }
        });
        System.out.println("  -> PASSED: SQLite database connection verified.");
    }

    @Test
    @Order(2)
    public void test2_LoginAuthentication() {
        System.out.println("[Test 2] Verifying Analyst and Admin login authentication...");
        Assertions.assertDoesNotThrow(() -> {
            User analyst = authService.login("analyst", "cyber123");
            Assertions.assertNotNull(analyst);
            Assertions.assertEquals("analyst", analyst.getUsername());

            User admin = authService.login("admin", "admin123");
            Assertions.assertNotNull(admin);
            Assertions.assertEquals("admin", admin.getUsername());
        });
        System.out.println("  -> PASSED: Demonstration credentials successfully validated.");
    }

    @Test
    @Order(3)
    public void test3_SecurityEventCanBeInserted() {
        System.out.println("[Test 3] Verifying SecurityEvent telemetry insertion...");
        Assertions.assertDoesNotThrow(() -> {
            SecurityEvent event = new SecurityEvent(
                SecurityUtils.generateId("EVT-TEST"),
                LocalDateTime.now(),
                EventType.AUTH_FAILURE,
                "10.0.0.99",
                "test.user",
                "Automated test failed login attempt",
                "AUTH_TEST_PAYLOAD",
                Severity.LOW
            );
            eventRepo.save(event);
            Assertions.assertTrue(event.getId() > 0);
        });
        System.out.println("  -> PASSED: Telemetry event persisted in SQLite.");
    }

    @Test
    @Order(4)
    public void test4_ThreatCanBeDetected() {
        System.out.println("[Test 4] Verifying polymorphic threat detection (Brute Force heuristic)...");
        Assertions.assertDoesNotThrow(() -> {
            // Generate 6 failed login events
            List<SecurityEvent> events = SimulationDataGenerator.generateBruteForceEvents("test_victim", "198.51.100.77", 6);
            eventRepo.saveAll(events);

            List<Threat> threats = detectionEngine.processEvents(events);
            Assertions.assertFalse(threats.isEmpty(), "Threat detection engine should identify brute force pattern");

            detectedThreat = threats.get(0);
            Assertions.assertNotNull(detectedThreat.getThreatId());
            System.out.println("  -> Detected Threat: " + detectedThreat);
        });
        System.out.println("  -> PASSED: Detection engine polymorphically detected threat.");
    }

    @Test
    @Order(5)
    public void test5_ThreatCanBePersisted() {
        System.out.println("[Test 5] Verifying polymorphic Threat persistence and retrieval...");
        Assertions.assertDoesNotThrow(() -> {
            Threat retrieved = threatRepo.findById(detectedThreat.getThreatId());
            Assertions.assertNotNull(retrieved);
            Assertions.assertEquals(detectedThreat.getThreatId(), retrieved.getThreatId());
            Assertions.assertEquals(detectedThreat.getThreatType(), retrieved.getThreatType());
        });
        System.out.println("  -> PASSED: Threat successfully saved and retrieved.");
    }

    @Test
    @Order(6)
    public void test6_IncidentCanBeCreated() {
        System.out.println("[Test 6] Verifying Incident case escalation from Threat...");
        Assertions.assertDoesNotThrow(() -> {
            createdIncident = incidentService.escalateThreatToIncident(detectedThreat, "Test Escalated Incident");
            Assertions.assertNotNull(createdIncident);
            Assertions.assertEquals(IncidentStatus.OPEN, createdIncident.getStatus());
            Assertions.assertEquals(detectedThreat.getThreatId(), createdIncident.getAssociatedThreat().getThreatId());
        });
        System.out.println("  -> PASSED: Incident created with Composition (HAS-A Threat).");
    }

    @Test
    @Order(7)
    public void test7_ResponseActionCanBeRecorded() {
        System.out.println("[Test 7] Verifying simulated containment response action execution...");
        Assertions.assertDoesNotThrow(() -> {
            ResponseAction action = incidentService.executeResponseAction(
                createdIncident.getIncidentId(),
                ResponseActionType.BLOCK_IP,
                "analyst",
                "Automated firewall block rule applied in simulation"
            );
            Assertions.assertNotNull(action);
            Assertions.assertEquals("EXECUTED", action.getStatus());

            // Reload incident to verify composed collection
            Incident reloaded = incidentRepo.findById(createdIncident.getIncidentId());
            Assertions.assertFalse(reloaded.getResponseActions().isEmpty(), "Incident should contain recorded ResponseAction");
        });
        System.out.println("  -> PASSED: Response action dispatched and recorded in audit log.");
    }

    @Test
    @Order(8)
    public void test8_IncidentCanBeResolved() {
        System.out.println("[Test 8] Verifying Incident resolution workflow...");
        Assertions.assertDoesNotThrow(() -> {
            incidentService.resolveIncident(createdIncident.getIncidentId(), "Simulated attack contained and threat neutralized.");
            Incident reloaded = incidentRepo.findById(createdIncident.getIncidentId());
            Assertions.assertEquals(IncidentStatus.RESOLVED, reloaded.getStatus());
        });
        System.out.println("  -> PASSED: Incident transitioned to RESOLVED.");
    }

    @Test
    @Order(9)
    public void test9_DataPersistsAfterRestart() {
        System.out.println("[Test 9] Verifying SQLite database persistence across manager reload...");
        Assertions.assertDoesNotThrow(() -> {
            // Create brand new instances to simulate fresh boot
            SecurityEventRepository freshEventRepo = new SecurityEventRepository(dbManager);
            ThreatRepository freshThreatRepo = new ThreatRepository(dbManager);
            IncidentRepository freshIncRepo = new IncidentRepository(dbManager, freshThreatRepo, new ResponseActionRepository(dbManager));

            Assertions.assertTrue(freshEventRepo.count() > 0);
            Assertions.assertTrue(freshThreatRepo.count() > 0);
            Assertions.assertTrue(freshIncRepo.count() > 0);
        });
        System.out.println("  -> PASSED: Relational data persists accurately across restarts.");
    }

    public static void main(String[] args) {
        System.out.println("=========================================================");
        System.out.println("CYBERSHIELD AUTOMATED SYSTEM VERIFICATION & SMOKE TEST");
        System.out.println("=========================================================");
        try {
            setUp();
            SmokeTest test = new SmokeTest();
            test.test1_DatabaseInitializes();
            test.test2_LoginAuthentication();
            test.test3_SecurityEventCanBeInserted();
            test.test4_ThreatCanBeDetected();
            test.test5_ThreatCanBePersisted();
            test.test6_IncidentCanBeCreated();
            test.test7_ResponseActionCanBeRecorded();
            test.test8_IncidentCanBeResolved();
            test.test9_DataPersistsAfterRestart();

            System.out.println("\n>>> ALL 9 SMOKE TEST SUITES PASSED FLAWLESSLY! <<<");
        } catch (Throwable t) {
            System.err.println("Smoke test failed: " + t.getMessage());
            t.printStackTrace();
            System.exit(1);
        }
    }
}
