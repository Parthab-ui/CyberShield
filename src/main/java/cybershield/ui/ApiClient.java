package cybershield.ui;

import cybershield.model.AccessEvent;
import cybershield.model.AccountLockStatus;
import cybershield.model.ActivityLog;
import cybershield.model.BlockedIp;
import cybershield.model.DashboardStats;
import cybershield.model.Incident;
import cybershield.model.IntrusionDetectionConfig;
import cybershield.model.InvestigationNote;
import cybershield.model.InvestigationSummary;
import cybershield.model.InvestigationTimelineItem;
import cybershield.model.SecurityAlert;
import cybershield.model.ThreatResponse;
import cybershield.model.ThreatResponseStats;
import cybershield.model.User;
import cybershield.security.SessionManager;
import cybershield.service.AccessEventService;
import cybershield.service.AccountLockoutService;
import cybershield.service.ActivityLogService;
import cybershield.service.DashboardService;
import cybershield.service.IncidentInvestigationService;
import cybershield.service.IncidentService;
import cybershield.service.IntrusionDetectionService;
import cybershield.service.IpBlockService;
import cybershield.service.ThreatResponseService;
import cybershield.service.UserService;

import java.util.List;

/**
 * ApiClient — Connects the Java Swing desktop client to the shared application services and database.
 * Demonstrates: Client-service abstraction layer, centralized authentication session management,
 * and seamless synchronization with the same persistent SQLite database powering the Web interface.
 * Updated for Review 3 to provide full desktop integration for Threat Response, Incident Forensics,
 * and Account Security workflows.
 */
public class ApiClient {

    private static final ApiClient INSTANCE = new ApiClient();

    private final UserService userService;
    private final IncidentService incidentService;
    private final AccessEventService accessEventService;
    private final ActivityLogService activityLogService;
    private final DashboardService dashboardService;
    private final IntrusionDetectionService intrusionDetectionService;
    private final IpBlockService ipBlockService;
    private final AccountLockoutService accountLockoutService;
    private final ThreatResponseService threatResponseService;
    private final IncidentInvestigationService incidentInvestigationService;

    private User currentUser;
    private String sessionToken;

    private ApiClient() {
        this.userService = new UserService();
        this.incidentService = new IncidentService();
        this.accessEventService = new AccessEventService();
        this.activityLogService = new ActivityLogService();
        this.dashboardService = new DashboardService();
        this.intrusionDetectionService = new IntrusionDetectionService();
        this.ipBlockService = new IpBlockService();
        this.accountLockoutService = new AccountLockoutService(this.activityLogService);
        this.threatResponseService = new ThreatResponseService(this.ipBlockService, this.incidentService, this.activityLogService);
        this.incidentInvestigationService = new IncidentInvestigationService(this.incidentService, this.userService, this.activityLogService, this.threatResponseService);
    }

    public static ApiClient getInstance() {
        return INSTANCE;
    }

    /** Authenticates user credentials and establishes a desktop session. */
    public User login(String username, String password) {
        User user = userService.authenticate(username, password, "DESKTOP");
        if (user != null) {
            this.currentUser = user;
            this.sessionToken = SessionManager.createSession(user);
        }
        return user;
    }

    /** Invalidates active session. */
    public void logout() {
        if (sessionToken != null) {
            SessionManager.invalidateSession(sessionToken);
            if (currentUser != null) {
                activityLogService.log(currentUser.getUsername(), "USER_LOGOUT", "Desktop user logged out");
            }
        }
        this.currentUser = null;
        this.sessionToken = null;
    }

    public User getCurrentUser() {
        return currentUser;
    }

    public boolean isAuthenticated() {
        return currentUser != null;
    }

    public boolean isAdmin() {
        return currentUser != null && currentUser.isAdmin();
    }

    public boolean isAnalyst() {
        return currentUser != null && currentUser.isAnalyst();
    }

    /** Retrieves dashboard metrics. */
    public DashboardStats getDashboardStats() {
        return dashboardService.getStats();
    }

    /** Retrieves filtered incidents. */
    public List<Incident> getIncidents(String query, String severity, String status) {
        return incidentService.getAll(query, severity, status);
    }

    /** Retrieves an incident by ID. */
    public Incident getIncidentById(int id) {
        return incidentService.getById(id);
    }

    /** Creates a new incident. */
    public Incident createIncident(Incident incident) {
        String actor = currentUser != null ? currentUser.getUsername() : "desktop_analyst";
        return incidentService.create(incident, actor);
    }

    /** Updates an incident. */
    public boolean updateIncident(int id, Incident updated) {
        String actor = currentUser != null ? currentUser.getUsername() : "desktop_analyst";
        return incidentService.update(id, updated, actor);
    }

    /** Deletes an incident (requires ADMIN role). */
    public boolean deleteIncident(int id) {
        if (!isAdmin()) {
            throw new SecurityException("Permission Denied: Only Administrator role can delete incident records.");
        }
        String actor = currentUser != null ? currentUser.getUsername() : "admin";
        return incidentService.delete(id, actor);
    }

    /** Retrieves access monitoring events. */
    public List<AccessEvent> getAccessEvents(int limit) {
        return accessEventService.getAll(limit);
    }

    /** Triggers a simulated intrusion attempt for demonstration. */
    public AccessEvent simulateThreat() {
        String source = currentUser != null ? "DESKTOP:" + currentUser.getUsername() : "DESKTOP_EVAL";
        return accessEventService.simulateThreat(source);
    }

    /** Retrieves system activity log. */
    public List<ActivityLog> getActivity(int limit) {
        return activityLogService.getAll(limit);
    }

    /** Retrieves latest active security alert for desktop dashboard. */
    public SecurityAlert getLatestAlert() {
        return intrusionDetectionService.getLatestAlert();
    }

    /** Retrieves recent security alerts. */
    public List<SecurityAlert> getRecentAlerts(int limit) {
        return intrusionDetectionService.getRecentAlerts(limit);
    }

    /** Retrieves IDS configuration parameters. */
    public IntrusionDetectionConfig getIntrusionConfig() {
        return intrusionDetectionService.getConfig();
    }

    /**
     * Simulates a brute-force attack from a target IP for faculty demonstration.
     * Records 5 failed login attempts in rapid succession to trigger the detection engine.
     */
    public SecurityAlert simulateBruteForceAttack(String ip) {
        String targetIp = (ip != null && !ip.trim().isEmpty()) ? ip.trim() : "192.168.1.105";
        long now = System.currentTimeMillis();
        SecurityAlert alert = null;
        for (int i = 1; i <= 5; i++) {
            alert = intrusionDetectionService.recordFailedLogin(targetIp, "admin", now + (i * 1000));
        }
        return alert;
    }

    // =========================================================================
    // REVIEW 3: IP BLOCKING & FIREWALL MANAGEMENT
    // =========================================================================

    /** Retrieves blocked IPs filtered by status (ACTIVE, EXPIRED, UNBLOCKED, or ALL). */
    public List<BlockedIp> getBlockedIps(String statusFilter) {
        return ipBlockService.getAllBlockedIps(statusFilter);
    }

    /** Blocks an IP address manually (requires ADMIN role). */
    public BlockedIp blockIp(String ip, String reason, long durationMinutes) {
        if (!isAdmin()) {
            throw new SecurityException("Permission Denied: Only Administrator can manually block IP addresses.");
        }
        String actor = currentUser != null ? currentUser.getUsername() : "desktop_admin";
        return ipBlockService.blockIp(ip, reason, durationMinutes, actor);
    }

    /** Unblocks an IP address (requires ADMIN role). */
    public boolean unblockIp(String ip) {
        if (!isAdmin()) {
            throw new SecurityException("Permission Denied: Only Administrator can unblock IP addresses.");
        }
        String actor = currentUser != null ? currentUser.getUsername() : "desktop_admin";
        return ipBlockService.unblockIp(ip, actor);
    }

    // =========================================================================
    // REVIEW 3: ACCOUNT LOCKOUT & CREDENTIAL SECURITY
    // =========================================================================

    /** Retrieves all currently locked accounts. */
    public List<AccountLockStatus> getLockedAccounts() {
        return accountLockoutService.getAllLockedAccounts();
    }

    /** Manually unlocks a user account (requires ADMIN role). */
    public boolean unlockAccount(String username) {
        if (!isAdmin()) {
            throw new SecurityException("Permission Denied: Only Administrator can unlock user accounts.");
        }
        String actor = currentUser != null ? currentUser.getUsername() : "desktop_admin";
        return accountLockoutService.unlockAccount(username, actor);
    }

    // =========================================================================
    // REVIEW 3: AUTOMATED THREAT RESPONSE
    // =========================================================================

    /** Retrieves threat response execution history with optional filtering. */
    public List<ThreatResponse> getThreatResponses(Integer incidentId, String targetIp, String status) {
        return threatResponseService.getResponseHistory(incidentId, targetIp, status);
    }

    /** Retrieves threat response metrics and KPI statistics. */
    public ThreatResponseStats getThreatResponseStats() {
        return threatResponseService.getResponseStatistics();
    }

    // =========================================================================
    // REVIEW 3: INCIDENT FORENSIC INVESTIGATION & TRIAGE
    // =========================================================================

    /** Retrieves forensic investigation notes for a given incident. */
    public List<InvestigationNote> getInvestigationNotes(int incidentId) {
        return incidentInvestigationService.getInvestigationNotes(incidentId);
    }

    /** Records a new forensic investigation note with optional JSON evidence. */
    public InvestigationNote addInvestigationNote(int incidentId, String notes, String evidenceData) {
        String analyst = currentUser != null ? currentUser.getUsername() : "desktop_analyst";
        return incidentInvestigationService.addInvestigationNote(incidentId, analyst, notes, evidenceData);
    }

    /** Assigns an incident to an analyst (requires ADMIN role). */
    public Incident assignInvestigator(int incidentId, String assignedAnalyst) {
        if (!isAdmin()) {
            throw new SecurityException("Permission Denied: Only Administrator can assign investigators.");
        }
        String actor = currentUser != null ? currentUser.getUsername() : "desktop_admin";
        return incidentInvestigationService.assignInvestigator(incidentId, assignedAnalyst, actor);
    }

    /** Classifies root cause category and rationale for an incident. */
    public Incident updateRootCause(int incidentId, String category, String explanation) {
        String actor = currentUser != null ? currentUser.getUsername() : "desktop_analyst";
        return incidentInvestigationService.updateRootCause(incidentId, category, explanation, actor);
    }

    /** Retrieves unified chronological investigation timeline. */
    public List<InvestigationTimelineItem> getInvestigationTimeline(int incidentId) {
        return incidentInvestigationService.getInvestigationTimeline(incidentId);
    }

    /** Retrieves comprehensive investigation case summary and metrics. */
    public InvestigationSummary getInvestigationSummary(int incidentId) {
        return incidentInvestigationService.getInvestigationSummary(incidentId);
    }

    /** Resolves an incident with a forensic summary. */
    public boolean resolveIncident(int incidentId, String resolutionSummary) {
        String actor = currentUser != null ? currentUser.getUsername() : "desktop_analyst";
        return incidentInvestigationService.resolveIncident(incidentId, resolutionSummary, actor);
    }

    /** Retrieves list of users eligible for assignment (ADMIN and ANALYST). */
    public List<User> getAssignableInvestigators() {
        return userService.getAssignableInvestigators();
    }
}
