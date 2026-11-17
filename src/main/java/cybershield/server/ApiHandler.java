package cybershield.server;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import cybershield.model.AccountLockStatus;
import cybershield.model.BlockedIp;
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

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ApiHandler — Central REST-style API controller handling all HTTP requests under '/api/'.
 * Demonstrates: Controller pattern, JSON serialization with Gson, session token authentication,
 * role authorization (ADMIN vs ANALYST), and clean HTTP status code delivery.
 */
public class ApiHandler implements HttpHandler {

    private final Gson gson = new Gson();

    /** Allowed CORS origins — built dynamically when server port is known. */
    private final Set<String> allowedOrigins = ConcurrentHashMap.newKeySet();

    /** Login rate-limiter: maps IP → timestamps of recent login attempts. */
    private final ConcurrentHashMap<String, Deque<Long>> loginAttempts = new ConcurrentHashMap<>();

    /** Maximum login attempts per IP per 60-second sliding window (Phase 4). */
    private static final int MAX_LOGIN_ATTEMPTS_PER_MINUTE = 10;

    // ── Input validation constants ────────────────────────────────────────────
    private static final Set<String> VALID_SEVERITIES = Set.of("LOW", "MEDIUM", "HIGH", "CRITICAL");
    private static final Set<String> VALID_STATUSES   = Set.of("OPEN", "IN_PROGRESS", "RESOLVED", "CLOSED");
    private static final int MAX_TITLE_LEN  = 200;
    private static final int MAX_DESC_LEN   = 2000;
    private static final int MAX_NOTE_LEN   = 5000;
    private static final int MAX_USERNAME_LEN = 50;
    private final IncidentService incidentService;
    private final AccessEventService accessEventService;
    private final ActivityLogService activityLogService;
    private final IntrusionDetectionService intrusionDetectionService;
    private final UserService userService;
    private final DashboardService dashboardService;
    private final IpBlockService ipBlockService;
    private final AccountLockoutService accountLockoutService;
    private final ThreatResponseService threatResponseService;
    private final IncidentInvestigationService incidentInvestigationService;

    public ApiHandler() {
        this(new IpBlockService(), new AccountLockoutService());
    }

    public ApiHandler(IpBlockService ipBlockService) {
        this(ipBlockService, new AccountLockoutService());
    }

    public ApiHandler(IpBlockService ipBlockService, AccountLockoutService accountLockoutService) {
        this.ipBlockService = (ipBlockService != null) ? ipBlockService : new IpBlockService();
        this.accountLockoutService = (accountLockoutService != null) ? accountLockoutService : new AccountLockoutService();
        this.incidentService = new IncidentService();
        this.accessEventService = new AccessEventService();
        this.activityLogService = new ActivityLogService();
        this.threatResponseService = new ThreatResponseService(this.ipBlockService, this.incidentService, this.activityLogService);
        this.intrusionDetectionService = new IntrusionDetectionService(
                incidentService, activityLogService, accessEventService, new IntrusionDetectionConfig(), this.threatResponseService
        );
        this.userService = new UserService(accessEventService, activityLogService, intrusionDetectionService, this.accountLockoutService);
        this.dashboardService = new DashboardService(incidentService, activityLogService, intrusionDetectionService);
        this.incidentInvestigationService = new IncidentInvestigationService(
                this.incidentService, this.userService, this.activityLogService, this.threatResponseService
        );
    }

    public IpBlockService getIpBlockService() {
        return ipBlockService;
    }

    public AccountLockoutService getAccountLockoutService() {
        return accountLockoutService;
    }

    public ThreatResponseService getThreatResponseService() {
        return threatResponseService;
    }

    public IncidentInvestigationService getIncidentInvestigationService() {
        return incidentInvestigationService;
    }

    /**
     * Registers the server's own origin as an allowed CORS origin.
     * Called by HttpServerManager after binding to a port.
     */
    public void addAllowedOrigin(int port) {
        allowedOrigins.add("http://localhost:" + port);
        allowedOrigins.add("http://127.0.0.1:" + port);
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        // ── CORS ──────────────────────────────────────────────────────────────
        // Reflect origin only when it matches the server's own host/port.
        String requestOrigin = exchange.getRequestHeaders().getFirst("Origin");
        if (requestOrigin != null && (allowedOrigins.isEmpty() || allowedOrigins.contains(requestOrigin))) {
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", requestOrigin);
            exchange.getResponseHeaders().set("Vary", "Origin");
        }
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, Authorization");

        // ── Security headers on every response ────────────────────────────────
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.getResponseHeaders().set("X-Frame-Options", "DENY");
        exchange.getResponseHeaders().set("Referrer-Policy", "no-referrer");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");

        String method = exchange.getRequestMethod().toUpperCase();
        if ("OPTIONS".equals(method)) {
            exchange.sendResponseHeaders(204, -1);
            return;
        }

        URI uri = exchange.getRequestURI();
        String path = uri.getPath();

        // ── Global IP block gate (before routing, skip OPTIONS already handled) ──
        // For the login endpoint we do IP checking *inside* handleLogin() so the
        // loopback test-override for clientIp still works. Skip it here for /api/auth/login.
        if (!path.equals("/api/auth/login")) {
            String gatewayIp = getClientIp(exchange);
            if (ipBlockService.isBlocked(gatewayIp)) {
                activityLogService.log("SYSTEM", "BLOCKED_IP_ACCESS",
                        "Blocked IP " + gatewayIp + " attempted to access " + path);
                sendError(exchange, 403, "Access denied: your IP address is blocked.");
                return;
            }
        }

        try {
            // Authentication Endpoints
            if (path.equals("/api/auth/login") && "POST".equals(method)) {
                handleLogin(exchange);
            } else if (path.equals("/api/auth/logout") && "POST".equals(method)) {
                handleLogout(exchange);
            } else if (path.equals("/api/auth/me") && "GET".equals(method)) {
                handleMe(exchange);
            } else if (path.equals("/api/auth/locked-accounts") && "GET".equals(method)) {
                handleGetLockedAccounts(exchange);
            } else if (path.equals("/api/auth/unlock") && "POST".equals(method)) {
                handleUnlockAccount(exchange);
            } else if (path.startsWith("/api/auth/lock-status/") && "GET".equals(method)) {
                handleGetAccountLockStatus(exchange);
            }

            // Firewall / IP Block Management Endpoints (Review 3 Phase 6A)
            else if (path.equals("/api/firewall/blocked-ips") && "GET".equals(method)) {
                handleGetBlockedIps(exchange);
            } else if (path.equals("/api/firewall/block") && "POST".equals(method)) {
                handleBlockIp(exchange);
            } else if (path.equals("/api/firewall/unblock") && "POST".equals(method)) {
                handleUnblockIp(exchange);
            }

            // Dashboard Endpoint
            else if (path.equals("/api/dashboard/stats") && "GET".equals(method)) {
                handleDashboardStats(exchange);
            }

            // Investigator Directory Endpoint (Review 3 Phase 6A)
            else if (path.equals("/api/investigators") && "GET".equals(method)) {
                handleGetInvestigators(exchange);
            }

            // Incident Investigation & Triage Endpoints (Review 3 Phase 6A)
            else if (path.matches("^/api/incidents/\\d+/investigations$") && "GET".equals(method)) {
                handleGetInvestigationNotes(exchange);
            } else if (path.matches("^/api/incidents/\\d+/investigations$") && "POST".equals(method)) {
                handleAddInvestigationNote(exchange);
            } else if (path.matches("^/api/incidents/\\d+/timeline$") && "GET".equals(method)) {
                handleGetInvestigationTimeline(exchange);
            } else if (path.matches("^/api/incidents/\\d+/investigation-summary$") && "GET".equals(method)) {
                handleGetInvestigationSummary(exchange);
            } else if (path.matches("^/api/incidents/\\d+/assign$") && "POST".equals(method)) {
                handleAssignInvestigator(exchange);
            } else if (path.matches("^/api/incidents/\\d+/root-cause$") && "POST".equals(method)) {
                handleUpdateRootCause(exchange);
            } else if (path.matches("^/api/incidents/\\d+/resolve$") && "POST".equals(method)) {
                handleResolveIncident(exchange);
            }

            // Incident Management CRUD Endpoints
            else if (path.equals("/api/incidents") && "GET".equals(method)) {
                handleGetIncidents(exchange);
            } else if (path.equals("/api/incidents") && "POST".equals(method)) {
                handleCreateIncident(exchange);
            } else if (path.matches("^/api/incidents/\\d+$") && "GET".equals(method)) {
                handleGetIncidentById(exchange);
            } else if (path.matches("^/api/incidents/\\d+$") && "PUT".equals(method)) {
                handleUpdateIncident(exchange);
            } else if (path.matches("^/api/incidents/\\d+$") && "DELETE".equals(method)) {
                handleDeleteIncident(exchange);
            }

            // Access Events Monitoring Endpoints
            else if (path.equals("/api/access-events") && "GET".equals(method)) {
                handleGetAccessEvents(exchange);
            } else if (path.equals("/api/access-events/simulate") && "POST".equals(method)) {
                handleSimulateThreat(exchange);
            }

            // Activity History Endpoint
            else if (path.equals("/api/activity") && "GET".equals(method)) {
                handleGetActivity(exchange);
            }

            // Review 2 Intrusion Detection & Threat Alert Endpoints
            else if (path.equals("/api/alerts") && "GET".equals(method)) {
                handleGetAlerts(exchange);
            } else if (path.equals("/api/alerts/latest") && "GET".equals(method)) {
                handleGetLatestAlert(exchange);
            } else if (path.equals("/api/intrusion/config") && "GET".equals(method)) {
                handleGetIntrusionConfig(exchange);
            } else if (path.equals("/api/intrusion/simulate-attack") && "POST".equals(method)) {
                handleSimulateBruteForce(exchange);
            }

            // Review 3 Phase 4 Threat Responses Endpoints
            else if (path.equals("/api/threat-responses") && "GET".equals(method)) {
                handleGetThreatResponses(exchange);
            } else if (path.equals("/api/threat-responses/stats") && "GET".equals(method)) {
                handleGetThreatResponseStats(exchange);
            }

            // Unknown endpoint
            else {
                sendError(exchange, 404, "Unknown API endpoint: " + path);
            }
        } catch (Exception e) {
            System.err.println("[ApiHandler] Internal error on " + path + ": " + e.getMessage());
            sendError(exchange, 500, "An internal server error occurred. Please try again.");
        }
    }

    // =========================================================================
    // ENDPOINT HANDLERS
    // =========================================================================

    /**
     * POST /api/auth/login — Authenticates credentials, creates session, returns bearer token.
     * Extracts remote client connection IP directly from the HTTP request.
     * Records failed login attempts and triggers automated intrusion detection when thresholds are reached.
     */
    private void handleLogin(HttpExchange exchange) throws IOException {
        String body = readRequestBody(exchange);
        if (body == null) return; // 413 already sent
        JsonObject json = gson.fromJson(body, JsonObject.class);

        if (json == null || !json.has("username") || !json.has("password")) {
            sendError(exchange, 400, "Username and password are required.");
            return;
        }

        String username = json.get("username").getAsString();
        String password = json.get("password").getAsString();
        String source = json.has("source") ? json.get("source").getAsString() : "WEB";

        // Extract client remote IP directly from HTTP connection address
        InetSocketAddress remoteAddr = exchange.getRemoteAddress();
        String actualSocketIp = (remoteAddr != null && remoteAddr.getAddress() != null)
                ? remoteAddr.getAddress().getHostAddress()
                : "127.0.0.1";

        if ("0:0:0:0:0:0:0:1".equals(actualSocketIp) || "::1".equals(actualSocketIp)) {
            actualSocketIp = "127.0.0.1";
        }

        String clientIp = actualSocketIp;
        // Strictly ignore client-supplied simulation IP unless request is from local loopback (testing context)
        if (isLocalConnection(exchange) && json.has("clientIp") && !json.get("clientIp").getAsString().trim().isEmpty()) {
            clientIp = json.get("clientIp").getAsString().trim();
        }

        // =========================================================================
        // APPLICATION-LEVEL IP ENFORCEMENT (Review 3 Phase 2)
        // =========================================================================
        if (ipBlockService.isBlocked(clientIp)) {
            BlockedIp activeBlock = ipBlockService.getActiveBlock(clientIp);
            long expiresAt = (activeBlock != null && activeBlock.getExpiresAt() != null) ? activeBlock.getExpiresAt() : 0L;

            JsonObject blockedResponse = new JsonObject();
            blockedResponse.addProperty("success", false);
            blockedResponse.addProperty("error", "IP_BLOCKED");
            blockedResponse.addProperty("message", "Access denied. This IP address has been temporarily blocked by CyberShield.");
            blockedResponse.addProperty("expiresAt", expiresAt);

            System.out.println("[ApiHandler] REJECTED login from blocked IP: " + clientIp +
                    " (Expires at: " + expiresAt + "). Password verification bypassed.");
            activityLogService.log("SYSTEM", "BLOCKED_IP_LOGIN",
                    "Login attempt rejected — blocked IP: " + clientIp + " for user: " + username);
            sendJson(exchange, 403, blockedResponse);
            return;
        }

        // =========================================================================
        // LOGIN RATE LIMITING (Phase 4): max 10 attempts/minute per IP
        // =========================================================================
        if (isLoginRateLimited(clientIp)) {
            activityLogService.log("SYSTEM", "RATE_LIMIT_HIT",
                    "Login rate limit exceeded for IP: " + clientIp);
            exchange.getResponseHeaders().set("Retry-After", "60");
            sendError(exchange, 429, "Too many login attempts. Please wait 60 seconds before trying again.");
            return;
        }

        // =========================================================================
        // ACCOUNT LOCKOUT ENFORCEMENT (Review 3 Phase 3)
        // =========================================================================
        if (accountLockoutService.isAccountLocked(username)) {
            sendAccountLockedResponse(exchange, username);
            return;
        }

        User user = userService.authenticate(username, password, clientIp, source);
        if (user != null) {
            String token = SessionManager.createSession(user);

            JsonObject response = new JsonObject();
            response.addProperty("success", true);
            response.addProperty("token", token);

            JsonObject userObj = new JsonObject();
            userObj.addProperty("id", user.getId());
            userObj.addProperty("username", user.getUsername());
            userObj.addProperty("role", user.getRole());
            userObj.addProperty("createdAt", user.getCreatedAt());
            response.add("user", userObj);

            sendJson(exchange, 200, response);
        } else {
            // Log failed login attempt for audit trail (never log the password itself)
            activityLogService.log("SYSTEM", "LOGIN_FAILED",
                    "Failed login attempt for username: " + username + " from IP: " + clientIp);
            // Check if this latest failed attempt just triggered an account lock (5th consecutive failure)
            if (accountLockoutService.isAccountLocked(username)) {
                sendAccountLockedResponse(exchange, username);
                return;
            }
            sendError(exchange, 401, "Invalid username or password.");
        }
    }

    /**
     * Sends an HTTP 423 Locked response when an account is temporarily locked.
     */
    private void sendAccountLockedResponse(HttpExchange exchange, String username) throws IOException {
        AccountLockStatus status = accountLockoutService.getAccountLockStatus(username);
        JsonObject lockedResponse = new JsonObject();
        lockedResponse.addProperty("success", false);
        lockedResponse.addProperty("error", "ACCOUNT_LOCKED");
        lockedResponse.addProperty("message", "This account is temporarily locked due to repeated failed login attempts.");
        lockedResponse.addProperty("lockedUntil", status.getLockedUntil());
        lockedResponse.addProperty("remainingSeconds", status.getRemainingSeconds());

        System.out.println("[ApiHandler] REJECTED login for locked account: " + username +
                " (Locked until: " + status.getLockedUntil() + ", remaining: " + status.getRemainingSeconds() + "s)");
        sendJson(exchange, 423, lockedResponse);
    }

    /**
     * POST /api/auth/unlock — Administrator-controlled service to unlock a locked account.
     */
    private void handleUnlockAccount(HttpExchange exchange) throws IOException {
        User admin = requireRole(exchange, "ADMIN");
        if (admin == null) return;

        String body = readRequestBody(exchange);
        if (body == null) return; // 413 already sent
        JsonObject json = gson.fromJson(body, JsonObject.class);
        if (json == null || !json.has("username")) {
            sendError(exchange, 400, "Username is required.");
            return;
        }

        String targetUsername = json.get("username").getAsString();
        boolean unlocked = accountLockoutService.unlockAccount(targetUsername, admin.getUsername());
        if (unlocked) {
            SessionManager.invalidateSessionsForUser(targetUsername);
            JsonObject res = new JsonObject();
            res.addProperty("success", true);
            res.addProperty("message", "Account " + targetUsername + " unlocked successfully.");
            sendJson(exchange, 200, res);
        } else {
            sendError(exchange, 404, "User not found or unable to unlock: " + targetUsername);
        }
    }

    /**
     * GET /api/auth/lock-status/{username} — Returns account lockout state (Admin/Analyst authorized).
     */
    private void handleGetAccountLockStatus(HttpExchange exchange) throws IOException {
        User caller = requireAuth(exchange);
        if (caller == null) return;

        String path = exchange.getRequestURI().getPath();
        String targetUsername = path.substring("/api/auth/lock-status/".length()).trim();
        AccountLockStatus status = accountLockoutService.getAccountLockStatus(targetUsername);
        sendJson(exchange, 200, status);
    }

    /**
     * POST /api/auth/logout — Invalidates active user session token.
     */
    private void handleLogout(HttpExchange exchange) throws IOException {
        String token = extractToken(exchange);
        User user = SessionManager.validateSession(token);
        if (user != null) {
            activityLogService.log(user.getUsername(), "USER_LOGOUT", "User logged out");
        }
        SessionManager.invalidateSession(token);
        JsonObject res = new JsonObject();
        res.addProperty("success", true);
        res.addProperty("message", "Logged out successfully.");
        sendJson(exchange, 200, res);
    }

    /**
     * GET /api/auth/me — Returns profile of current authenticated session user.
     */
    private void handleMe(HttpExchange exchange) throws IOException {
        User user = requireAuth(exchange);
        if (user == null) return;

        JsonObject userObj = new JsonObject();
        userObj.addProperty("id", user.getId());
        userObj.addProperty("username", user.getUsername());
        userObj.addProperty("role", user.getRole());
        userObj.addProperty("createdAt", user.getCreatedAt());
        sendJson(exchange, 200, userObj);
    }

    /**
     * GET /api/dashboard/stats — Compiles real live metrics from database.
     */
    private void handleDashboardStats(HttpExchange exchange) throws IOException {
        User user = requireAuth(exchange);
        if (user == null) return;

        var stats = dashboardService.getStats();
        sendJson(exchange, 200, stats);
    }

    /**
     * GET /api/incidents — Returns filtered incident records.
     */
    private void handleGetIncidents(HttpExchange exchange) throws IOException {
        User user = requireAuth(exchange);
        if (user == null) return;

        Map<String, String> queryParams = parseQueryParams(exchange.getRequestURI());
        String q = queryParams.get("q");
        String severity = queryParams.get("severity");
        String status = queryParams.get("status");

        var list = incidentService.getAll(q, severity, status);
        sendJson(exchange, 200, list);
    }

    /**
     * GET /api/incidents/{id} — Returns single incident by ID.
     */
    private void handleGetIncidentById(HttpExchange exchange) throws IOException {
        User user = requireAuth(exchange);
        if (user == null) return;

        int id = extractIdFromPath(exchange.getRequestURI().getPath(), "/api/incidents/");
        if (id <= 0) {
            sendError(exchange, 400, "Invalid incident ID.");
            return;
        }

        Incident inc = incidentService.getById(id);
        if (inc != null) {
            sendJson(exchange, 200, inc);
        } else {
            sendError(exchange, 404, "Incident not found with ID: " + id);
        }
    }

    /**
     * POST /api/incidents — Creates a new incident (requires authentication).
     */
    private void handleCreateIncident(HttpExchange exchange) throws IOException {
        User user = requireAuth(exchange);
        if (user == null) return;

        String body = readRequestBody(exchange);
        if (body == null) return; // 413 already sent
        Incident incoming = gson.fromJson(body, Incident.class);

        // Validate inputs
        String titleErr = validateTitle(incoming == null ? null : incoming.getTitle());
        if (titleErr != null) { sendError(exchange, 400, titleErr); return; }
        String descErr = validateDescription(incoming.getDescription());
        if (descErr != null) { sendError(exchange, 400, descErr); return; }
        String sevErr = validateSeverity(incoming.getSeverity());
        if (sevErr != null) { sendError(exchange, 400, sevErr); return; }
        String statusErr = validateStatus(incoming.getStatus());
        if (statusErr != null) { sendError(exchange, 400, statusErr); return; }

        Incident created = incidentService.create(incoming, user.getUsername());
        if (created != null) {
            sendJson(exchange, 201, created);
        } else {
            sendError(exchange, 500, "Failed to create incident in database.");
        }
    }

    /**
     * PUT /api/incidents/{id} — Updates an existing incident (requires authentication).
     */
    private void handleUpdateIncident(HttpExchange exchange) throws IOException {
        User user = requireAuth(exchange);
        if (user == null) return;

        int id = extractIdFromPath(exchange.getRequestURI().getPath(), "/api/incidents/");
        if (id <= 0) {
            sendError(exchange, 400, "Invalid incident ID.");
            return;
        }

        String body = readRequestBody(exchange);
        if (body == null) return; // 413 already sent
        Incident incoming = gson.fromJson(body, Incident.class);

        // Validate inputs
        String titleErr = validateTitle(incoming == null ? null : incoming.getTitle());
        if (titleErr != null) { sendError(exchange, 400, titleErr); return; }
        String descErr = validateDescription(incoming.getDescription());
        if (descErr != null) { sendError(exchange, 400, descErr); return; }
        String sevErr = validateSeverity(incoming.getSeverity());
        if (sevErr != null) { sendError(exchange, 400, sevErr); return; }
        String statusErr = validateStatus(incoming.getStatus());
        if (statusErr != null) { sendError(exchange, 400, statusErr); return; }

        boolean updated = incidentService.update(id, incoming, user.getUsername());
        if (updated) {
            JsonObject res = new JsonObject();
            res.addProperty("success", true);
            res.addProperty("message", "Incident #" + id + " updated successfully.");
            sendJson(exchange, 200, res);
        } else {
            sendError(exchange, 404, "Incident #" + id + " could not be found or updated.");
        }
    }

    /**
     * DELETE /api/incidents/{id} — Deletes an incident (requires ADMIN role!).
     */
    private void handleDeleteIncident(HttpExchange exchange) throws IOException {
        User user = requireRole(exchange, "ADMIN");
        if (user == null) return;

        int id = extractIdFromPath(exchange.getRequestURI().getPath(), "/api/incidents/");
        if (id <= 0) {
            sendError(exchange, 400, "Invalid incident ID.");
            return;
        }

        boolean deleted = incidentService.delete(id, user.getUsername());
        if (deleted) {
            JsonObject res = new JsonObject();
            res.addProperty("success", true);
            res.addProperty("message", "Incident #" + id + " deleted successfully.");
            sendJson(exchange, 200, res);
        } else {
            sendError(exchange, 404, "Incident #" + id + " not found or already deleted.");
        }
    }

    /**
     * GET /api/access-events — Returns recent access and intrusion attempts.
     */
    private void handleGetAccessEvents(HttpExchange exchange) throws IOException {
        User user = requireAuth(exchange);
        if (user == null) return;

        var events = accessEventService.getAll(50);
        sendJson(exchange, 200, events);
    }

    /**
     * POST /api/access-events/simulate — Triggers a simulated intrusion attempt for demonstration (requires ANALYST or ADMIN).
     */
    private void handleSimulateThreat(HttpExchange exchange) throws IOException {
        User user = requireRole(exchange, "ADMIN", "ANALYST");
        if (user == null) return;
        String origin = "USER:" + user.getUsername();

        var event = accessEventService.simulateThreat(origin);
        sendJson(exchange, 201, event);
    }

    /**
     * GET /api/activity — Returns recent user activity audit trail.
     */
    private void handleGetActivity(HttpExchange exchange) throws IOException {
        User user = requireAuth(exchange);
        if (user == null) return;

        var activities = activityLogService.getAll(50);
        sendJson(exchange, 200, activities);
    }

    /**
     * GET /api/alerts — Returns all recent intrusion detection alerts.
     */
    private void handleGetAlerts(HttpExchange exchange) throws IOException {
        User user = requireAuth(exchange);
        if (user == null) return;

        var alerts = intrusionDetectionService.getRecentAlerts(50);
        sendJson(exchange, 200, alerts);
    }

    /**
     * GET /api/alerts/latest — Returns the most recent security alert.
     */
    private void handleGetLatestAlert(HttpExchange exchange) throws IOException {
        User user = requireAuth(exchange);
        if (user == null) return;

        SecurityAlert latest = intrusionDetectionService.getLatestAlert();
        if (latest != null) {
            sendJson(exchange, 200, latest);
        } else {
            JsonObject empty = new JsonObject();
            empty.addProperty("status", "NORMAL");
            empty.addProperty("message", "No active intrusion alerts detected.");
            sendJson(exchange, 200, empty);
        }
    }

    /**
     * GET /api/intrusion/config — Returns current IDS rule configuration.
     */
    private void handleGetIntrusionConfig(HttpExchange exchange) throws IOException {
        User user = requireAuth(exchange);
        if (user == null) return;

        sendJson(exchange, 200, intrusionDetectionService.getConfig());
    }

    /**
     * POST /api/intrusion/simulate-attack — Simulates a burst of 5 failed login attempts
     * from a specified or simulated source IP to demonstrate automated detection (requires ANALYST or ADMIN).
     */
    private void handleSimulateBruteForce(HttpExchange exchange) throws IOException {
        User user = requireRole(exchange, "ADMIN", "ANALYST");
        if (user == null) return;
        String body = readRequestBody(exchange);
        if (body == null) return; // 413 already sent
        String targetIp = "192.168.1.105";

        if (body != null && !body.trim().isEmpty()) {
            try {
                JsonObject json = gson.fromJson(body, JsonObject.class);
                if (json != null && json.has("ip") && !json.get("ip").getAsString().trim().isEmpty()) {
                    targetIp = json.get("ip").getAsString().trim();
                }
            } catch (Exception ignored) {}
        }

        long now = System.currentTimeMillis();
        SecurityAlert triggeredAlert = null;

        // Simulate 5 consecutive failed login attempts
        for (int i = 1; i <= 5; i++) {
            triggeredAlert = intrusionDetectionService.recordFailedLogin(targetIp, "admin", now + (i * 1000));
        }

        JsonObject response = new JsonObject();
        response.addProperty("success", true);
        response.addProperty("simulatedIp", targetIp);
        response.addProperty("attemptsSimulated", 5);
        if (triggeredAlert != null) {
            response.addProperty("alertGenerated", true);
            response.addProperty("incidentId", triggeredAlert.getIncidentId());
            response.addProperty("severity", triggeredAlert.getSeverity());
            response.add("alert", gson.toJsonTree(triggeredAlert));
        } else {
            response.addProperty("alertGenerated", false);
            response.addProperty("note", "Alert may be suppressed due to active cooldown for this IP.");
        }

        sendJson(exchange, 201, response);
    }

    /**
     * GET /api/threat-responses — Retrieves automated defensive countermeasures history.
     * Supports optional query params: ?incidentId=123, ?targetIp=1.2.3.4, ?status=EXECUTED
     */
    private void handleGetThreatResponses(HttpExchange exchange) throws IOException {
        User user = requireAuth(exchange);
        if (user == null) return;

        Map<String, String> query = parseQueryParams(exchange.getRequestURI());
        Integer incidentId = null;
        if (query.containsKey("incidentId")) {
            try {
                incidentId = Integer.parseInt(query.get("incidentId"));
            } catch (NumberFormatException ignored) {}
        }
        String targetIp = query.get("targetIp");
        String status = query.get("status");

        List<ThreatResponse> responses = threatResponseService.getResponseHistory(incidentId, targetIp, status);
        sendJson(exchange, 200, responses);
    }

    /**
     * GET /api/threat-responses/stats — Returns aggregated statistics on executed defenses.
     */
    private void handleGetThreatResponseStats(HttpExchange exchange) throws IOException {
        User user = requireAuth(exchange);
        if (user == null) return;

        ThreatResponseStats stats = threatResponseService.getResponseStatistics();
        sendJson(exchange, 200, stats);
    }

    // =========================================================================
    // REVIEW 3 PHASE 6A: FIREWALL & IP BLOCKING ENDPOINTS
    // =========================================================================

    /**
     * GET /api/firewall/blocked-ips — Retrieves active/historical blocked IPs.
     * Supports ?status=ACTIVE|EXPIRED|UNBLOCKED|ALL (default: ALL).
     */
    private void handleGetBlockedIps(HttpExchange exchange) throws IOException {
        User user = requireAuth(exchange);
        if (user == null) return;

        Map<String, String> query = parseQueryParams(exchange.getRequestURI());
        String status = query.getOrDefault("status", "ALL");

        List<BlockedIp> list = ipBlockService.getAllBlockedIps(status);
        sendJson(exchange, 200, list);
    }

    /**
     * POST /api/firewall/block — Administrator manually blocks an IP address.
     */
    private void handleBlockIp(HttpExchange exchange) throws IOException {
        User user = requireRole(exchange, "ADMIN");
        if (user == null) return;

        String body = readRequestBody(exchange);
        if (body == null) return; // 413 already sent
        JsonObject json = gson.fromJson(body, JsonObject.class);
        String ip = (json != null && json.has("ipAddress") && !json.get("ipAddress").getAsString().trim().isEmpty())
                ? json.get("ipAddress").getAsString().trim()
                : ((json != null && json.has("ip") && !json.get("ip").getAsString().trim().isEmpty())
                    ? json.get("ip").getAsString().trim() : null);
        if (ip == null) {
            sendError(exchange, 400, "IP address is required.");
            return;
        }
        String ipErr = validateIp(ip);
        if (ipErr != null) { sendError(exchange, 400, ipErr); return; }

        String reason = (json.has("reason") && !json.get("reason").getAsString().trim().isEmpty())
                ? json.get("reason").getAsString().trim()
                : "Manually blocked by Administrator";
        long duration = json.has("durationMinutes") ? json.get("durationMinutes").getAsLong() : 15L;

        try {
            BlockedIp blocked = ipBlockService.blockIp(ip, reason, duration, user.getUsername());
            activityLogService.log(user.getUsername(), "IP_MANUALLY_BLOCKED",
                    "Manually blocked IP: " + ip + " (" + duration + " min, Reason: " + reason + ")");

            JsonObject res = new JsonObject();
            res.addProperty("success", true);
            res.addProperty("message", "IP " + ip + " blocked successfully for " + duration + " minutes.");
            res.add("data", gson.toJsonTree(blocked));
            res.add("blockedIp", gson.toJsonTree(blocked));
            sendJson(exchange, 201, res);
        } catch (IllegalArgumentException e) {
            sendError(exchange, 400, e.getMessage());
        }
    }

    /**
     * POST /api/firewall/unblock — Administrator manually unblocks an active IP block.
     */
    private void handleUnblockIp(HttpExchange exchange) throws IOException {
        User user = requireRole(exchange, "ADMIN");
        if (user == null) return;

        String body = readRequestBody(exchange);
        if (body == null) return; // 413 already sent
        JsonObject json = gson.fromJson(body, JsonObject.class);
        String ip = (json != null && json.has("ipAddress") && !json.get("ipAddress").getAsString().trim().isEmpty())
                ? json.get("ipAddress").getAsString().trim()
                : ((json != null && json.has("ip") && !json.get("ip").getAsString().trim().isEmpty())
                    ? json.get("ip").getAsString().trim() : null);
        if (ip == null) {
            sendError(exchange, 400, "IP address is required.");
            return;
        }
        String ipErr = validateIp(ip);
        if (ipErr != null) { sendError(exchange, 400, ipErr); return; }

        boolean unblocked = ipBlockService.unblockIp(ip, user.getUsername());
        if (unblocked) {
            activityLogService.log(user.getUsername(), "IP_MANUALLY_UNBLOCKED",
                    "Manually unblocked IP: " + ip);

            JsonObject res = new JsonObject();
            res.addProperty("success", true);
            res.addProperty("message", "IP " + ip + " unblocked successfully.");
            sendJson(exchange, 200, res);
        } else {
            sendError(exchange, 404, "No active block found for IP: " + ip);
        }
    }

    // =========================================================================
    // REVIEW 3 PHASE 6A: ACCOUNT SECURITY & LOCKOUT ENDPOINTS
    // =========================================================================

    /**
     * GET /api/auth/locked-accounts — Retrieves all accounts with lock status (Admin only).
     */
    private void handleGetLockedAccounts(HttpExchange exchange) throws IOException {
        User user = requireRole(exchange, "ADMIN");
        if (user == null) return;

        List<AccountLockStatus> accounts = accountLockoutService.getAllLockedAccounts();
        sendJson(exchange, 200, accounts);
    }

    // =========================================================================
    // REVIEW 3 PHASE 6A: INVESTIGATOR DIRECTORY
    // =========================================================================

    /**
     * GET /api/investigators — Returns list of accounts eligible to be assigned as investigators.
     */
    private void handleGetInvestigators(HttpExchange exchange) throws IOException {
        User user = requireRole(exchange, "ADMIN", "ANALYST");
        if (user == null) return;

        List<User> list = userService.getAssignableInvestigators();
        com.google.gson.JsonArray arr = new com.google.gson.JsonArray();
        for (User u : list) {
            JsonObject obj = new JsonObject();
            obj.addProperty("id", u.getId());
            obj.addProperty("username", u.getUsername());
            obj.addProperty("role", u.getRole());
            obj.addProperty("createdAt", u.getCreatedAt());
            arr.add(obj);
        }
        sendJson(exchange, 200, arr);
    }

    // =========================================================================
    // REVIEW 3 PHASE 6A: INCIDENT INVESTIGATION & TRIAGE ENDPOINTS
    // =========================================================================

    /**
     * GET /api/incidents/{id}/investigations — Retrieves investigation notes for an incident.
     */
    private void handleGetInvestigationNotes(HttpExchange exchange) throws IOException {
        User user = requireAuth(exchange);
        if (user == null) return;

        int id = extractIdFromPath(exchange.getRequestURI().getPath(), "/api/incidents/");
        if (id <= 0) {
            sendError(exchange, 400, "Invalid incident ID.");
            return;
        }

        Incident inc = incidentService.getById(id);
        if (inc == null) {
            sendError(exchange, 404, "Incident #" + id + " not found.");
            return;
        }

        List<InvestigationNote> notes = incidentInvestigationService.getInvestigationNotes(id);
        sendJson(exchange, 200, notes);
    }

    /**
     * POST /api/incidents/{id}/investigations — Adds a note and optional JSON evidence.
     */
    private void handleAddInvestigationNote(HttpExchange exchange) throws IOException {
        User user = requireRole(exchange, "ADMIN", "ANALYST");
        if (user == null) return;

        int id = extractIdFromPath(exchange.getRequestURI().getPath(), "/api/incidents/");
        if (id <= 0) {
            sendError(exchange, 400, "Invalid incident ID.");
            return;
        }

        String body = readRequestBody(exchange);
        if (body == null) return; // 413 already sent
        JsonObject json = gson.fromJson(body, JsonObject.class);
        if (json == null || !json.has("notes") || json.get("notes").getAsString().trim().isEmpty()) {
            sendError(exchange, 400, "Investigation notes cannot be empty.");
            return;
        }

        String notes = json.get("notes").getAsString().trim();
        String noteErr = validateNote(notes);
        if (noteErr != null) { sendError(exchange, 400, noteErr); return; }

        String evidenceData = (json.has("evidenceData") && !json.get("evidenceData").isJsonNull())
                ? json.get("evidenceData").getAsString()
                : null;

        try {
            // SECURITY: Never trust analystUsername from frontend body. Always bind to authenticated user!
            InvestigationNote created = incidentInvestigationService.addInvestigationNote(
                    id, user.getUsername(), notes, evidenceData
            );
            if (created != null) {
                sendJson(exchange, 201, created);
            } else {
                sendError(exchange, 500, "Failed to persist investigation note.");
            }
        } catch (IllegalArgumentException e) {
            sendError(exchange, 400, e.getMessage());
        }
    }

    /**
     * GET /api/incidents/{id}/timeline — Retrieves chronological investigation timeline.
     */
    private void handleGetInvestigationTimeline(HttpExchange exchange) throws IOException {
        User user = requireAuth(exchange);
        if (user == null) return;

        int id = extractIdFromPath(exchange.getRequestURI().getPath(), "/api/incidents/");
        if (id <= 0) {
            sendError(exchange, 400, "Invalid incident ID.");
            return;
        }

        Incident inc = incidentService.getById(id);
        if (inc == null) {
            sendError(exchange, 404, "Incident #" + id + " not found.");
            return;
        }

        List<InvestigationTimelineItem> timeline = incidentInvestigationService.getInvestigationTimeline(id);
        sendJson(exchange, 200, timeline);
    }

    /**
     * GET /api/incidents/{id}/investigation-summary — Retrieves incident investigation summary.
     */
    private void handleGetInvestigationSummary(HttpExchange exchange) throws IOException {
        User user = requireAuth(exchange);
        if (user == null) return;

        int id = extractIdFromPath(exchange.getRequestURI().getPath(), "/api/incidents/");
        if (id <= 0) {
            sendError(exchange, 400, "Invalid incident ID.");
            return;
        }

        InvestigationSummary summary = incidentInvestigationService.getInvestigationSummary(id);
        if (summary != null) {
            sendJson(exchange, 200, summary);
        } else {
            sendError(exchange, 404, "Incident #" + id + " not found.");
        }
    }

    /**
     * POST /api/incidents/{id}/assign — Administrator assigns an investigator.
     */
    private void handleAssignInvestigator(HttpExchange exchange) throws IOException {
        User user = requireRole(exchange, "ADMIN");
        if (user == null) return;

        int id = extractIdFromPath(exchange.getRequestURI().getPath(), "/api/incidents/");
        if (id <= 0) {
            sendError(exchange, 400, "Invalid incident ID.");
            return;
        }

        String body = readRequestBody(exchange);
        if (body == null) return; // 413 already sent
        JsonObject json = gson.fromJson(body, JsonObject.class);
        if (json == null || !json.has("assignedAnalyst") || json.get("assignedAnalyst").getAsString().trim().isEmpty()) {
            sendError(exchange, 400, "Assigned analyst username is required.");
            return;
        }

        String assignedAnalyst = json.get("assignedAnalyst").getAsString().trim();
        String userErr = validateUsername(assignedAnalyst);
        if (userErr != null) { sendError(exchange, 400, userErr); return; }
        try {
            Incident updated = incidentInvestigationService.assignInvestigator(id, assignedAnalyst, user.getUsername());
            JsonObject res = new JsonObject();
            res.addProperty("success", true);
            res.addProperty("message", "Investigator '" + assignedAnalyst + "' assigned to incident #" + id);
            res.add("incident", gson.toJsonTree(updated));
            sendJson(exchange, 200, res);
        } catch (IllegalArgumentException e) {
            sendError(exchange, 400, e.getMessage());
        }
    }

    /**
     * POST /api/incidents/{id}/root-cause — Updates root cause classification.
     */
    private void handleUpdateRootCause(HttpExchange exchange) throws IOException {
        User user = requireRole(exchange, "ADMIN", "ANALYST");
        if (user == null) return;

        int id = extractIdFromPath(exchange.getRequestURI().getPath(), "/api/incidents/");
        if (id <= 0) {
            sendError(exchange, 400, "Invalid incident ID.");
            return;
        }

        String body = readRequestBody(exchange);
        if (body == null) return; // 413 already sent
        JsonObject json = gson.fromJson(body, JsonObject.class);
        if (json == null || !json.has("category") || json.get("category").getAsString().trim().isEmpty()) {
            sendError(exchange, 400, "Root cause category is required.");
            return;
        }

        String category = json.get("category").getAsString().trim();
        String explanation = (json.has("explanation") && !json.get("explanation").isJsonNull())
                ? json.get("explanation").getAsString().trim()
                : "";

        try {
            Incident updated = incidentInvestigationService.updateRootCause(id, category, explanation, user.getUsername());
            JsonObject res = new JsonObject();
            res.addProperty("success", true);
            res.addProperty("message", "Root cause classification updated for incident #" + id);
            res.add("incident", gson.toJsonTree(updated));
            sendJson(exchange, 200, res);
        } catch (IllegalArgumentException e) {
            sendError(exchange, 400, e.getMessage());
        }
    }

    /**
     * POST /api/incidents/{id}/resolve — Resolves incident with technical summary.
     */
    private void handleResolveIncident(HttpExchange exchange) throws IOException {
        User user = requireRole(exchange, "ADMIN", "ANALYST");
        if (user == null) return;

        int id = extractIdFromPath(exchange.getRequestURI().getPath(), "/api/incidents/");
        if (id <= 0) {
            sendError(exchange, 400, "Invalid incident ID.");
            return;
        }

        String body = readRequestBody(exchange);
        if (body == null) return; // 413 already sent
        JsonObject json = gson.fromJson(body, JsonObject.class);
        if (json == null || !json.has("resolutionSummary") || json.get("resolutionSummary").getAsString().trim().isEmpty()) {
            sendError(exchange, 400, "Resolution summary cannot be empty.");
            return;
        }

        String resolutionSummary = json.get("resolutionSummary").getAsString().trim();
        try {
            boolean resolved = incidentInvestigationService.resolveIncident(id, resolutionSummary, user.getUsername());
            if (resolved) {
                JsonObject res = new JsonObject();
                res.addProperty("success", true);
                res.addProperty("message", "Incident #" + id + " resolved successfully.");
                sendJson(exchange, 200, res);
            } else {
                sendError(exchange, 404, "Incident #" + id + " not found or could not be resolved.");
            }
        } catch (IllegalArgumentException e) {
            sendError(exchange, 400, e.getMessage());
        }
    }

    // =========================================================================
    // UTILITY METHODS
    // =========================================================================

    /** Validates authentication token from Authorization header. Sends 401 if unauthenticated. */
    private User requireAuth(HttpExchange exchange) throws IOException {
        String token = extractToken(exchange);
        User user = SessionManager.validateSession(token);
        if (user == null) {
            sendError(exchange, 401, "Authentication required. Please log in.");
            return null;
        }
        return user;
    }

    /**
     * Enforces Role-Based Access Control (RBAC).
     * Validates authentication and ensures caller possesses one of the allowed roles.
     * Sends 401 if unauthenticated, 403 if insufficient privileges.
     */
    private User requireRole(HttpExchange exchange, String... allowedRoles) throws IOException {
        User user = requireAuth(exchange);
        if (user == null) {
            return null;
        }
        String userRole = user.getRole();
        if (userRole != null) {
            for (String allowed : allowedRoles) {
                if (allowed.equalsIgnoreCase(userRole)) {
                    return user;
                }
            }
        }
        sendError(exchange, 403, "Permission Denied: Insufficient privileges for this operation.");
        return null;
    }

    /** Extracts bearer token strictly from 'Authorization: Bearer <token>' header. Query params are rejected for security. */
    private String extractToken(HttpExchange exchange) {
        String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
        if (authHeader != null && authHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return authHeader.substring(7).trim();
        }
        return null;
    }

    /** Extracts numerical ID from a REST URL path like /api/incidents/5 */
    private int extractIdFromPath(String path, String prefix) {
        try {
            String idStr = path.substring(prefix.length());
            // Remove any trailing slash or params
            if (idStr.contains("/")) {
                idStr = idStr.substring(0, idStr.indexOf('/'));
            }
            return Integer.parseInt(idStr);
        } catch (Exception e) {
            return -1;
        }
    }

    /** Parses URL query parameters. */
    private Map<String, String> parseQueryParams(URI uri) {
        Map<String, String> map = new HashMap<>();
        String query = uri.getQuery();
        if (query == null || query.isEmpty()) return map;

        String[] pairs = query.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf('=');
            if (idx > 0) {
                String key = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8);
                String val = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8);
                map.put(key, val);
            }
        }
        return map;
    }

    /**
     * Reads the HTTP request body as a UTF-8 string.
     * Rejects bodies larger than 64 KB with HTTP 413 to prevent memory exhaustion.
     */
    private String readRequestBody(HttpExchange exchange) throws IOException {
        final int MAX_BODY = 65536; // 64 KB
        byte[] buf = new byte[MAX_BODY + 1];
        int totalRead = 0;
        var in = exchange.getRequestBody();
        int read;
        while (totalRead <= MAX_BODY && (read = in.read(buf, totalRead, buf.length - totalRead)) != -1) {
            totalRead += read;
        }
        if (totalRead > MAX_BODY) {
            sendError(exchange, 413, "Request body too large. Maximum size is 64 KB.");
            return null; // caller must check for null
        }
        return new String(buf, 0, totalRead, StandardCharsets.UTF_8).trim();
    }

    /** Sends a JSON response with status code and Content-Type header. */
    private void sendJson(HttpExchange exchange, int statusCode, Object data) throws IOException {
        String jsonStr = gson.toJson(data);
        byte[] bytes = jsonStr.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    /** Sends a standardized error JSON response. */
    private void sendError(HttpExchange exchange, int statusCode, String message) throws IOException {
        JsonObject err = new JsonObject();
        err.addProperty("success", false);
        err.addProperty("error", message);
        err.addProperty("message", message);
        sendJson(exchange, statusCode, err);
    }

    /** Extracts the client IP from the socket address (loopback normalised to 127.0.0.1). */
    private String getClientIp(HttpExchange exchange) {
        if (isLocalConnection(exchange)) {
            String xff = exchange.getRequestHeaders().getFirst("X-Forwarded-For");
            if (xff != null && !xff.trim().isEmpty()) {
                return xff.trim();
            }
        }
        InetSocketAddress remoteAddr = exchange.getRemoteAddress();
        if (remoteAddr == null || remoteAddr.getAddress() == null) return "127.0.0.1";
        String ip = remoteAddr.getAddress().getHostAddress();
        if ("0:0:0:0:0:0:0:1".equals(ip) || "::1".equals(ip)) return "127.0.0.1";
        return ip;
    }

    /**
     * Sliding-window login rate limiter.
     * Returns true (and blocks) when an IP has made more than 10 login attempts in the last 60 seconds.
     * Thread-safe: each IP gets its own ArrayDeque guarded by putIfAbsent.
     */
    private boolean isLoginRateLimited(String ip) {
        long now = System.currentTimeMillis();
        long windowMs = 60_000L;
        Deque<Long> timestamps = loginAttempts.computeIfAbsent(ip, k -> new ArrayDeque<>());
        synchronized (timestamps) {
            // Evict timestamps older than the window
            while (!timestamps.isEmpty() && now - timestamps.peekFirst() > windowMs) {
                timestamps.pollFirst();
            }
            timestamps.addLast(now);
            return timestamps.size() > MAX_LOGIN_ATTEMPTS_PER_MINUTE;
        }
    }

    /**
     * Validates incident title: not null, 1–200 characters.
     * Returns error message or null if valid.
     */
    private String validateTitle(String title) {
        if (title == null || title.trim().isEmpty()) return "Incident title is required.";
        if (title.trim().length() > MAX_TITLE_LEN)
            return "Incident title must not exceed " + MAX_TITLE_LEN + " characters.";
        return null;
    }

    /**
     * Validates incident description: may be blank, but if provided must be ≤ 2000 chars.
     */
    private String validateDescription(String desc) {
        if (desc != null && desc.length() > MAX_DESC_LEN)
            return "Description must not exceed " + MAX_DESC_LEN + " characters.";
        return null;
    }

    /**
     * Validates severity: must be one of LOW, MEDIUM, HIGH, CRITICAL (case-insensitive).
     */
    private String validateSeverity(String severity) {
        if (severity == null || severity.trim().isEmpty()) return null; // optional
        if (!VALID_SEVERITIES.contains(severity.trim().toUpperCase()))
            return "Invalid severity. Allowed values: LOW, MEDIUM, HIGH, CRITICAL.";
        return null;
    }

    /**
     * Validates status: must be one of OPEN, IN_PROGRESS, RESOLVED, CLOSED.
     */
    private String validateStatus(String status) {
        if (status == null || status.trim().isEmpty()) return null; // optional
        if (!VALID_STATUSES.contains(status.trim().toUpperCase()))
            return "Invalid status. Allowed values: OPEN, IN_PROGRESS, RESOLVED, CLOSED.";
        return null;
    }

    /**
     * Validates an IP address string using InetAddress parsing.
     * Returns error message or null if valid.
     */
    private String validateIp(String ip) {
        if (ip == null || ip.trim().isEmpty()) return "IP address is required.";
        try {
            java.net.InetAddress.getByName(ip.trim());
            return null;
        } catch (java.net.UnknownHostException e) {
            return "Invalid IP address format: " + ip;
        }
    }

    /**
     * Validates a username: alphanumeric plus underscore, max 50 chars.
     */
    private String validateUsername(String username) {
        if (username == null || username.trim().isEmpty()) return "Username is required.";
        if (username.trim().length() > MAX_USERNAME_LEN)
            return "Username must not exceed " + MAX_USERNAME_LEN + " characters.";
        if (!username.trim().matches("[a-zA-Z0-9_]+"))
            return "Username may only contain letters, digits, and underscores.";
        return null;
    }

    /**
     * Validates investigation note text: not empty, max 5000 chars.
     */
    private String validateNote(String note) {
        if (note == null || note.trim().isEmpty()) return "Investigation note cannot be empty.";
        if (note.trim().length() > MAX_NOTE_LEN)
            return "Note must not exceed " + MAX_NOTE_LEN + " characters.";
        return null;
    }

    /**
     * Checks if the request originated from the local loopback interface (localhost).
     * Used exclusively to permit test harnesses running locally to pass simulated client IPs.
     */
    private boolean isLocalConnection(HttpExchange exchange) {
        InetSocketAddress remoteAddr = exchange.getRemoteAddress();
        if (remoteAddr == null || remoteAddr.getAddress() == null) return true;
        return remoteAddr.getAddress().isLoopbackAddress() ||
               "127.0.0.1".equals(remoteAddr.getAddress().getHostAddress()) ||
               "::1".equals(remoteAddr.getAddress().getHostAddress());
    }
}
