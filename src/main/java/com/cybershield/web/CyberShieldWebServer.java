package com.cybershield.web;

import com.cybershield.exception.DatabaseOperationException;
import com.cybershield.exception.IncidentManagementException;
import com.cybershield.model.Incident;
import com.cybershield.model.ResponseAction;
import com.cybershield.model.SecurityEvent;
import com.cybershield.model.Threat;
import com.cybershield.model.enums.IncidentStatus;
import com.cybershield.model.enums.ResponseActionType;
import com.cybershield.repository.DatabaseManager;
import com.cybershield.repository.IncidentRepository;
import com.cybershield.repository.ResponseActionRepository;
import com.cybershield.repository.SecurityEventRepository;
import com.cybershield.repository.ThreatRepository;
import com.cybershield.service.IncidentService;
import com.cybershield.service.SimulationService;
import com.cybershield.util.DateTimeUtils;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;

/**
 * Built-in HTTP Web Server for CyberShield.
 * Runs on http://localhost:8080 using standard Java 17 jdk.httpserver without external dependencies.
 * Serves a modern dark-mode SOC dashboard and REST API endpoints.
 */
public class CyberShieldWebServer {

    public static final int DEFAULT_PORT = 8080;
    private static HttpServer server;
    private static final SecurityEventRepository eventRepo = new SecurityEventRepository(DatabaseManager.getInstance());
    private static final ThreatRepository threatRepo = new ThreatRepository(DatabaseManager.getInstance());
    private static final ResponseActionRepository actionRepo = new ResponseActionRepository(DatabaseManager.getInstance());
    private static final IncidentRepository incidentRepo = new IncidentRepository(DatabaseManager.getInstance(), threatRepo, actionRepo);
    private static final IncidentService incidentService = new IncidentService(incidentRepo, threatRepo, actionRepo);
    private static final SimulationService simService = new SimulationService();

    public static synchronized void startServer(int port) throws IOException {
        if (server != null) {
            return;
        }

        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.setExecutor(Executors.newCachedThreadPool());

        // Static single-page SOC Web Dashboard
        server.createContext("/", new DashboardHandler());

        // REST API endpoints
        server.createContext("/api/metrics", new MetricsHandler());
        server.createContext("/api/events", new EventsHandler());
        server.createContext("/api/threats", new ThreatsHandler());
        server.createContext("/api/incidents", new IncidentsHandler());
        server.createContext("/api/actions", new ActionsHandler());
        server.createContext("/api/simulate", new SimulateHandler());
        server.createContext("/api/action", new ExecuteActionHandler());
        server.createContext("/api/resolve", new ResolveIncidentHandler());

        server.start();
        System.out.println("===================================================================");
        System.out.println("  🛡 CYBERSHIELD LOCALHOST WEB SERVER ACTIVE!");
        System.out.println("  👉 Access in browser: http://localhost:" + port);
        System.out.println("===================================================================");
    }

    public static synchronized void stopServer() {
        if (server != null) {
            server.stop(0);
            server = null;
        }
    }

    private static void sendJsonResponse(HttpExchange exchange, int statusCode, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static Map<String, String> parseQueryParams(String query) {
        Map<String, String> map = new HashMap<>();
        if (query == null || query.isEmpty()) return map;
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                map.put(kv[0], java.net.URLDecoder.decode(kv[1], StandardCharsets.UTF_8));
            } else if (kv.length == 1) {
                map.put(kv[0], "");
            }
        }
        return map;
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\b", "\\b")
                .replace("\f", "\\f")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    /**
     * Dashboard HTML Handler - Serves the complete, interactive dark-theme SOC Web Application.
     */
    private static class DashboardHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
                exchange.sendResponseHeaders(204, -1);
                return;
            }

            String html = getDashboardHtml();
            byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        }
    }

    private static class MetricsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                int events = eventRepo.count();
                int threats = threatRepo.count();
                int highCrit = threatRepo.countHighOrCritical();
                int openInc = incidentRepo.countByStatus(IncidentStatus.OPEN) + incidentRepo.countByStatus(IncidentStatus.INVESTIGATING);
                int resInc = incidentRepo.countByStatus(IncidentStatus.RESOLVED);

                String json = String.format(
                    "{\"events\":%d,\"threats\":%d,\"highCritical\":%d,\"openIncidents\":%d,\"resolvedIncidents\":%d}",
                    events, threats, highCrit, openInc, resInc
                );
                sendJsonResponse(exchange, 200, json);
            } catch (DatabaseOperationException e) {
                sendJsonResponse(exchange, 500, "{\"error\":\"" + escapeJson(e.getMessage()) + "\"}");
            }
        }
    }

    private static class EventsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                List<SecurityEvent> events = eventRepo.findAll(30);
                StringBuilder sb = new StringBuilder("[");
                for (int i = 0; i < events.size(); i++) {
                    SecurityEvent e = events.get(i);
                    if (i > 0) sb.append(",");
                    sb.append(String.format(
                        "{\"id\":%d,\"eventId\":\"%s\",\"timestamp\":\"%s\",\"type\":\"%s\",\"sourceIp\":\"%s\",\"user\":\"%s\",\"description\":\"%s\",\"payload\":\"%s\",\"severity\":\"%s\"}",
                        e.getId(), escapeJson(e.getEventId()), DateTimeUtils.format(e.getTimestamp()),
                        e.getEventType().name(), escapeJson(e.getSourceIp()), escapeJson(e.getUsername()),
                        escapeJson(e.getDescription()), escapeJson(e.getRawPayload()), e.getSeverity().name()
                    ));
                }
                sb.append("]");
                sendJsonResponse(exchange, 200, sb.toString());
            } catch (DatabaseOperationException e) {
                sendJsonResponse(exchange, 500, "{\"error\":\"" + escapeJson(e.getMessage()) + "\"}");
            }
        }
    }

    private static class ThreatsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                List<Threat> threats = threatRepo.findAll();
                StringBuilder sb = new StringBuilder("[");
                for (int i = 0; i < threats.size(); i++) {
                    Threat t = threats.get(i);
                    if (i > 0) sb.append(",");
                    sb.append(String.format(
                        "{\"id\":%d,\"threatId\":\"%s\",\"type\":\"%s\",\"severity\":\"%s\",\"status\":\"%s\",\"sourceIp\":\"%s\",\"targetAsset\":\"%s\",\"detectedAt\":\"%s\",\"description\":\"%s\",\"report\":\"%s\"}",
                        t.getId(), escapeJson(t.getThreatId()), t.getThreatType().name(), t.getSeverity().name(),
                        t.getStatus().name(), escapeJson(t.getSourceIp()), escapeJson(t.getTargetAsset()),
                        DateTimeUtils.format(t.getDetectedAt()), escapeJson(t.getDescription()),
                        escapeJson(t.generateIncidentReport())
                    ));
                }
                sb.append("]");
                sendJsonResponse(exchange, 200, sb.toString());
            } catch (DatabaseOperationException e) {
                sendJsonResponse(exchange, 500, "{\"error\":\"" + escapeJson(e.getMessage()) + "\"}");
            }
        }
    }

    private static class IncidentsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                List<Incident> incidents = incidentRepo.findAll();
                StringBuilder sb = new StringBuilder("[");
                for (int i = 0; i < incidents.size(); i++) {
                    Incident inc = incidents.get(i);
                    if (i > 0) sb.append(",");
                    sb.append(String.format(
                        "{\"id\":%d,\"incidentId\":\"%s\",\"title\":\"%s\",\"severity\":\"%s\",\"status\":\"%s\",\"threatId\":\"%s\",\"createdAt\":\"%s\",\"updatedAt\":\"%s\",\"description\":\"%s\",\"actionsCount\":%d}",
                        inc.getId(), escapeJson(inc.getIncidentId()), escapeJson(inc.getTitle()),
                        inc.getSeverity().name(), inc.getStatus().name(),
                        inc.getAssociatedThreat() != null ? escapeJson(inc.getAssociatedThreat().getThreatId()) : "None",
                        DateTimeUtils.format(inc.getCreatedAt()), DateTimeUtils.format(inc.getUpdatedAt()),
                        escapeJson(inc.getDescription()), inc.getResponseActions().size()
                    ));
                }
                sb.append("]");
                sendJsonResponse(exchange, 200, sb.toString());
            } catch (DatabaseOperationException e) {
                sendJsonResponse(exchange, 500, "{\"error\":\"" + escapeJson(e.getMessage()) + "\"}");
            }
        }
    }

    private static class ActionsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                List<ResponseAction> actions = actionRepo.findAll(30);
                StringBuilder sb = new StringBuilder("[");
                for (int i = 0; i < actions.size(); i++) {
                    ResponseAction act = actions.get(i);
                    if (i > 0) sb.append(",");
                    sb.append(String.format(
                        "{\"id\":%d,\"actionId\":\"%s\",\"incidentId\":\"%s\",\"actionType\":\"%s\",\"target\":\"%s\",\"executedBy\":\"%s\",\"status\":\"%s\",\"details\":\"%s\",\"executedAt\":\"%s\"}",
                        act.getId(), escapeJson(act.getActionId()), escapeJson(act.getIncidentId()),
                        act.getActionType().name(), escapeJson(act.getTarget()), escapeJson(act.getExecutedBy()),
                        escapeJson(act.getStatus()), escapeJson(act.getDetails()), DateTimeUtils.format(act.getExecutedAt())
                    ));
                }
                sb.append("]");
                sendJsonResponse(exchange, 200, sb.toString());
            } catch (DatabaseOperationException e) {
                sendJsonResponse(exchange, 500, "{\"error\":\"" + escapeJson(e.getMessage()) + "\"}");
            }
        }
    }

    private static class SimulateHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Map<String, String> params = parseQueryParams(exchange.getRequestURI().getQuery());
            String scenario = params.getOrDefault("scenario", "bruteforce").toLowerCase();

            try {
                SimulationService.SimulationResult result;
                switch (scenario) {
                    case "phishing" -> result = simService.simulatePhishing(
                        "finance@corporate.internal",
                        "payroll-update@secure-portal-verify.com",
                        "URGENT: Mandatory payroll verification required",
                        "http://verify-creds.phish-domain.com/login"
                    );
                    case "malware" -> result = simService.simulateMalware(
                        "WORKSTATION-04",
                        "C:\\Users\\Public\\ransom_encryptor_sim.exe",
                        "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
                    );
                    case "suspicious_login" -> result = simService.simulateSuspiciousLogin(
                        "sarah.admin",
                        "Vladivostok, Russia",
                        "185.220.101.5"
                    );
                    default -> result = simService.simulateBruteForce("root", "192.168.1.188", 6);
                }

                // Auto-escalate detected threats to formal incidents
                List<String> escalatedIncidentIds = new ArrayList<>();
                for (Threat t : result.detectedThreats()) {
                    try {
                        Incident inc = incidentService.escalateThreatToIncident(t, "Auto-Escalated " + t.getThreatType().getDisplayName());
                        escalatedIncidentIds.add(inc.getIncidentId());
                    } catch (IncidentManagementException ignored) {}
                }

                String json = String.format(
                    "{\"success\":true,\"scenario\":\"%s\",\"eventsGenerated\":%d,\"threatsDetected\":%d,\"escalatedIncidents\":%s,\"summary\":\"%s\"}",
                    escapeJson(result.scenarioName()), result.generatedEvents().size(), result.detectedThreats().size(),
                    "[\"" + String.join("\",\"", escalatedIncidentIds) + "\"]",
                    escapeJson(result.summaryMessage())
                );
                sendJsonResponse(exchange, 200, json);

            } catch (Exception e) {
                sendJsonResponse(exchange, 500, "{\"success\":false,\"error\":\"" + escapeJson(e.getMessage()) + "\"}");
            }
        }
    }

    private static class ExecuteActionHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Map<String, String> params = parseQueryParams(exchange.getRequestURI().getQuery());
            String incidentId = params.get("incidentId");
            String actionTypeStr = params.getOrDefault("actionType", "BLOCK_IP");

            if (incidentId == null || incidentId.isEmpty()) {
                sendJsonResponse(exchange, 400, "{\"error\":\"incidentId is required\"}");
                return;
            }

            try {
                ResponseActionType actionType = ResponseActionType.valueOf(actionTypeStr.toUpperCase());
                ResponseAction action = incidentService.executeResponseAction(incidentId, actionType, "analyst (web)", "Dispatched from Web Console");
                String json = String.format(
                    "{\"success\":true,\"actionId\":\"%s\",\"actionType\":\"%s\",\"target\":\"%s\",\"status\":\"%s\"}",
                    escapeJson(action.getActionId()), action.getActionType().name(), escapeJson(action.getTarget()), escapeJson(action.getStatus())
                );
                sendJsonResponse(exchange, 200, json);
            } catch (Exception e) {
                sendJsonResponse(exchange, 500, "{\"success\":false,\"error\":\"" + escapeJson(e.getMessage()) + "\"}");
            }
        }
    }

    private static class ResolveIncidentHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Map<String, String> params = parseQueryParams(exchange.getRequestURI().getQuery());
            String incidentId = params.get("incidentId");
            String notes = params.getOrDefault("notes", "Incident mitigated and resolved via Web Console.");

            if (incidentId == null || incidentId.isEmpty()) {
                sendJsonResponse(exchange, 400, "{\"error\":\"incidentId is required\"}");
                return;
            }

            try {
                incidentService.resolveIncident(incidentId, notes);
                sendJsonResponse(exchange, 200, "{\"success\":true,\"incidentId\":\"" + escapeJson(incidentId) + "\",\"status\":\"RESOLVED\"}");
            } catch (Exception e) {
                sendJsonResponse(exchange, 500, "{\"success\":false,\"error\":\"" + escapeJson(e.getMessage()) + "\"}");
            }
        }
    }

    private static String getDashboardHtml() {
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CYBERSHIELD — SOC Threat Monitoring & Incident Response</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #090d16;
            --bg-card: #111827;
            --bg-card-hover: #1f2937;
            --border-color: #1f293d;
            --text-primary: #f8fafc;
            --text-muted: #94a3b8;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --status-green: #10b981;
            --status-amber: #f59e0b;
            --status-red: #ef4444;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', -apple-system, sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-primary);
            line-height: 1.5;
            padding-bottom: 40px;
        }
        header {
            background-color: #0b1120;
            border-bottom: 1px solid var(--border-color);
            padding: 16px 28px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        .brand { display: flex; align-items: center; gap: 12px; }
        .brand h1 { font-size: 20px; font-weight: 700; color: var(--accent-cyan); letter-spacing: 0.5px; }
        .brand span { font-size: 13px; color: var(--text-muted); border-left: 1px solid var(--border-color); padding-left: 12px; }
        .header-status { display: flex; align-items: center; gap: 16px; font-size: 13px; }
        .badge-live { background: rgba(16, 185, 129, 0.15); color: var(--status-green); border: 1px solid var(--status-green); padding: 4px 10px; border-radius: 9999px; font-weight: 600; font-size: 12px; }

        .container { max-width: 1380px; margin: 0 auto; padding: 24px; display: flex; flex-direction: column; gap: 24px; }

        .banner-disclaimer {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid var(--status-red);
            border-radius: 8px;
            padding: 12px 18px;
            font-size: 13px;
            color: #fca5a5;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
        }
        .metric-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 18px 20px;
            display: flex;
            flex-direction: column;
            gap: 6px;
            transition: transform 0.2s, border-color 0.2s;
        }
        .metric-card:hover { transform: translateY(-2px); border-color: var(--accent-cyan); }
        .metric-title { font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.8px; color: var(--text-muted); }
        .metric-val { font-size: 32px; font-weight: 700; line-height: 1.1; }
        .metric-sub { font-size: 11px; color: var(--text-muted); }

        .section-title {
            font-size: 16px;
            font-weight: 700;
            color: var(--accent-cyan);
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .simulator-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
        }
        .sim-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 14px;
            margin-bottom: 18px;
        }
        .sim-box {
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            gap: 12px;
        }
        .sim-box h3 { font-size: 14px; font-weight: 600; color: var(--text-primary); }
        .sim-box p { font-size: 12px; color: var(--text-muted); }
        .btn {
            background: var(--accent-blue);
            color: white;
            border: none;
            border-radius: 6px;
            padding: 9px 14px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: opacity 0.2s, background-color 0.2s;
            text-align: center;
        }
        .btn:hover { opacity: 0.9; }
        .btn-danger { background: var(--status-red); }
        .btn-success { background: var(--status-green); color: #022c22; }
        .btn-outline { background: transparent; border: 1px solid var(--border-color); color: var(--text-muted); }
        .btn-outline:hover { background: var(--bg-card-hover); color: var(--text-primary); }

        .terminal-console {
            background: #050811;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 14px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: #34d399;
            height: 160px;
            overflow-y: auto;
            white-space: pre-wrap;
        }

        .data-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: 24px;
        }

        .table-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            overflow-x: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            text-align: left;
        }
        th {
            background: #0f172a;
            color: var(--text-muted);
            font-weight: 600;
            padding: 10px 14px;
            border-bottom: 1px solid var(--border-color);
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.5px;
        }
        td {
            padding: 10px 14px;
            border-bottom: 1px solid rgba(31, 41, 61, 0.6);
            color: var(--text-primary);
        }
        tr:hover td { background: rgba(30, 41, 59, 0.4); }

        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }
        .badge-critical { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
        .badge-high { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }
        .badge-medium { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6; }
        .badge-low { background: rgba(148, 163, 184, 0.2); color: #cbd5e1; border: 1px solid #64748b; }
        .badge-resolved { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }

        .action-btn-group { display: flex; gap: 6px; }
        .action-btn-group .btn { padding: 4px 8px; font-size: 11px; }
    </style>
</head>
<body>

<header>
    <div class="brand">
        <h1>🛡 CYBERSHIELD</h1>
        <span>SOC Threat Monitoring & Incident Response</span>
    </div>
    <div class="header-status">
        <span class="badge-live">● LOCALHOST ONLINE (:8080)</span>
        <span style="color: var(--text-muted);">Operator: <b>analyst</b></span>
    </div>
</header>

<div class="container">

    <div class="banner-disclaimer">
        <span>⚠️</span>
        <div><b>SIMULATION ONLY:</b> Educational cybersecurity demonstration system. Safe mock telemetry without actual exploits, packet sniffing, or network manipulation.</div>
    </div>

    <!-- 5 KPI Metric Cards -->
    <div class="metrics-grid">
        <div class="metric-card">
            <span class="metric-title">Total Events</span>
            <span class="metric-val" id="val-events" style="color: var(--accent-cyan);">0</span>
            <span class="metric-sub">Telemetry records ingested</span>
        </div>
        <div class="metric-card">
            <span class="metric-title">Total Threats</span>
            <span class="metric-val" id="val-threats" style="color: var(--accent-blue);">0</span>
            <span class="metric-sub">Heuristically detected</span>
        </div>
        <div class="metric-card">
            <span class="metric-title">High / Critical</span>
            <span class="metric-val" id="val-highcrit" style="color: var(--status-red);">0</span>
            <span class="metric-sub">Priority security alarms</span>
        </div>
        <div class="metric-card">
            <span class="metric-title">Open Incidents</span>
            <span class="metric-val" id="val-openinc" style="color: var(--status-amber);">0</span>
            <span class="metric-sub">Awaiting containment</span>
        </div>
        <div class="metric-card">
            <span class="metric-title">Resolved Incidents</span>
            <span class="metric-val" id="val-resinc" style="color: var(--status-green);">0</span>
            <span class="metric-sub">Successfully mitigated</span>
        </div>
    </div>

    <!-- Interactive Attack Scenario Simulator -->
    <div class="simulator-card">
        <div class="section-title">
            <span>🎯 CYBER THREAT ATTACK SCENARIO SIMULATOR</span>
            <span style="font-size: 12px; color: var(--text-muted); font-weight: normal;">Click any scenario to simulate live telemetry & threat detection</span>
        </div>
        <div class="sim-grid">
            <div class="sim-box">
                <div>
                    <h3>1. Brute Force Attack</h3>
                    <p>Simulates rapid SSH password spraying against root account from an external IP.</p>
                </div>
                <button class="btn btn-danger" onclick="triggerSimulation('bruteforce')">SIMULATE BRUTE FORCE</button>
            </div>
            <div class="sim-box">
                <div>
                    <h3>2. Spear Phishing Campaign</h3>
                    <p>Simulates deceptive inbound corporate payroll verification email with fraudulent URL.</p>
                </div>
                <button class="btn" onclick="triggerSimulation('phishing')">SIMULATE PHISHING</button>
            </div>
            <div class="sim-box">
                <div>
                    <h3>3. Ransomware File Drop</h3>
                    <p>Simulates suspicious binary drop and process creation signature on an endpoint.</p>
                </div>
                <button class="btn btn-danger" onclick="triggerSimulation('malware')">SIMULATE MALWARE</button>
            </div>
            <div class="sim-box">
                <div>
                    <h3>4. Suspicious Login Anomaly</h3>
                    <p>Simulates impossible travel velocity anomaly and off-hours foreign device access.</p>
                </div>
                <button class="btn" onclick="triggerSimulation('suspicious_login')">SIMULATE SUSPICIOUS LOGIN</button>
            </div>
        </div>

        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
            <span style="font-size: 12px; font-weight: 600; color: var(--accent-cyan);">EXECUTION TRACE TERMINAL</span>
            <button class="btn btn-outline" style="padding: 2px 8px; font-size: 11px;" onclick="clearConsole()">Clear Console</button>
        </div>
        <div class="terminal-console" id="sim-console">=== CyberShield Simulation Engine Ready. Select a scenario above to test. ===\n</div>
    </div>

    <div class="data-grid">

        <!-- Incidents Table with Containment Action Triggers -->
        <div class="table-card">
            <div class="section-title">
                <span>🚨 ESCALATED INCIDENT CASES & CONTAINMENT ACTIONS</span>
                <button class="btn btn-outline" onclick="loadAllData()">↻ Refresh</button>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Incident ID</th>
                        <th>Title</th>
                        <th>Severity</th>
                        <th>Status</th>
                        <th>Created</th>
                        <th>Actions Taken</th>
                        <th>Dispatch Containment</th>
                    </tr>
                </thead>
                <tbody id="incidents-body">
                    <tr><td colspan="7" style="text-align: center; color: var(--text-muted);">No open incidents recorded.</td></tr>
                </tbody>
            </table>
        </div>

        <!-- Threats Table -->
        <div class="table-card">
            <div class="section-title">
                <span>⚡ IDENTIFIED SECURITY THREATS (POLYMORPHIC HEURISTICS)</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Threat ID</th>
                        <th>Category</th>
                        <th>Severity</th>
                        <th>Source IP</th>
                        <th>Target Asset</th>
                        <th>Status</th>
                        <th>Detected At</th>
                    </tr>
                </thead>
                <tbody id="threats-body">
                    <tr><td colspan="7" style="text-align: center; color: var(--text-muted);">No threats detected yet.</td></tr>
                </tbody>
            </table>
        </div>

        <!-- Telemetry Feed -->
        <div class="table-card">
            <div class="section-title">
                <span>📡 INGESTED TELEMETRY STREAM</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Event ID</th>
                        <th>Time</th>
                        <th>Type</th>
                        <th>Source IP</th>
                        <th>User</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody id="events-body">
                    <tr><td colspan="6" style="text-align: center; color: var(--text-muted);">Loading telemetry stream...</td></tr>
                </tbody>
            </table>
        </div>

        <!-- Audit Trail -->
        <div class="table-card">
            <div class="section-title">
                <span>📈 INCIDENT RESPONSE CONTAINMENT AUDIT TRAIL</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Action ID</th>
                        <th>Incident ID</th>
                        <th>Action Dispatched</th>
                        <th>Target</th>
                        <th>Operator</th>
                        <th>Status</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody id="actions-body">
                    <tr><td colspan="7" style="text-align: center; color: var(--text-muted);">No containment actions dispatched yet.</td></tr>
                </tbody>
            </table>
        </div>

    </div>

</div>

<script>
    function logConsole(msg) {
        const con = document.getElementById('sim-console');
        const now = new Date().toLocaleTimeString();
        con.textContent += `[${now}] ${msg}\\n`;
        con.scrollTop = con.scrollHeight;
    }

    function clearConsole() {
        document.getElementById('sim-console').textContent = "=== CyberShield Simulation Console Cleared. ===\\n";
    }

    function getSeverityBadge(sev) {
        const s = (sev || 'LOW').toUpperCase();
        if (s === 'CRITICAL') return '<span class="badge badge-critical">CRITICAL</span>';
        if (s === 'HIGH') return '<span class="badge badge-high">HIGH</span>';
        if (s === 'MEDIUM') return '<span class="badge badge-medium">MEDIUM</span>';
        return '<span class="badge badge-low">LOW</span>';
    }

    function getStatusBadge(st) {
        const s = (st || 'OPEN').toUpperCase();
        if (s === 'RESOLVED') return '<span class="badge badge-resolved">RESOLVED</span>';
        if (s === 'INVESTIGATING') return '<span class="badge badge-medium">INVESTIGATING</span>';
        return '<span class="badge badge-high">OPEN</span>';
    }

    async function triggerSimulation(scenario) {
        logConsole(`>>> TRIGGERING SCENARIO: ${scenario.toUpperCase()}`);
        try {
            const res = await fetch(`/api/simulate?scenario=${scenario}`);
            const data = await res.json();
            if (data.success) {
                logConsole(`Ingested ${data.eventsGenerated} events.`);
                logConsole(`⚡ Detection Engine identified ${data.threatsDetected} threat(s)!`);
                logConsole(`▲ Auto-Escalated to Incidents: ${data.escalatedIncidents.join(', ')}`);
                logConsole(`>>> COMPLETED: ${data.summary}`);
                loadAllData();
            } else {
                logConsole(`ERROR: ${data.error}`);
            }
        } catch (e) {
            logConsole(`Execution failed: ${e.message}`);
        }
    }

    async function dispatchAction(incidentId, actionType) {
        logConsole(`Executing containment response action: ${actionType} on ${incidentId}...`);
        try {
            const res = await fetch(`/api/action?incidentId=${encodeURIComponent(incidentId)}&actionType=${actionType}`);
            const data = await res.json();
            if (data.success) {
                logConsole(`✓ Action ${data.actionId} (${data.actionType}) successfully executed on ${data.target}!`);
                loadAllData();
            } else {
                alert(`Action failed: ${data.error}`);
            }
        } catch (e) {
            alert(`Network error: ${e.message}`);
        }
    }

    async function resolveIncident(incidentId) {
        const notes = prompt("Enter resolution notes for this incident:", "Threat neutralized and perimeter verified.");
        if (notes) {
            try {
                const res = await fetch(`/api/resolve?incidentId=${encodeURIComponent(incidentId)}&notes=${encodeURIComponent(notes)}`);
                const data = await res.json();
                if (data.success) {
                    logConsole(`✓ Incident ${incidentId} marked as RESOLVED!`);
                    loadAllData();
                } else {
                    alert(`Resolution failed: ${data.error}`);
                }
            } catch (e) {
                alert(`Network error: ${e.message}`);
            }
        }
    }

    async function loadAllData() {
        try {
            // Metrics
            const mRes = await fetch('/api/metrics');
            const m = await mRes.json();
            document.getElementById('val-events').textContent = m.events;
            document.getElementById('val-threats').textContent = m.threats;
            document.getElementById('val-highcrit').textContent = m.highCritical;
            document.getElementById('val-openinc').textContent = m.openIncidents;
            document.getElementById('val-resinc').textContent = m.resolvedIncidents;

            // Events
            const eRes = await fetch('/api/events');
            const events = await eRes.json();
            const eb = document.getElementById('events-body');
            if (events.length > 0) {
                eb.innerHTML = events.slice(0, 10).map(e => `
                    <tr>
                        <td><code>${e.eventId}</code></td>
                        <td>${e.timestamp}</td>
                        <td><b>${e.type}</b></td>
                        <td>${e.sourceIp}</td>
                        <td>${e.user}</td>
                        <td>${e.description}</td>
                    </tr>
                `).join('');
            }

            // Threats
            const tRes = await fetch('/api/threats');
            const threats = await tRes.json();
            const tb = document.getElementById('threats-body');
            if (threats.length > 0) {
                tb.innerHTML = threats.map(t => `
                    <tr>
                        <td><code>${t.threatId}</code></td>
                        <td><b>${t.type}</b></td>
                        <td>${getSeverityBadge(t.severity)}</td>
                        <td>${t.sourceIp}</td>
                        <td>${t.targetAsset}</td>
                        <td>${getStatusBadge(t.status)}</td>
                        <td>${t.detectedAt}</td>
                    </tr>
                `).join('');
            }

            // Incidents
            const iRes = await fetch('/api/incidents');
            const incidents = await iRes.json();
            const ib = document.getElementById('incidents-body');
            if (incidents.length > 0) {
                ib.innerHTML = incidents.map(inc => `
                    <tr>
                        <td><code>${inc.incidentId}</code></td>
                        <td><b>${inc.title}</b></td>
                        <td>${getSeverityBadge(inc.severity)}</td>
                        <td>${getStatusBadge(inc.status)}</td>
                        <td>${inc.createdAt}</td>
                        <td>${inc.actionsCount} action(s)</td>
                        <td>
                            <div class="action-btn-group">
                                ${inc.status !== 'RESOLVED' ? `
                                    <button class="btn btn-danger" onclick="dispatchAction('${inc.incidentId}', 'BLOCK_IP')">Block IP</button>
                                    <button class="btn btn-danger" onclick="dispatchAction('${inc.incidentId}', 'DISABLE_USER')">Disable User</button>
                                    <button class="btn btn-danger" onclick="dispatchAction('${inc.incidentId}', 'QUARANTINE_SIMULATION')">Quarantine</button>
                                    <button class="btn btn-success" onclick="resolveIncident('${inc.incidentId}')">✓ Resolve</button>
                                ` : '<span style="color: var(--status-green); font-weight: 600;">Resolved</span>'}
                            </div>
                        </td>
                    </tr>
                `).join('');
            }

            // Actions Audit Trail
            const aRes = await fetch('/api/actions');
            const actions = await aRes.json();
            const ab = document.getElementById('actions-body');
            if (actions.length > 0) {
                ab.innerHTML = actions.map(a => `
                    <tr>
                        <td><code>${a.actionId}</code></td>
                        <td><code>${a.incidentId}</code></td>
                        <td><b>${a.actionType}</b></td>
                        <td>${a.target}</td>
                        <td>${a.executedBy}</td>
                        <td><span class="badge badge-resolved">${a.status}</span></td>
                        <td>${a.executedAt}</td>
                    </tr>
                `).join('');
            }

        } catch (e) {
            console.error("Failed to fetch data:", e);
        }
    }

    // Initial load and periodic polling every 4 seconds
    loadAllData();
    setInterval(loadAllData, 4000);
</script>

</body>
</html>
""";
    }

    public static void main(String[] args) {
        try {
            DatabaseManager.getInstance().initializeDatabase();
            startServer(DEFAULT_PORT);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
