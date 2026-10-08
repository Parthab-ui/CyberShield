package cybershield.util;

import cybershield.dao.BlockedIPDAO;
import cybershield.dao.IncidentDAO;
import cybershield.dao.LogDAO;
import cybershield.dao.StatsDAO;
import cybershield.dao.ThreatDAO;
import cybershield.model.BlockedIP;
import cybershield.model.Incident;
import cybershield.model.Threat;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * ReportGenerator — Utility that extracts database metrics and compiles formatted report texts.
 * Isolates data assembly from ReportPanel GUI rendering.
 * Provides HTML generation for JEditorPane and structured text for JTextPane StyledDocument.
 */
public class ReportGenerator {

    private final StatsDAO     statsDAO;
    private final ThreatDAO    threatDAO;
    private final IncidentDAO  incidentDAO;
    private final BlockedIPDAO blockedIPDAO;
    private final LogDAO       logDAO;

    public ReportGenerator() {
        this.statsDAO     = new StatsDAO();
        this.threatDAO    = new ThreatDAO();
        this.incidentDAO  = new IncidentDAO();
        this.blockedIPDAO = new BlockedIPDAO();
        this.logDAO       = new LogDAO();
    }

    /** Generates an HTML Executive Summary Report for JEditorPane. */
    public String generateSummaryHtmlReport(int days) {
        int totalThreats    = statsDAO.countThreats();
        int criticalThreats = statsDAO.countThreatsBySeverity("CRITICAL");
        int openIncidents   = statsDAO.countOpenIncidents();
        int blockedIPs      = statsDAO.countBlockedIPs();
        int resolvedThreats = statsDAO.countResolvedThreats();
        int closedIncidents = statsDAO.countClosedIncidents();
        int totalIncidents  = statsDAO.countTotalIncidents();

        int threatResRate   = totalThreats > 0 ? (resolvedThreats * 100) / totalThreats : 0;
        int incResRate      = totalIncidents > 0 ? (closedIncidents * 100) / totalIncidents : 0;
        String generatedAt  = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

        StringBuilder html = new StringBuilder();
        html.append("<html><body style='background-color:#121228; color:#e6e6e6; font-family:Segoe UI, sans-serif; padding:15px;'>");
        html.append("<h1 style='color:#00c8dc; margin-bottom:4px;'>CYBERSHIELD EXECUTIVE SECURITY REPORT</h1>");
        html.append("<p style='color:#9696aa; font-size:11px;'>Generated on: ").append(generatedAt).append(" | Scope: Last ").append(days).append(" days</p>");
        html.append("<hr style='border:1px solid #32325a;'/>");

        html.append("<h3 style='color:#00c8dc;'>1. System Health & Threat Overview</h3>");
        html.append("<table border='1' cellpadding='8' cellspacing='0' style='border-collapse:collapse; border-color:#32325a; width:100%; font-size:12px;'>");
        html.append("<tr style='background-color:#1a1a3a; color:#00c8dc;'><th>Metric</th><th>Count</th><th>Status Indicator</th></tr>");
        html.append("<tr><td>Total Detected Threats</td><td><b>").append(totalThreats).append("</b></td><td style='color:#00c8dc;'>Monitored</td></tr>");
        html.append("<tr><td>Critical Severity Threats</td><td><b>").append(criticalThreats).append("</b></td><td style='color:#dc3232;'>").append(criticalThreats > 0 ? "URGENT ACTION NEEDED" : "NORMAL").append("</td></tr>");
        html.append("<tr><td>Open Security Incidents</td><td><b>").append(openIncidents).append("</b></td><td style='color:#ffa500;'>").append(openIncidents > 0 ? "INVESTIGATING" : "CLEAR").append("</td></tr>");
        html.append("<tr><td>Active Blocked IPs (Blacklist)</td><td><b>").append(blockedIPs).append("</b></td><td style='color:#32c850;'>ENFORCED</td></tr>");
        html.append("<tr><td>Threat Resolution Rate</td><td><b>").append(threatResRate).append("%</b></td><td style='color:#32c850;'>").append(resolvedThreats).append(" / ").append(totalThreats).append(" resolved</td></tr>");
        html.append("<tr><td>Incident Closure Rate</td><td><b>").append(incResRate).append("%</b></td><td style='color:#00c8dc;'>").append(closedIncidents).append(" / ").append(totalIncidents).append(" closed</td></tr>");
        html.append("</table>");

        html.append("<h3 style='color:#00c8dc; margin-top:20px;'>2. Threat Distribution by Severity</h3>");
        html.append("<table border='1' cellpadding='6' cellspacing='0' style='border-collapse:collapse; border-color:#32325a; width:100%; font-size:12px;'>");
        html.append("<tr style='background-color:#1a1a3a; color:#00c8dc;'><th>Severity</th><th>Threat Count</th><th>Impact Assessment</th></tr>");

        Map<String, Integer> sevMap = statsDAO.countThreatsBySeverityMap();
        html.append("<tr><td style='color:#32c850;'><b>LOW</b></td><td>").append(sevMap.getOrDefault("LOW", 0)).append("</td><td>Informational & reconnaissance probes</td></tr>");
        html.append("<tr><td style='color:#f0c832;'><b>MEDIUM</b></td><td>").append(sevMap.getOrDefault("MEDIUM", 0)).append("</td><td>Port scans, brute-force attempts</td></tr>");
        html.append("<tr><td style='color:#ffa500;'><b>HIGH</b></td><td>").append(sevMap.getOrDefault("HIGH", 0)).append("</td><td>Targeted exploitation & credential theft</td></tr>");
        html.append("<tr><td style='color:#dc3232;'><b>CRITICAL</b></td><td>").append(sevMap.getOrDefault("CRITICAL", 0)).append("</td><td>Ransomware, root compromise & DDoS bursts</td></tr>");
        html.append("</table>");

        html.append("<h3 style='color:#00c8dc; margin-top:20px;'>3. Strategic Recommendations</h3>");
        html.append("<ul>");
        html.append("<li>Ensure continuous firewall ingestion from active blacklisted IP pools.</li>");
        html.append("<li>Prioritize open incidents with CRITICAL and HIGH priority tiers.</li>");
        html.append("<li>Maintain routine log audit verification on the live dashboard.</li>");
        html.append("</ul>");

        html.append("</body></html>");
        return html.toString();
    }

    /** Generates an HTML Incident Response Report for JEditorPane. */
    public String generateIncidentHtmlReport(int days) {
        List<Incident> incidents = incidentDAO.getAll();
        String generatedAt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

        StringBuilder html = new StringBuilder();
        html.append("<html><body style='background-color:#121228; color:#e6e6e6; font-family:Segoe UI, sans-serif; padding:15px;'>");
        html.append("<h1 style='color:#00c8dc;'>INCIDENT RESPONSE DOSSIER REPORT</h1>");
        html.append("<p style='color:#9696aa; font-size:11px;'>Generated on: ").append(generatedAt).append(" | Total Incidents: ").append(incidents.size()).append("</p>");
        html.append("<hr style='border:1px solid #32325a;'/>");

        html.append("<table border='1' cellpadding='8' cellspacing='0' style='border-collapse:collapse; border-color:#32325a; width:100%; font-size:12px;'>");
        html.append("<tr style='background-color:#1a1a3a; color:#00c8dc;'>");
        html.append("<th>ID</th><th>Title</th><th>Threat ID</th><th>Priority</th><th>Status</th><th>Logged At</th>");
        html.append("</tr>");

        for (Incident inc : incidents) {
            String pColor = "#32c850";
            if ("CRITICAL".equalsIgnoreCase(inc.getPriority())) pColor = "#dc3232";
            else if ("HIGH".equalsIgnoreCase(inc.getPriority())) pColor = "#ffa500";
            else if ("MEDIUM".equalsIgnoreCase(inc.getPriority())) pColor = "#f0c832";

            String sColor = "OPEN".equalsIgnoreCase(inc.getStatus()) ? "#dc3232" : ("IN_PROGRESS".equalsIgnoreCase(inc.getStatus()) ? "#ffa500" : "#32c850");

            html.append("<tr>");
            html.append("<td>#").append(inc.getId()).append("</td>");
            html.append("<td><b>").append(inc.getTitle()).append("</b><br/><span style='color:#9696aa; font-size:10px;'>").append(inc.getDescription()).append("</span></td>");
            html.append("<td>Threat #").append(inc.getThreatId()).append("</td>");
            html.append("<td style='color:").append(pColor).append(";'><b>").append(inc.getPriority()).append("</b></td>");
            html.append("<td style='color:").append(sColor).append(";'><b>").append(inc.getStatus()).append("</b></td>");
            html.append("<td>").append(inc.getCreatedAt()).append("</td>");
            html.append("</tr>");
        }

        html.append("</table>");
        html.append("</body></html>");
        return html.toString();
    }

    /** Generates plain text threat report for export or text processing. */
    public String generateThreatPlainTextReport(int days) {
        List<Threat> threats = threatDAO.getRecentThreats(days);
        if (threats.isEmpty()) {
            threats = threatDAO.getAll();
        }

        StringBuilder sb = new StringBuilder();
        sb.append("=====================================================\n");
        sb.append("         CYBERSHIELD THREAT AUDIT REPORT             \n");
        sb.append("=====================================================\n");
        sb.append("Generated At: ").append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date())).append("\n");
        sb.append("Total Threats Analyzed: ").append(threats.size()).append("\n\n");

        for (Threat t : threats) {
            sb.append(String.format("Threat #%d: [%s] Type: %s | Target: %s | IP: %s | Status: %s | Date: %s\n",
                t.getId(), t.getSeverity(), t.getThreatType(), t.getTargetSystem(),
                t.getSourceIp(), t.getStatus(), t.getDetectedAt()));
        }

        sb.append("\n==================== END OF REPORT ==================\n");
        return sb.toString();
    }
}
