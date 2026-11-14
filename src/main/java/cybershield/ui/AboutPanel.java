package cybershield.ui;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;

/**
 * AboutPanel — Displays project specifications, academic evaluation metadata,
 * technology stack, and editable team member placeholders for college review.
 * Demonstrates:
 * - Clean multi-card layout with JPanel and TitledBorder.
 * - Presentation of architecture for faculty evaluation.
 */
public class AboutPanel extends JPanel {

    public AboutPanel() {
        setLayout(new BorderLayout(0, 16));
        setBackground(SwingTheme.PANEL_BG);
        setBorder(BorderFactory.createEmptyBorder(20, 24, 20, 24));

        initContent();
    }

    private void initContent() {
        // TOP: Title & Mission
        JPanel topPanel = new JPanel(new BorderLayout(0, 6));
        topPanel.setOpaque(false);

        JLabel title = new JLabel("CyberShield — Cybersecurity Monitoring and Incident Management System");
        title.setFont(SwingTheme.FONT_TITLE);
        title.setForeground(SwingTheme.TEXT_PRIMARY);

        JLabel subtitle = new JLabel("Academic B.Tech Computer Science & Engineering 2nd Year Project Evaluation");
        subtitle.setFont(SwingTheme.FONT_BODY);
        subtitle.setForeground(SwingTheme.PRIMARY_COLOR);

        topPanel.add(title, BorderLayout.NORTH);
        topPanel.add(subtitle, BorderLayout.SOUTH);
        add(topPanel, BorderLayout.NORTH);

        // CENTER: 2-column grid of details
        JPanel gridPanel = new JPanel(new GridLayout(2, 2, 16, 16));
        gridPanel.setOpaque(false);

        // Card 1: Project Objectives & Scope
        JPanel objCard = createCard("Project Objectives & Scope");
        JTextArea objText = createReadOnlyTextArea(
            "• Real-time Incident Lifecycle Tracking: Report, categorize, prioritize, and resolve cybersecurity incidents.\n\n" +
            "• Intrusion Detection & Telemetry: Monitor unauthorized authentication anomalies and brute-force attempts.\n\n" +
            "• Unified Dual Interface: Single persistent SQLite database accessed synchronously by both modern Web and Java Swing Desktop applications.\n\n" +
            "• Role-Based Access Control: Strict administrative authorization ensuring non-admin users cannot purge records."
        );
        objCard.add(new JScrollPane(objText), BorderLayout.CENTER);
        gridPanel.add(objCard);

        // Card 2: Technology Stack
        JPanel techCard = createCard("Technical Architecture & Libraries");
        JTextArea techText = createReadOnlyTextArea(
            "• Core Language: Java (JDK 17+ compatible)\n\n" +
            "• Desktop GUI: Pure Java Swing (EDT safe, comprehensive 40+ component inventory, custom renderers)\n\n" +
            "• Embedded Backend: Java HttpServer (com.sun.net.httpserver) with REST API endpoints\n\n" +
            "• Database Layer: SQLite via JDBC with Write-Ahead Logging (WAL) for safe multi-client concurrency\n\n" +
            "• Web Client: Clean Vanilla HTML5, Dark Navy CSS, and JavaScript SPA (Zero heavy frameworks)\n\n" +
            "• Security: Salted SHA-256 password hashing and token-based session verification"
        );
        techCard.add(new JScrollPane(techText), BorderLayout.CENTER);
        gridPanel.add(techCard);

        // Card 3: Academic Review Team (Placeholders)
        JPanel teamCard = createCard("Project Review Team (Editable Placeholders)");
        JTextArea teamText = createReadOnlyTextArea(
            "Student Team Members:\n" +
            "1. Name: [STUDENT 1 NAME] | Reg No: [REGISTRATION NUMBER 1]\n" +
            "2. Name: [STUDENT 2 NAME] | Reg No: [REGISTRATION NUMBER 2]\n\n" +
            "Academic Details:\n" +
            "• Degree: B.Tech Computer Science & Engineering (2nd Year)\n" +
            "• Course: Advanced Java Programming / Object-Oriented Software Engineering\n" +
            "• Faculty Guide: [FACULTY GUIDE NAME & DESIGNATION]\n" +
            "• Department: Department of Computer Science and Engineering\n" +
            "• Institution: [COLLEGE / UNIVERSITY NAME PLACEHOLDER]"
        );
        teamCard.add(new JScrollPane(teamText), BorderLayout.CENTER);
        gridPanel.add(teamCard);

        // Card 4: Demo Credentials & Security Notice
        JPanel credCard = createCard("Evaluation Accounts & Safe Demo Notice");
        JTextArea credText = createReadOnlyTextArea(
            "Pre-Seeded Demonstration Accounts:\n\n" +
            "• Administrator:   username: admin    | password: Admin@123\n" +
            "  Permissions: Full read/write/update + Incident Deletion + Audit Viewing\n\n" +
            "• Security Analyst: username: analyst  | password: Analyst@123\n" +
            "  Permissions: Read/write incidents + Access Monitoring (Deletion restricted)\n\n" +
            "Notice: In accordance with academic guidelines, all sample telemetry and attack vectors are simulated for educational demonstration."
        );
        credCard.add(new JScrollPane(credText), BorderLayout.CENTER);
        gridPanel.add(credCard);

        add(gridPanel, BorderLayout.CENTER);

        // BOTTOM: Quick Action
        JPanel bottomBar = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        bottomBar.setOpaque(false);
        JLabel noteLabel = new JLabel("CyberShield v2.0-Student-Edition • Local SQLite Persistent Storage");
        noteLabel.setForeground(SwingTheme.TEXT_MUTED);
        noteLabel.setFont(SwingTheme.FONT_SMALL);
        bottomBar.add(noteLabel);
        add(bottomBar, BorderLayout.SOUTH);
    }

    private JPanel createCard(String title) {
        JPanel card = new JPanel(new BorderLayout());
        card.setBackground(SwingTheme.CARD_BG);
        card.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(SwingTheme.BORDER_COLOR),
            title, TitledBorder.LEFT, TitledBorder.TOP,
            SwingTheme.FONT_BOLD, SwingTheme.TEXT_PRIMARY
        ));
        return card;
    }

    private JTextArea createReadOnlyTextArea(String content) {
        JTextArea area = new JTextArea(content);
        area.setBackground(SwingTheme.CARD_BG);
        area.setForeground(SwingTheme.TEXT_PRIMARY);
        area.setFont(SwingTheme.FONT_BODY);
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        return area;
    }
}
