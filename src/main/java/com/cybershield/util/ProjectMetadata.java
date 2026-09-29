package com.cybershield.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;

/**
 * Manages project title, team members details, and college review metadata.
 * Persists changes to data/project_team.properties so edits made in the GUI are preserved.
 */
public class ProjectMetadata {

    private static final String CONFIG_FILE_PATH = "data/project_team.properties";

    private static String projectTitle = "CYBERSHIELD — Cybersecurity Threat Monitoring & Incident Response System";
    private static String courseName = "Advanced Object-Oriented Programming (AOOP) - Java";
    private static String reviewDate = "October 1st, 2026 (First Review - GUI & Front-End)";
    private static String department = "Department of Computer Science & Engineering";

    // Team Member 1 (Lead & Database Layer)
    private static String member1Name = "Parthab Sarkar";
    private static String member1Roll = "23BCSE0101"; // Default customizable roll number
    private static String member1Role = "Team Lead | Database Layer & Core Framework (SQLite, JDBC, Repositories, Exceptions)";

    // Team Member 2 (Detection & Heuristic Simulation)
    private static String member2Name = "Team Member 2";
    private static String member2Roll = "23BCSE0102";
    private static String member2Role = "Detection Lead | Threat Hierarchy, Heuristic Detection Engine & Attack Simulator";

    // Team Member 3 (UI & Incident Workflows)
    private static String member3Name = "Team Member 3";
    private static String member3Roll = "23BCSE0103";
    private static String member3Role = "UI & Incident Lead | Java Swing GUI Architecture, Component Integration & Incident Management";

    static {
        loadProperties();
    }

    public static synchronized void loadProperties() {
        File file = new File(CONFIG_FILE_PATH);
        if (!file.exists()) {
            saveProperties(); // Create default file
            return;
        }

        Properties props = new Properties();
        try (FileInputStream in = new FileInputStream(file)) {
            props.load(in);
            projectTitle = props.getProperty("project.title", projectTitle);
            courseName = props.getProperty("project.course", courseName);
            reviewDate = props.getProperty("project.reviewDate", reviewDate);
            department = props.getProperty("project.department", department);

            member1Name = props.getProperty("member1.name", member1Name);
            member1Roll = props.getProperty("member1.roll", member1Roll);
            member1Role = props.getProperty("member1.role", member1Role);

            member2Name = props.getProperty("member2.name", member2Name);
            member2Roll = props.getProperty("member2.roll", member2Roll);
            member2Role = props.getProperty("member2.role", member2Role);

            member3Name = props.getProperty("member3.name", member3Name);
            member3Roll = props.getProperty("member3.roll", member3Roll);
            member3Role = props.getProperty("member3.role", member3Role);
        } catch (IOException e) {
            System.err.println("Could not load project_team.properties: " + e.getMessage());
        }
    }

    public static synchronized void saveProperties() {
        File dir = new File("data");
        if (!dir.exists()) {
            dir.mkdirs();
        }

        Properties props = new Properties();
        props.setProperty("project.title", projectTitle);
        props.setProperty("project.course", courseName);
        props.setProperty("project.reviewDate", reviewDate);
        props.setProperty("project.department", department);

        props.setProperty("member1.name", member1Name);
        props.setProperty("member1.roll", member1Roll);
        props.setProperty("member1.role", member1Role);

        props.setProperty("member2.name", member2Name);
        props.setProperty("member2.roll", member2Roll);
        props.setProperty("member2.role", member2Role);

        props.setProperty("member3.name", member3Name);
        props.setProperty("member3.roll", member3Roll);
        props.setProperty("member3.role", member3Role);

        try (FileOutputStream out = new FileOutputStream(CONFIG_FILE_PATH)) {
            props.store(out, "CYBERSHIELD Team & Project Metadata for Review Evaluation");
        } catch (IOException e) {
            System.err.println("Could not save project_team.properties: " + e.getMessage());
        }
    }

    public static synchronized void updateDetails(String title, String course, String dept,
                                                  String m1Name, String m1Roll, String m1Role,
                                                  String m2Name, String m2Roll, String m2Role,
                                                  String m3Name, String m3Roll, String m3Role) {
        projectTitle = title;
        courseName = course;
        department = dept;

        member1Name = m1Name;
        member1Roll = m1Roll;
        member1Role = m1Role;

        member2Name = m2Name;
        member2Roll = m2Roll;
        member2Role = m2Role;

        member3Name = m3Name;
        member3Roll = m3Roll;
        member3Role = m3Role;

        saveProperties();
    }

    // Getters
    public static String getProjectTitle() { return projectTitle; }
    public static String getCourseName() { return courseName; }
    public static String getReviewDate() { return reviewDate; }
    public static String getDepartment() { return department; }

    public static String getMember1Name() { return member1Name; }
    public static String getMember1Roll() { return member1Roll; }
    public static String getMember1Role() { return member1Role; }

    public static String getMember2Name() { return member2Name; }
    public static String getMember2Roll() { return member2Roll; }
    public static String getMember2Role() { return member2Role; }

    public static String getMember3Name() { return member3Name; }
    public static String getMember3Roll() { return member3Roll; }
    public static String getMember3Role() { return member3Role; }
}
