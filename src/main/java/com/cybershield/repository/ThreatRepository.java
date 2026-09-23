package com.cybershield.repository;

import com.cybershield.exception.DatabaseOperationException;
import com.cybershield.model.BruteForceThreat;
import com.cybershield.model.MalwareThreat;
import com.cybershield.model.PhishingThreat;
import com.cybershield.model.SuspiciousLoginThreat;
import com.cybershield.model.Threat;
import com.cybershield.model.enums.Severity;
import com.cybershield.model.enums.ThreatStatus;
import com.cybershield.model.enums.ThreatType;
import com.cybershield.util.DateTimeUtils;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Repository for managing Threat polymorphic entities in SQLite.
 * Demonstrates Polymorphic Object-Relational Mapping without third-party ORMs.
 */
public class ThreatRepository {

    private final DatabaseManager databaseManager;

    public ThreatRepository() {
        this.databaseManager = DatabaseManager.getInstance();
    }

    public ThreatRepository(DatabaseManager databaseManager) {
        this.databaseManager = databaseManager;
    }

    public Threat save(Threat threat) throws DatabaseOperationException {
        String sql = """
            INSERT INTO threats (
                threat_id, threat_type, severity, status, source_ip, target_asset, detected_at, description,
                failed_attempts, window_duration, sender_email, suspicious_url, keyword_hits,
                file_hash, file_path, quarantined_flag, geo_anomaly, unusual_hour, device_fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """;

        try (Connection conn = databaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {

            pstmt.setString(1, threat.getThreatId());
            pstmt.setString(2, threat.getThreatType().name());
            pstmt.setString(3, threat.getSeverity().name());
            pstmt.setString(4, threat.getStatus().name());
            pstmt.setString(5, threat.getSourceIp());
            pstmt.setString(6, threat.getTargetAsset());
            pstmt.setString(7, DateTimeUtils.format(threat.getDetectedAt()));
            pstmt.setString(8, threat.getDescription());

            // Polymorphic extraction of subclass-specific attributes
            if (threat instanceof BruteForceThreat bf) {
                pstmt.setInt(9, bf.getFailedAttempts());
                pstmt.setInt(10, bf.getWindowDurationSeconds());
                pstmt.setString(11, null);
                pstmt.setString(12, null);
                pstmt.setString(13, null);
                pstmt.setString(14, null);
                pstmt.setString(15, null);
                pstmt.setInt(16, 0);
                pstmt.setInt(17, 0);
                pstmt.setInt(18, 0);
                pstmt.setString(19, null);
            } else if (threat instanceof PhishingThreat ph) {
                pstmt.setInt(9, 0);
                pstmt.setInt(10, 0);
                pstmt.setString(11, ph.getSenderEmail());
                pstmt.setString(12, ph.getSuspiciousUrl());
                pstmt.setString(13, String.join(",", ph.getKeywordHits()));
                pstmt.setString(14, null);
                pstmt.setString(15, null);
                pstmt.setInt(16, 0);
                pstmt.setInt(17, 0);
                pstmt.setInt(18, 0);
                pstmt.setString(19, null);
            } else if (threat instanceof MalwareThreat mw) {
                pstmt.setInt(9, 0);
                pstmt.setInt(10, 0);
                pstmt.setString(11, null);
                pstmt.setString(12, null);
                pstmt.setString(13, null);
                pstmt.setString(14, mw.getFileHash());
                pstmt.setString(15, mw.getFilePath());
                pstmt.setInt(16, mw.isQuarantinedFlag() ? 1 : 0);
                pstmt.setInt(17, 0);
                pstmt.setInt(18, 0);
                pstmt.setString(19, null);
            } else if (threat instanceof SuspiciousLoginThreat sl) {
                pstmt.setInt(9, 0);
                pstmt.setInt(10, 0);
                pstmt.setString(11, null);
                pstmt.setString(12, null);
                pstmt.setString(13, null);
                pstmt.setString(14, null);
                pstmt.setString(15, null);
                pstmt.setInt(16, 0);
                pstmt.setInt(17, sl.isGeoAnomaly() ? 1 : 0);
                pstmt.setInt(18, sl.isUnusualHour() ? 1 : 0);
                pstmt.setString(19, sl.getDeviceFingerprint());
            } else {
                pstmt.setInt(9, 0);
                pstmt.setInt(10, 0);
                pstmt.setString(11, null);
                pstmt.setString(12, null);
                pstmt.setString(13, null);
                pstmt.setString(14, null);
                pstmt.setString(15, null);
                pstmt.setInt(16, 0);
                pstmt.setInt(17, 0);
                pstmt.setInt(18, 0);
                pstmt.setString(19, null);
            }

            int affected = pstmt.executeUpdate();
            if (affected > 0) {
                try (ResultSet keys = pstmt.getGeneratedKeys()) {
                    if (keys.next()) {
                        threat.setId(keys.getInt(1));
                    }
                }
            }
            return threat;
        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to save threat: " + threat.getThreatId(), e);
        }
    }

    public void updateStatus(String threatId, ThreatStatus status) throws DatabaseOperationException {
        String sql = "UPDATE threats SET status = ? WHERE threat_id = ?";
        try (Connection conn = databaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, status.name());
            pstmt.setString(2, threatId);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to update status for threat: " + threatId, e);
        }
    }

    public Threat findById(String threatId) throws DatabaseOperationException {
        String sql = "SELECT * FROM threats WHERE threat_id = ?";
        try (Connection conn = databaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, threatId);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return mapRowToThreat(rs);
                }
            }
            return null;
        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to find threat by ID: " + threatId, e);
        }
    }

    public List<Threat> findAll() throws DatabaseOperationException {
        List<Threat> list = new ArrayList<>();
        String sql = "SELECT * FROM threats ORDER BY id DESC";
        try (Connection conn = databaseManager.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                list.add(mapRowToThreat(rs));
            }
            return list;
        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to query all threats", e);
        }
    }

    public int count() throws DatabaseOperationException {
        String sql = "SELECT COUNT(*) FROM threats";
        try (Connection conn = databaseManager.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            if (rs.next()) {
                return rs.getInt(1);
            }
            return 0;
        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to count threats", e);
        }
    }

    public int countHighOrCritical() throws DatabaseOperationException {
        String sql = "SELECT COUNT(*) FROM threats WHERE severity IN ('HIGH', 'CRITICAL')";
        try (Connection conn = databaseManager.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            if (rs.next()) {
                return rs.getInt(1);
            }
            return 0;
        } catch (SQLException e) {
            throw new DatabaseOperationException("Failed to count high/critical threats", e);
        }
    }

    /**
     * Polymorphic Factory method reconstructing the exact Threat subclass from SQLite.
     */
    private Threat mapRowToThreat(ResultSet rs) throws SQLException {
        String threatId = rs.getString("threat_id");
        ThreatType type = ThreatType.fromString(rs.getString("threat_type"));
        String sourceIp = rs.getString("source_ip");
        String targetAsset = rs.getString("target_asset");
        String description = rs.getString("description");
        Severity severity = Severity.fromString(rs.getString("severity"));
        ThreatStatus status = ThreatStatus.fromString(rs.getString("status"));
        String detectedAt = rs.getString("detected_at");

        Threat threat;

        switch (type) {
            case BRUTE_FORCE -> {
                int attempts = rs.getInt("failed_attempts");
                int window = rs.getInt("window_duration");
                threat = new BruteForceThreat(threatId, sourceIp, targetAsset, attempts, window, description);
            }
            case PHISHING -> {
                String sender = rs.getString("sender_email");
                String url = rs.getString("suspicious_url");
                String hits = rs.getString("keyword_hits");
                List<String> keywords = (hits != null && !hits.isEmpty()) ? Arrays.asList(hits.split(",")) : new ArrayList<>();
                threat = new PhishingThreat(threatId, sourceIp, targetAsset, sender, url, keywords, description);
            }
            case MALWARE -> {
                String hash = rs.getString("file_hash");
                String path = rs.getString("file_path");
                boolean quarantined = rs.getInt("quarantined_flag") == 1;
                MalwareThreat mw = new MalwareThreat(threatId, sourceIp, targetAsset, hash, path, description);
                mw.setQuarantinedFlag(quarantined);
                threat = mw;
            }
            case SUSPICIOUS_LOGIN -> {
                boolean geo = rs.getInt("geo_anomaly") == 1;
                boolean unusual = rs.getInt("unusual_hour") == 1;
                String device = rs.getString("device_fingerprint");
                threat = new SuspiciousLoginThreat(threatId, sourceIp, targetAsset, geo, unusual, device, description);
            }
            default -> threat = new BruteForceThreat(threatId, sourceIp, targetAsset, 5, 30, description);
        }

        threat.setId(rs.getInt("id"));
        threat.setSeverity(severity);
        threat.setStatus(status);
        threat.setDetectedAt(DateTimeUtils.parse(detectedAt));

        return threat;
    }
}
