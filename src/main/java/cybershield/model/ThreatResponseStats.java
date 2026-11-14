package cybershield.model;

/**
 * ThreatResponseStats — Aggregated metrics regarding automated and manual threat mitigation actions.
 * Used for dashboard presentation, forensic review, and compliance auditing.
 */
public class ThreatResponseStats {

    private int totalResponses;
    private int successfulBlocks;
    private int failedResponses;
    private int skippedResponses;
    private int alreadyActive;
    private int activeBlockedIps;

    public ThreatResponseStats() {
    }

    public ThreatResponseStats(int totalResponses, int successfulBlocks, int failedResponses,
                               int skippedResponses, int alreadyActive, int activeBlockedIps) {
        this.totalResponses = totalResponses;
        this.successfulBlocks = successfulBlocks;
        this.failedResponses = failedResponses;
        this.skippedResponses = skippedResponses;
        this.alreadyActive = alreadyActive;
        this.activeBlockedIps = activeBlockedIps;
    }

    public int getTotalResponses() {
        return totalResponses;
    }

    public void setTotalResponses(int totalResponses) {
        this.totalResponses = totalResponses;
    }

    public int getSuccessfulBlocks() {
        return successfulBlocks;
    }

    public void setSuccessfulBlocks(int successfulBlocks) {
        this.successfulBlocks = successfulBlocks;
    }

    public int getFailedResponses() {
        return failedResponses;
    }

    public void setFailedResponses(int failedResponses) {
        this.failedResponses = failedResponses;
    }

    public int getSkippedResponses() {
        return skippedResponses;
    }

    public void setSkippedResponses(int skippedResponses) {
        this.skippedResponses = skippedResponses;
    }

    public int getAlreadyActive() {
        return alreadyActive;
    }

    public void setAlreadyActive(int alreadyActive) {
        this.alreadyActive = alreadyActive;
    }

    public int getActiveBlockedIps() {
        return activeBlockedIps;
    }

    public void setActiveBlockedIps(int activeBlockedIps) {
        this.activeBlockedIps = activeBlockedIps;
    }

    @Override
    public String toString() {
        return "ThreatResponseStats{" +
                "totalResponses=" + totalResponses +
                ", successfulBlocks=" + successfulBlocks +
                ", failedResponses=" + failedResponses +
                ", skippedResponses=" + skippedResponses +
                ", alreadyActive=" + alreadyActive +
                ", activeBlockedIps=" + activeBlockedIps +
                '}';
    }
}
