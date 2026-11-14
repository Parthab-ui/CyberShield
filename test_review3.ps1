# =====================================================================
# CYBERSHIELD REVIEW 3: FULL SYSTEM REGRESSION & INTEGRATION SUITE
# =====================================================================
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  CYBERSHIELD REVIEW 3: FULL-STACK SOC INTEGRATION & REGRESSION TEST  " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$baseUrl = "http://localhost:8080"
$ErrorActionPreference = "Stop"

# Helper function for pretty printing
function Assert-Step([string]$step, [bool]$condition, [string]$msg) {
    if ($condition) {
        Write-Host "  [PASS] $step - $msg" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] $step - $msg" -ForegroundColor Red
        throw "Assertion failed for step: $step"
    }
}

# ---------------------------------------------------------------------
# 1. VERIFY STATIC SOC ASSETS
# ---------------------------------------------------------------------
Write-Host "`n[1/7] Verifying Web SOC Console Assets & Resources..." -ForegroundColor Yellow
$html = Invoke-WebRequest -Uri "$baseUrl/" -UseBasicParsing
$css = Invoke-WebRequest -Uri "$baseUrl/css/style.css" -UseBasicParsing
$js = Invoke-WebRequest -Uri "$baseUrl/js/app.js" -UseBasicParsing

Assert-Step "1.1" ($html.StatusCode -eq 200 -and $html.Content.Length -gt 15000) "index.html delivered ($($html.Content.Length) bytes)"
Assert-Step "1.2" ($css.StatusCode -eq 200 -and $css.Content.Length -gt 10000) "style.css delivered ($($css.Content.Length) bytes)"
Assert-Step "1.3" ($js.StatusCode -eq 200 -and $js.Content.Length -gt 20000) "app.js delivered ($($js.Content.Length) bytes)"

# ---------------------------------------------------------------------
# 2. VERIFY AUTHENTICATION & RBAC GATING
# ---------------------------------------------------------------------
Write-Host "`n[2/7] Verifying Authentication & Role-Based Access Control (RBAC)..." -ForegroundColor Yellow

$adminLogin = '{"username":"admin","password":"Admin@123"}'
$adminRes = Invoke-RestMethod -Uri "$baseUrl/api/auth/login" -Method Post -Body $adminLogin -ContentType "application/json"
$adminToken = $adminRes.token
$adminHeaders = @{ "Authorization" = "Bearer $adminToken" }
Assert-Step "2.1" ($adminRes.success -and $adminRes.user.role -eq "ADMIN") "Admin logged in successfully with ADMIN role"

$analystLogin = '{"username":"analyst","password":"Analyst@123"}'
$analystRes = Invoke-RestMethod -Uri "$baseUrl/api/auth/login" -Method Post -Body $analystLogin -ContentType "application/json"
$analystToken = $analystRes.token
$analystHeaders = @{ "Authorization" = "Bearer $analystToken" }
Assert-Step "2.2" ($analystRes.success -and $analystRes.user.role -eq "ANALYST") "Analyst logged in successfully with ANALYST role"

# ---------------------------------------------------------------------
# 3. VERIFY APPLICATION-LEVEL FIREWALL & IP BLOCKING ENGINE
# ---------------------------------------------------------------------
Write-Host "`n[3/7] Testing IP Blocking & Firewall Engine..." -ForegroundColor Yellow

# 3.1 Analyst attempts to block IP (Must fail 403)
$forbidden = $false
try {
    $body = '{"ip":"198.51.100.88","reason":"Unauthorized probe","durationMinutes":30}'
    Invoke-RestMethod -Uri "$baseUrl/api/firewall/block" -Method Post -Headers $analystHeaders -Body $body -ContentType "application/json"
} catch {
    if ($_.Exception.Response.StatusCode.value__ -eq 403) { $forbidden = $true }
}
Assert-Step "3.1" $forbidden "Analyst blocked from executing firewall IP block (HTTP 403 Forbidden)"

# 3.2 Admin blocks IP successfully
$blockBody = '{"ip":"198.51.100.88","reason":"Automated intrusion containment","durationMinutes":60}'
$blockRes = Invoke-RestMethod -Uri "$baseUrl/api/firewall/block" -Method Post -Headers $adminHeaders -Body $blockBody -ContentType "application/json"
Assert-Step "3.2" ($blockRes.success -and $blockRes.blockedIp.status -eq "ACTIVE") "Admin blocked IP 198.51.100.88 (60 mins)"

# 3.3 Verify blocked IP is rejected on login
$blockedLogin = $false
try {
    $loginFromBlocked = '{"username":"admin","password":"Admin@123","clientIp":"198.51.100.88"}'
    Invoke-RestMethod -Uri "$baseUrl/api/auth/login" -Method Post -Body $loginFromBlocked -ContentType "application/json"
} catch {
    if ($_.Exception.Response.StatusCode.value__ -eq 403) { $blockedLogin = $true }
}
Assert-Step "3.3" $blockedLogin "Login attempt from blocked IP 198.51.100.88 rejected before password evaluation (HTTP 403)"

# 3.4 Admin unblocks IP
$unblockBody = '{"ip":"198.51.100.88"}'
$unblockRes = Invoke-RestMethod -Uri "$baseUrl/api/firewall/unblock" -Method Post -Headers $adminHeaders -Body $unblockBody -ContentType "application/json"
Assert-Step "3.4" $unblockRes.success "Admin unblocked IP 198.51.100.88 successfully"

# ---------------------------------------------------------------------
# 4. VERIFY TEMPORARY ACCOUNT LOCKOUT & CREDENTIAL SECURITY
# ---------------------------------------------------------------------
Write-Host "`n[4/7] Testing Account Lockout & Credential Defense..." -ForegroundColor Yellow

# Ensure standard_user starts unlocked
try {
    $preUnlock = '{"username":"standard_user"}'
    Invoke-RestMethod -Uri "$baseUrl/api/auth/unlock" -Method Post -Headers $adminHeaders -Body $preUnlock -ContentType "application/json" | Out-Null
} catch {}

# 4.1 Trigger 5 failed logins on test target user 'standard_user'
for ($i = 1; $i -le 5; $i++) {
    try {
        $badAuth = "{`"username`":`"standard_user`",`"password`":`"BadPass$i`"}"
        Invoke-RestMethod -Uri "$baseUrl/api/auth/login" -Method Post -Body $badAuth -ContentType "application/json"
    } catch {
        # Expected failure
    }
}

# 4.2 Query locked accounts as Admin
$lockedAccounts = Invoke-RestMethod -Uri "$baseUrl/api/auth/locked-accounts" -Method Get -Headers $adminHeaders
$isUserLocked = $false
foreach ($acc in $lockedAccounts) {
    if ($acc.username -eq "standard_user" -and ($acc.locked -or $acc.isLocked)) {
        $isUserLocked = $true
    }
}
Assert-Step "4.1" $isUserLocked "Account 'standard_user' is locked after 5 failed password attempts"

# 4.3 Verify 6th login is rejected as locked
$lockRejected = $false
try {
    $attemptOnLocked = '{"username":"standard_user","password":"User@123"}'
    Invoke-RestMethod -Uri "$baseUrl/api/auth/login" -Method Post -Body $attemptOnLocked -ContentType "application/json"
} catch {
    if ($_.Exception.Response.StatusCode.value__ -eq 423 -or $_.Exception.Response.StatusCode.value__ -eq 401) {
        $lockRejected = $true
    }
}
Assert-Step "4.2" $lockRejected "Login attempt on locked account rejected without credential evaluation"

# 4.4 Admin unlocks account
$unlockBody = '{"username":"standard_user"}'
$unlockRes = Invoke-RestMethod -Uri "$baseUrl/api/auth/unlock" -Method Post -Headers $adminHeaders -Body $unlockBody -ContentType "application/json"
Assert-Step "4.3" $unlockRes.success "Admin unlocked account 'standard_user' and reset attempt counter"

# ---------------------------------------------------------------------
# 5. VERIFY AUTOMATED THREAT RESPONSE & IDS INTEGRATION
# ---------------------------------------------------------------------
Write-Host "`n[5/7] Testing Automated Threat Response & IDS Integration..." -ForegroundColor Yellow

$randHost = Get-Random -Minimum 30 -Maximum 240
$attackerIp = "198.51.100.$randHost"

for ($i = 1; $i -le 5; $i++) {
    try {
        $badAuth = "{`"username`":`"target_probe`",`"password`":`"WrongPass$i`",`"clientIp`":`"$attackerIp`"}"
        Invoke-RestMethod -Uri "$baseUrl/api/auth/login" -Method Post -Body $badAuth -ContentType "application/json"
    } catch {
        # Expected failure
    }
}

# Query threat responses for this IP
$responses = Invoke-RestMethod -Uri "$baseUrl/api/threat-responses?targetIp=$attackerIp" -Method Get -Headers $adminHeaders
Assert-Step "5.1" ($responses.Count -ge 1) "Automated Threat Response logged for attacker IP $attackerIp"

$firstResponse = $responses[0]
Assert-Step "5.2" (($firstResponse.actionTaken -eq "AUTO_BLOCK_IP" -or $firstResponse.actionTaken -eq "APPLICATION_IP_BLOCK") -and $firstResponse.status -eq "EXECUTED") "Action taken was AUTO_BLOCK_IP with status EXECUTED"
$autoIncidentId = $firstResponse.incidentId
Assert-Step "5.3" ($autoIncidentId -ne $null -and $autoIncidentId -gt 0) "Autonomous threat response linked to Incident #$autoIncidentId"

# Check threat stats
$stats = Invoke-RestMethod -Uri "$baseUrl/api/threat-responses/stats" -Method Get -Headers $adminHeaders
Assert-Step "5.4" ($stats.totalResponses -gt 0 -and $stats.successfulBlocks -gt 0) "Threat response metrics reporting active autonomous defenses"

# ---------------------------------------------------------------------
# 6. VERIFY ADVANCED FORENSIC INVESTIGATION & TRIAGE SYSTEM
# ---------------------------------------------------------------------
Write-Host "`n[6/7] Testing Forensic Investigation, Evidence Archival & Resolution..." -ForegroundColor Yellow

# 6.1 Query assignable investigators
$investigators = Invoke-RestMethod -Uri "$baseUrl/api/investigators" -Method Get -Headers $analystHeaders
Assert-Step "6.1" ($investigators.Count -ge 2) "Assignable investigators directory retrieved with sanitized users"

# 6.2 Admin assigns incident to analyst
$assignBody = '{"assignedAnalyst":"analyst"}'
$assignRes = Invoke-RestMethod -Uri "$baseUrl/api/incidents/$autoIncidentId/assign" -Method Post -Headers $adminHeaders -Body $assignBody -ContentType "application/json"
Assert-Step "6.2" ($assignRes.incident.assignedTo -eq "analyst" -or $assignRes.incident.assignedAnalyst -eq "analyst") "Case #$autoIncidentId assigned to 'analyst'"

# 6.3 Analyst adds forensic note with structured JSON evidence
$noteBody = '{
    "notes": "Triage identified automated credential stuffing botnet signature.",
    "evidenceData": "{\"signature\":\"T1110.001\",\"source_ip\":\"' + $attackerIp + '\",\"burst_rate\":\"5 req / 2s\",\"tool\":\"Hydra/v9.3\"}"
}'
$noteRes = Invoke-RestMethod -Uri "$baseUrl/api/incidents/$autoIncidentId/investigations" -Method Post -Headers $analystHeaders -Body $noteBody -ContentType "application/json"
Assert-Step "6.3" ($noteRes.analystUsername -eq "analyst" -and $noteRes.evidenceData -ne $null) "Forensic note with structured JSON evidence archived"

# 6.4 Analyst records Root Cause Analysis
$rcBody = '{"category":"BRUTE_FORCE","explanation":"Distributed dictionary attack against administrative console"}'
$rcRes = Invoke-RestMethod -Uri "$baseUrl/api/incidents/$autoIncidentId/root-cause" -Method Post -Headers $analystHeaders -Body $rcBody -ContentType "application/json"
Assert-Step "6.4" ($rcRes.incident.rootCauseCategory -eq "BRUTE_FORCE" -and $rcRes.incident.status -eq "INVESTIGATING") "Root cause classified as BRUTE_FORCE and status moved to INVESTIGATING"

# 6.5 Verify unified chronological timeline
$timeline = Invoke-RestMethod -Uri "$baseUrl/api/incidents/$autoIncidentId/timeline" -Method Get -Headers $analystHeaders
Assert-Step "6.5" ($timeline.Count -ge 4) "Chronological timeline reconstructed ($($timeline.Count) case milestones)"

# 6.6 Analyst resolves incident
$resBody = '{"resolutionSummary":"IP blocked at application firewall, root cause documented, credential stuffing contained."}'
$resSuccess = Invoke-RestMethod -Uri "$baseUrl/api/incidents/$autoIncidentId/resolve" -Method Post -Headers $analystHeaders -Body $resBody -ContentType "application/json"
Assert-Step "6.6" ($resSuccess.success) "Incident #$autoIncidentId marked RESOLVED"

# 6.7 Inspect complete case dossier summary
$summary = Invoke-RestMethod -Uri "$baseUrl/api/incidents/$autoIncidentId/investigation-summary" -Method Get -Headers $analystHeaders
Assert-Step "6.7" ($summary.status -eq "RESOLVED" -and $summary.rootCauseCategory -eq "BRUTE_FORCE" -and ($summary.totalInvestigationNotes -ge 1 -or $summary.totalNotes -ge 1)) "Case dossier verified with structured forensic summary"

# ---------------------------------------------------------------------
# 7. VERIFY DASHBOARD REVIEW 3 METRICS INTEGRATION
# ---------------------------------------------------------------------
Write-Host "`n[7/7] Testing SOC Dashboard Review 3 KPI Metrics..." -ForegroundColor Yellow
$dashStats = Invoke-RestMethod -Uri "$baseUrl/api/dashboard/stats" -Method Get -Headers $adminHeaders
Assert-Step "7.1" ($dashStats.activeBlockedIps -ne $null) "Dashboard telemetry provides activeBlockedIps metric ($($dashStats.activeBlockedIps))"
Assert-Step "7.2" ($dashStats.lockedAccounts -ne $null) "Dashboard telemetry provides lockedAccounts metric ($($dashStats.lockedAccounts))"
Assert-Step "7.3" ($dashStats.successfulThreatResponses -ne $null) "Dashboard telemetry provides successfulThreatResponses metric ($($dashStats.successfulThreatResponses))"
Assert-Step "7.4" ($dashStats.failedThreatResponses -ne $null) "Dashboard telemetry provides failedThreatResponses metric ($($dashStats.failedThreatResponses))"

Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host "  >>> ALL 25+ REVIEW 3 INTEGRATION & REGRESSION TESTS PASSED! <<<     " -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Cyan
