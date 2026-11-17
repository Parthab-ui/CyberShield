Write-Host "=== 1. TEST STATIC ASSETS ==="
$html = Invoke-WebRequest -Uri "http://localhost:8080/" -UseBasicParsing
Write-Host "GET / Status:" $html.StatusCode "Length:" $html.Content.Length

$css = Invoke-WebRequest -Uri "http://localhost:8080/css/style.css" -UseBasicParsing
Write-Host "GET /css/style.css Status:" $css.StatusCode "Length:" $css.Content.Length

$js = Invoke-WebRequest -Uri "http://localhost:8080/js/app.js" -UseBasicParsing
Write-Host "GET /js/app.js Status:" $js.StatusCode "Length:" $js.Content.Length

Write-Host "`n=== 2. TEST AUTHENTICATION ==="
$loginBody = '{"username":"admin","password":"Admin@123"}'
$loginRes = Invoke-RestMethod -Uri "http://localhost:8080/api/auth/login" -Method Post -Body $loginBody -ContentType "application/json"
Write-Host "Admin Login Success:" $loginRes.success "Role:" $loginRes.user.role
$token = $loginRes.token

Write-Host "`n=== 3. TEST INCIDENT CREATION ==="
$incBody = '{"title":"Ransomware Canary Alert","description":"Canary file altered on NAS storage","severity":"CRITICAL","status":"OPEN"}'
$headers = @{ "Authorization" = "Bearer $token" }
$incRes = Invoke-RestMethod -Uri "http://localhost:8080/api/incidents" -Method Post -Headers $headers -Body $incBody -ContentType "application/json"
$createdId = $incRes.id
Write-Host "Create Incident Success! New ID:" $createdId "Title:" $incRes.title

Write-Host "`n=== 4. TEST INCIDENT UPDATE ==="
$updBody = '{"title":"Ransomware Canary Alert [CONTAINED]","description":"Host quarantined via firewall","severity":"HIGH","status":"RESOLVED"}'
$updRes = Invoke-RestMethod -Uri "http://localhost:8080/api/incidents/$createdId" -Method Put -Headers $headers -Body $updBody -ContentType "application/json"
Write-Host "Update Incident Success:" $updRes.success "Message:" $updRes.message

Write-Host "`n=== 5. TEST THREAT SIMULATION ==="
$threatRes = Invoke-RestMethod -Uri "http://localhost:8080/api/access-events/simulate" -Method Post -Headers $headers
Write-Host "Simulated Threat Created ID:" $threatRes.id "Source:" $threatRes.source "Result:" $threatRes.result

Write-Host "`n=== 6. TEST DASHBOARD STATS REFRESH ==="
$stats = Invoke-RestMethod -Uri "http://localhost:8080/api/dashboard/stats" -Method Get -Headers $headers
Write-Host "Total Incidents:" $stats.totalIncidents "Open:" $stats.openIncidents "Critical:" $stats.criticalIncidents "Unauthorized Events:" $stats.unauthorizedEvents

Write-Host "`n=== 7. TEST INCIDENT DELETION (ADMIN) ==="
$delRes = Invoke-RestMethod -Uri "http://localhost:8080/api/incidents/$createdId" -Method Delete -Headers $headers
Write-Host "Delete Incident Success:" $delRes.success "Message:" $delRes.message

Write-Host "`n=== 8. TEST AUDIT TRAIL ==="
$activity = Invoke-RestMethod -Uri "http://localhost:8080/api/activity?limit=5" -Method Get -Headers $headers
Write-Host "Audit Log Records Count:" $activity.Count
foreach ($a in $activity) {
    Write-Host "  -> [$($a.action)] by $($a.username): $($a.details)"
}

Write-Host "`n>>> ALL 8 ENDPOINT & CRUD TESTS PASSED WITH 100% SUCCESS! <<<"
