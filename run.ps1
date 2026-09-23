# CYBERSHIELD - PowerShell Runner Script
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "  CYBERSHIELD: SOC Threat Monitoring & Incident Response System" -ForegroundColor White
Write-Host "  Educational AOOP Project - Java 17 + Swing + SQLite" -ForegroundColor Gray
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""

$jarPath = "target\cybershield-1.0.0.jar"
if (Test-Path $jarPath) {
    Write-Host "[INFO] Launching packaged CyberShield executable JAR..." -ForegroundColor Green
    java -jar $jarPath
} else {
    Write-Host "[INFO] JAR not found. Executing via Maven..." -ForegroundColor Yellow
    mvn exec:java
}
