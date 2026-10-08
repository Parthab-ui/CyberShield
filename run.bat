@echo off
cd /d "%~dp0"
title CyberShield - Threat Monitoring ^& Incident Response
echo ===================================================
echo   Starting CyberShield (Zero-Setup Mode)
echo ===================================================
java -cp "out;lib/*" cybershield.Main
pause

