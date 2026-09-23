@echo off
title CYBERSHIELD - Cybersecurity Threat Monitoring & Incident Response System
echo ===================================================================
echo   CYBERSHIELD: SOC Threat Monitoring & Incident Response System
echo   Educational AOOP Project - Java 17 + Swing + SQLite
echo ===================================================================
echo.

if exist "target\cybershield-1.0.0.jar" (
    echo [INFO] Launching packaged CyberShield executable JAR...
    java -jar target\cybershield-1.0.0.jar
) else (
    echo [INFO] JAR not found. Compiling and running with Maven...
    mvn exec:java
)

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Application exited with error code %ERRORLEVEL%.
    pause
)
