@echo off
setlocal enabledelayedexpansion

:: ============================================================================
:: CYBERSHIELD — MASTER APPLICATION LAUNCHER
:: Cybersecurity Monitoring and Incident Management System
:: 2nd-Year B.Tech CSE Project Evaluation Edition
:: ============================================================================

title CyberShield - Master Launcher
color 0B

:CHECK_JAVA
echo ======================================================================
echo   CYBERSHIELD: Cybersecurity Monitoring & Incident Management System 
echo   Academic B.Tech CSE 2nd-Year Evaluation Launcher
echo ======================================================================
echo.

where java >nul 2>nul
if %errorlevel% neq 0 (
    color 0C
    echo [ERROR] Java is not detected in your PATH environment variable.
    echo Please install Java JDK 17 or higher and ensure 'java' is in PATH.
    echo.
    pause
    exit /b 1
)

:: Check if the runnable fat-jar exists, else build it
if not exist "target\cybershield-1.0.0-jar-with-dependencies.jar" (
    echo [INFO] Application package not found. Building project using Maven...
    where mvn >nul 2>nul
    if %errorlevel% neq 0 (
        color 0C
        echo [ERROR] Maven ('mvn') is not found in PATH to compile the project.
        echo Please ensure Apache Maven is installed or run in an environment with mvn.
        echo.
        pause
        exit /b 1
    )
    call mvn package -DskipTests
    if %errorlevel% neq 0 (
        color 0C
        echo [ERROR] Maven build failed. Please inspect the errors above.
        pause
        exit /b 1
    )
    echo [OK] Project compiled and packaged successfully.
    echo.
)

:MENU
cls
color 0B
echo ======================================================================
echo   CYBERSHIELD: Cybersecurity Monitoring & Incident Management System 
echo   Academic B.Tech CSE 2nd-Year Evaluation Launcher
echo ======================================================================
echo.
echo   Demo Accounts:
echo     [1] Administrator:    admin   / Admin@123   (Full Permissions + Delete)
echo     [2] Security Analyst: analyst / Analyst@123 (Triage + Incident Logging)
echo.
echo   Please select an option:
echo.
echo     [1] START FULL SYSTEM (Backend HTTP Server + Swing Desktop GUI)
echo     [2] Start Web Server Only (http://localhost:8080)
echo     [3] Launch Java Swing Desktop GUI Only
echo     [4] Open Web Application in Default Browser
echo     [5] Rebuild and Package Project (mvn clean package)
echo     [6] Run Automated System Verification Tests
echo     [7] Exit Launcher
echo.
set /p choice="Enter your choice (1-7): "

if "%choice%"=="1" goto START_FULL
if "%choice%"=="2" goto START_SERVER
if "%choice%"=="3" goto START_GUI
if "%choice%"=="4" goto OPEN_BROWSER
if "%choice%"=="5" goto REBUILD
if "%choice%"=="6" goto RUN_TESTS
if "%choice%"=="7" goto EXIT_APP

echo.
echo [!] Invalid selection. Please enter a number between 1 and 7.
timeout /t 2 >nul
goto MENU

:START_FULL
cls
echo ======================================================================
echo   Starting CyberShield Full System...
echo ======================================================================
echo.
echo [1/2] Starting embedded Web & REST API Server in background...
start "CyberShield Web Server" cmd /k "title CyberShield Backend Server && java -jar target\cybershield-1.0.0-jar-with-dependencies.jar --server-only"
timeout /t 3 >nul

echo [2/2] Launching Java Swing Desktop GUI...
start "CyberShield Desktop GUI" java -jar target\cybershield-1.0.0-jar-with-dependencies.jar --gui-only

echo.
echo [OK] Both Server and Desktop GUI have been initiated!
echo  - Web Application: http://localhost:8080/
echo  - Swing Desktop GUI window should now be visible on your screen.
echo.
echo You may keep this launcher window open or press any key to return to menu.
pause
goto MENU

:START_SERVER
cls
echo ======================================================================
echo   Starting CyberShield Embedded Web Server Only...
echo ======================================================================
echo.
echo Access URL: http://localhost:8080/
echo Press Ctrl+C in the server console to stop the server.
echo.
java -jar target\cybershield-1.0.0-jar-with-dependencies.jar --server-only
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Server terminated with error code %errorlevel%.
    pause
)
goto MENU

:START_GUI
cls
echo ======================================================================
echo   Launching CyberShield Java Swing Desktop GUI...
echo ======================================================================
echo.
java -jar target\cybershield-1.0.0-jar-with-dependencies.jar --gui-only
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Swing GUI terminated with error code %errorlevel%.
    pause
)
goto MENU

:OPEN_BROWSER
echo Opening http://localhost:8080 in default web browser...
start http://localhost:8080/
timeout /t 2 >nul
goto MENU

:REBUILD
cls
echo ======================================================================
echo   Rebuilding CyberShield with Maven...
echo ======================================================================
echo.
call mvn clean package -DskipTests
if %errorlevel% equ 0 (
    color 0A
    echo.
    echo [OK] Build successful! Standalone package refreshed.
) else (
    color 0C
    echo.
    echo [ERROR] Maven build failed.
)
pause
goto MENU

:RUN_TESTS
cls
echo ======================================================================
echo   Running Automated Review 2 & System Verification Suite...
echo ======================================================================
echo.
echo [1/3] Running JUnit 5 Automated Intrusion Detection Unit Tests...
call mvn test
echo.
echo [2/3] Running System CRUD & REST API Tests...
powershell -ExecutionPolicy Bypass -File test_system.ps1
echo.
echo [3/3] Running RBAC Role Authorization Tests...
powershell -ExecutionPolicy Bypass -File test_roles.ps1
echo.
pause
goto MENU

:EXIT_APP
echo.
echo Thank you for using CyberShield! Good luck with your project viva!
timeout /t 2 >nul
exit /b 0
