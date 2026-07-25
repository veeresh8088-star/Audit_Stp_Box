@echo off
TITLE AICyberAuditBox Launcher
COLOR 0A
echo ===================================================
echo   Starting AICyberAuditBox Standalone Engine...
echo ===================================================
echo.
echo [1/2] Launching API Backend & Web Dashboard on http://localhost:8000 ...
start /B "" "AICyberAuditBox.exe"
timeout /t 3 >nul
echo [2/2] Opening Web Dashboard in default browser...
start http://localhost:8000
echo.
echo [OK] System is running! Keep this console window open while auditing.
pause
