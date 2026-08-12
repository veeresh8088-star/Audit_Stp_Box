@echo off
cd /d "%~dp0"
title AICyberAuditBox - Stop All Services
echo ==================================================
echo   AICyberAuditBox: Stopping All Local Services
echo ==================================================

echo.
echo [1/3] Terminating Python/Uvicorn API server processes...
taskkill /F /IM python.exe /T >nul 2>&1
powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; if ($p -and $p.ProcessName -notlike '*docker*') { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }" >nul 2>&1

echo.
echo [2/3] Terminating llama-server and Ollama LLM processes...
taskkill /F /IM llama-server* /T >nul 2>&1
taskkill /F /IM ollama* /T >nul 2>&1
powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort 11434,11435 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; if ($p -and $p.ProcessName -notlike '*docker*') { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }" >nul 2>&1


echo.
echo [3/3] Stopping Docker Database Container (ShaktiDB)...
docker-compose down >nul 2>&1
docker stop shakthidb_service >nul 2>&1

echo.
echo ==================================================
echo   ✅ All AICyberAuditBox services have been stopped.
echo ==================================================
pause
