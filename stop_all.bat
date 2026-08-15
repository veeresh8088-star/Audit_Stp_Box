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
:: -t 30 gives Postgres a real 30s to shut down cleanly (checkpoint + flush)
:: instead of Docker's default ~10s grace period before SIGKILL. Too short a
:: window here -- especially if Postgres was mid-write when this ran, e.g. an
:: audit actively saving findings -- forces WAL crash-recovery on the NEXT
:: start, which is what actually triggered the empty-database incident this
:: was fixed alongside (src/db/database.py's init_db() retry logic protects
:: against that race if it still happens; this reduces how often it can).
docker-compose down -t 30 >nul 2>&1
docker stop -t 30 shakthidb_service >nul 2>&1

echo.
echo ==================================================
echo   ✅ All AICyberAuditBox services have been stopped.
echo ==================================================
pause
