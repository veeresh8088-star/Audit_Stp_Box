@echo off
title AISecurityAudit Local API Launcher
echo ==========================================
echo    AISecurityAudit - Local Web Dashboard
echo ==========================================

:: 0. Kill any process already using port 8000 to avoid WinError 10048
echo [0/3] Checking if port 8000 is already in use...
for /f "tokens=5" %%P in ('netstat -ano ^| findstr ":8000 " ^| findstr "LISTENING" 2^>nul') do (
    echo       Found existing process on port 8000 (PID: %%P) - Stopping it...
    taskkill /PID %%P /F >nul 2>&1
)
echo [v] OK: Port 8000 is free.
echo.

:: 1. Check local LLM backend
echo [1/3] Checking Offline LLM Engine...
python -c "import socket; s=socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', 11434))" >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Ollama/llama.cpp LLM server is not detected on port 11434!
    echo           Please start Ollama or run_llamacpp_demo.bat first.
    timeout /t 3 >nul
) else (
    echo [v] OK: Local LLM service is active.
)

:: 2. Check Docker for ShaktiDB
echo.
echo [2/3] Checking Docker Database Service (ShaktiDB)...
set /a retry_count=0

:check_docker
docker ps > nul 2>&1
if %errorlevel% equ 0 goto :docker_success

set /a retry_count+=1
if %retry_count% geq 12 goto :docker_fail

echo [i] Waiting for Docker service to start (Attempt %retry_count%/12)...
timeout /t 5 >nul
goto :check_docker

:docker_success
echo [v] OK: Docker is running. Starting ShaktiDB container...
docker-compose up -d
goto :docker_done

:docker_fail
echo [WARNING] Docker is not running. Continuing without ShaktiDB (SQLite fallback).
goto :docker_done

:docker_done
echo.

:: 3. Launching FastAPI & browser
echo [3/3] Launching AICyberAuditBox Dashboard...

:: Set dynamic concurrency and Redis env vars
:: 2x CPU cores = all 15+ users run simultaneously with NO queue (slight speed tradeoff per user)
set /a MAX_CONCURRENT_AUDITS=%NUMBER_OF_PROCESSORS% * 2
if %MAX_CONCURRENT_AUDITS% LSS 16 set MAX_CONCURRENT_AUDITS=16
set REDIS_URL=redis://127.0.0.1:6379/0

:: Check for Let's Encrypt (Certbot) trusted certificates first
set CERTBOT_CERT=C:\Certbot\live\localauditshakti.centralindia.cloudapp.azure.com\fullchain.pem
set CERTBOT_KEY=C:\Certbot\live\localauditshakti.centralindia.cloudapp.azure.com\privkey.pem

:: FIX: --workers 4 spawns 4 parallel Python processes.
:: 10 simultaneous users are distributed across 4 workers instead of queuing through 1.
:: --reload is incompatible with --workers (removed for production multi-user mode).
if exist "%CERTBOT_CERT%" if exist "%CERTBOT_KEY%" (
    echo [🔒 TRUSTED SSL] Let's Encrypt Certificate detected! Starting HTTPS server...
    start https://localauditshakti.centralindia.cloudapp.azure.com
    python -m uvicorn src.api.main:app --host :: --port 443 --workers 4 --ssl-keyfile "%CERTBOT_KEY%" --ssl-certfile "%CERTBOT_CERT%"
) else if exist cert.pem if exist key.pem (
    echo [🔒 SSL] Self-Signed Certificate detected! Starting HTTPS server...
    start https://localauditshakti.centralindia.cloudapp.azure.com
    python -m uvicorn src.api.main:app --host :: --port 443 --workers 4 --ssl-keyfile key.pem --ssl-certfile cert.pem
) else (
    echo [HTTP] Starting standard HTTP server...
    start http://localauditshakti.centralindia.cloudapp.azure.com
    python -m uvicorn src.api.main:app --host :: --port 80 --workers 4
)
