@echo off
title AICyberAuditBox Local API Launcher
echo ==========================================
echo    AICyberAuditBox - Local Web Dashboard
echo ==========================================

:: 1. Check local LLM backend
echo [1/3] Checking Offline LLM Engine...
python -c "import socket; s=socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', 11434))" >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Ollama/llama.cpp LLM server is not detected on port 11434!
    echo           Please start Ollama or run_llamacpp_demo.bat first.
    timeout /t 5 >nul
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
echo [ERROR] Docker is not running or Docker Desktop is not detected!
echo         ShaktiDB PostgreSQL is required to run the Master-Slave Database Architecture.
echo         Please start Docker Desktop and run this script again.
exit /b 1

:docker_done
echo.

:: 3. Launching FastAPI & browser
echo [3/3] Launching Local API Dashboard...
start http://127.0.0.1:8000/
python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000
