@echo off
cd /d "%~dp0"
set "PYTHONPATH=%~dp0;%PYTHONPATH%"
title AISecurityAudit - Start All Local Services
echo ==================================================
echo   AISecurityAudit: Unified Single-Click Launcher
echo ==================================================

echo.
echo [1/5] Stopping any existing backend server instances...
taskkill /F /IM ollama* /T >nul 2>&1
taskkill /F /IM llama-server* /T >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :11434 ^| findstr LISTENING') do taskkill /F /PID %%a >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :11435 ^| findstr LISTENING') do taskkill /F /PID %%a >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8000 ^| findstr LISTENING') do taskkill /F /PID %%a >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :443 ^| findstr LISTENING') do taskkill /F /PID %%a >nul 2>&1
echo [v] Ports 8000 ^& 443 cleared.

:: Ensure SSL Certificate Exists
if not exist cert.pem (
    echo [SSL] Generating local SSL Certificate...
    python generate_self_ssl.py
)

:: Locate llama-server.exe
set "LLAMA_SERVER_EXE="
if exist "C:\Users\veeresh988V\Desktop\llama\llama-server.exe" (
    set "LLAMA_SERVER_EXE=C:\Users\veeresh988V\Desktop\llama\llama-server.exe"
) else if exist "C:\Users\HP\Downloads\llama,,ccppp mode\llama-server.exe" (
    set "LLAMA_SERVER_EXE=C:\Users\HP\Downloads\llama,,ccppp mode\llama-server.exe"
) else (
    set "LLAMA_SERVER_EXE=%~dp0llama-server.exe"
)

:: Calculate full CPU thread distribution for max performance
set /a LLM_THREADS=%NUMBER_OF_PROCESSORS%
if %LLM_THREADS% LSS 1 set LLM_THREADS=4

set /a EMBED_THREADS=%NUMBER_OF_PROCESSORS%
if %EMBED_THREADS% LSS 1 set EMBED_THREADS=4

:: Calculate parallel LLM slots for C++ continuous batching.
:: Set to 2x CPU cores so 15+ users run simultaneously with NO queue.
:: Tradeoff: each auditor runs at ~50% speed instead of 100%, but ZERO queueing.
:: RAM cost: each extra slot = ~200MB KV cache. Adjust multiplier if RAM is low.
set /a LLM_SLOTS=%NUMBER_OF_PROCESSORS% * 2
if %LLM_SLOTS% LSS 16 set LLM_SLOTS=16

echo.
echo [2/5] Starting llama.cpp LLM Server (Port 11434 with %LLM_THREADS% threads, %LLM_SLOTS% parallel slots, --cont-batching)...
start "Llama LLM Server" /d "%~dp0" /min "%LLAMA_SERVER_EXE%" --port 11434 -m "%~dp0google_gemma-4-E4B-it-Q4_K_M.gguf" -c 0 -np %LLM_SLOTS% -t %LLM_THREADS% -b 2048 -ub 512 --mlock --flash-attn on --cont-batching

echo.
echo [3/5] Starting llama.cpp Embedding Server (Port 11435 with %EMBED_THREADS% threads, --mlock locked RAM)...
start "Llama Embedding Server" /d "%~dp0" /min "%LLAMA_SERVER_EXE%" --port 11435 -m "%~dp0nomic-embed-text-v1.5.f16.gguf" -t %EMBED_THREADS% --mlock --embedding

echo.
echo [4/5] Starting Database & Live Telemetry (SQLite / PostgreSQL & Redis Port 6380)...
if exist "%~dp0tools\redis\redis-server.exe" (
    start "Windows Redis Server" /d "%~dp0tools\redis" /min "%~dp0tools\redis\redis-server.exe" --port 6380
)
docker-compose up -d > nul 2>&1

echo.
echo Waiting 12 seconds for models to load in RAM...
timeout /t 12 >nul

echo.
echo [5/5] Launching AISecurityAudit HTTPS Server ^& Dashboard...
set LLM_BACKEND=llama.cpp
set EMBEDDING_HOST=http://127.0.0.1:11435
set OLLAMA_KEEP_ALIVE=24h
set OLLAMA_NUM_PARALLEL=4
set OLLAMA_MAX_LOADED_MODELS=3
set MAX_CONCURRENT_AUDITS=%LLM_SLOTS%
set REDIS_URL=redis://127.0.0.1:6380/0
set JWT_SECRET=3f955ad04cac120284051dc8bdaed7320dfeaba546860e8a3507dc8583a06ec9

echo.
echo ==================================================
echo   AICyberAuditBox Secure HTTPS Server Active
echo   Domain URL: https://aicyberauditbox.com/
echo   Press Ctrl+C in this terminal to stop server.
echo ==================================================
start https://aicyberauditbox.com/
python -m uvicorn src.api.main:app --host :: --port 443 --ssl-keyfile key.pem --ssl-certfile cert.pem
pause
