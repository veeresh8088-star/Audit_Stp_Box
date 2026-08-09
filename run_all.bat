@echo off
cd /d "%~dp0"
set "PYTHONPATH=%~dp0;%PYTHONPATH%"
title AISecurityAudit - Start All Local Services
echo ==================================================
echo   AISecurityAudit: Unified Single-Click Launcher
echo ==================================================

echo.
echo [1/6] Installing/updating Python dependencies...
python -m pip install -r requirements.txt --disable-pip-version-check -q
if errorlevel 1 (
    echo [!] Dependency install failed or skipped ^(no internet / offline run^) -- continuing with existing packages.
) else (
    echo [v] Python dependencies up to date.
)

echo.
echo [2/6] Stopping any existing backend server instances...
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

:: Calculate Physical Cores using WMI/CIM (or fallback to logical/2) for accurate thread/slot distribution
set "PHYSICAL_CORES="
for /f "tokens=*" %%c in ('powershell -NoProfile -Command "(Get-CimInstance Win32_Processor).NumberOfCores" 2^>nul') do set PHYSICAL_CORES=%%c
if "%PHYSICAL_CORES%"=="" set /a PHYSICAL_CORES=%NUMBER_OF_PROCESSORS% / 2
if %PHYSICAL_CORES% LSS 1 set PHYSICAL_CORES=4

set /a LLM_THREADS=%NUMBER_OF_PROCESSORS%
if %LLM_THREADS% LSS 1 set LLM_THREADS=4

set /a EMBED_THREADS=%NUMBER_OF_PROCESSORS%
if %EMBED_THREADS% LSS 1 set EMBED_THREADS=4

:: Calculate parallel LLM slots for llama.cpp continuous batching.
:: Total context (-c 0, the model's native max) is split evenly across these slots,
:: so more slots = more concurrent audits but less context room per slot. Formula:
:: Physical Cores / 2 (e.g. 10 Physical Cores -> 5 Slots) keeps each slot's context
:: large enough for a full audit document + multi-evidence findings without truncating.
set /a LLM_SLOTS=%PHYSICAL_CORES% / 2
if %LLM_SLOTS% LSS 4 set LLM_SLOTS=4

echo.
echo [3/6] Starting llama.cpp LLM Server (%PHYSICAL_CORES% Physical Cores --^> %LLM_SLOTS% Parallel Slots for %LLM_SLOTS% Concurrent Members, --cont-batching)...
start "Llama LLM Server" /d "%~dp0" /min "%LLAMA_SERVER_EXE%" --port 11434 -m "%~dp0google_gemma-4-E4B-it-Q4_K_M.gguf" -c 0 -np %LLM_SLOTS% -t %LLM_THREADS% -b 2048 -ub 512 --mlock --flash-attn on --cont-batching

echo.
echo [4/6] Starting llama.cpp Embedding Server (Port 11435 with %EMBED_THREADS% threads, --mlock locked RAM)...
start "Llama Embedding Server" /d "%~dp0" /min "%LLAMA_SERVER_EXE%" --port 11435 -m "%~dp0nomic-embed-text-v1.5.f16.gguf" -t %EMBED_THREADS% --mlock --embedding

echo.
echo [5/6] Starting Database ^& Live Telemetry (SQLite / PostgreSQL ^& Redis Port 6380)...
if exist "%~dp0tools\redis\redis-server.exe" (
    start "Windows Redis Server" /d "%~dp0tools\redis" /min "%~dp0tools\redis\redis-server.exe" --port 6380
)
docker-compose up -d > nul 2>&1

echo.
echo Waiting 12 seconds for models to load in RAM...
timeout /t 12 >nul

echo.
echo [6/6] Launching AISecurityAudit HTTPS Server ^& Dashboard...
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
echo   AICyberAuditBox Local Web Dashboard Active
echo   Local URL: http://localhost:8000/
echo   Press Ctrl+C in this terminal to stop server.
echo ==================================================
start http://localhost:8000/
python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000
pause
