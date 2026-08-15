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
echo [2/6] Stopping any existing backend server instances (excluding Docker)...
taskkill /F /IM python.exe /T >nul 2>&1
taskkill /F /IM uvicorn.exe /T >nul 2>&1
taskkill /F /IM llama-server* /T >nul 2>&1
taskkill /F /IM ollama* /T >nul 2>&1
powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort 8000,11434,11435,443 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; if ($p -and $p.ProcessName -notlike '*docker*') { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }" >nul 2>&1
echo [v] Ports 8000, 11434 ^& 11435 cleared safely without stopping Docker.


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
if "%LLM_SLOTS%"=="" set LLM_SLOTS=24



echo.
echo [3/6] Starting llama.cpp LLM Server (%PHYSICAL_CORES% Physical Cores --^> %LLM_SLOTS% Parallel Slots for %LLM_SLOTS% Concurrent Members, --cont-batching)...
start "Llama LLM Server" /d "%~dp0" /min "%LLAMA_SERVER_EXE%" --port 11434 -m "%~dp0google_gemma-4-E4B-it-Q4_K_M.gguf" -c 0 -np %LLM_SLOTS% -t %LLM_THREADS% -b 2048 -ub 512 --flash-attn on --cont-batching

echo.
echo [4/6] Starting llama.cpp Embedding Server (Port 11435 with %EMBED_THREADS% threads)...
start "Llama Embedding Server" /d "%~dp0" /min "%LLAMA_SERVER_EXE%" --port 11435 -m "%~dp0nomic-embed-text-v1.5.f16.gguf" -t %EMBED_THREADS% --embedding

echo.
echo [5/6] Starting Database ^& Live Telemetry (SQLite / PostgreSQL ^& Redis Port 6380)...
if exist "%~dp0tools\redis\redis-server.exe" (
    start "Windows Redis Server" /d "%~dp0tools\redis" /min "%~dp0tools\redis\redis-server.exe" --port 6380
)
docker ps > nul 2>&1
if %errorlevel% equ 0 (
    echo [v] Docker detected. Starting ShaktiDB PostgreSQL container...
    docker-compose up -d shakthidb > nul 2>&1
) else (
    echo [i] Docker is offline/not running. Continuing with local SQLite fallback database.
)


echo.
echo Waiting 12 seconds for models to load in RAM...
timeout /t 12 >nul

set LLM_BACKEND=llama.cpp
set EMBEDDING_HOST=http://127.0.0.1:11435
set OLLAMA_KEEP_ALIVE=24h
set OLLAMA_NUM_PARALLEL=4
set OLLAMA_MAX_LOADED_MODELS=3
set MAX_CONCURRENT_AUDITS=%LLM_SLOTS%
set REDIS_URL=redis://127.0.0.1:6380/0
:: JWT_SECRET intentionally not set here -- that hardcoded value was a real,
:: exploitable credential (forge any session, including admin) once committed
:: to source control. src/api/endpoints/auth.py generates and persists a
:: random secret to data/.jwt_secret on first run if JWT_SECRET isn't set;
:: set it explicitly here only for a production/multi-instance deployment.

echo.
echo [6/6] Launching AISecurityAudit Web Dashboard...
echo ==================================================
echo   AICyberAuditBox Local Web Dashboard Active
echo   Local URL: http://localhost:8000/
echo   Press Ctrl+C in this terminal to stop server.
echo ==================================================
start http://localhost:8000/
python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000
pause


