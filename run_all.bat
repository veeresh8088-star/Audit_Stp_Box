@echo off
cd /d "%~dp0"
set "PYTHONPATH=%~dp0;%PYTHONPATH%"
title AICyberAuditBox - Start All Local Services
echo ==================================================
echo   AICyberAuditBox: Unified Single-Click Launcher
echo ==================================================

echo.
echo [1/5] Stopping any existing backend server instances...
taskkill /F /IM ollama* /T >nul 2>&1
taskkill /F /IM llama-server* /T >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :11434 ^| findstr LISTENING') do taskkill /F /PID %%a >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :11435 ^| findstr LISTENING') do taskkill /F /PID %%a >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8000 ^| findstr LISTENING') do taskkill /F /PID %%a >nul 2>&1
echo [v] Port 8000 cleared.

:: Locate llama-server.exe
set "LLAMA_SERVER_EXE="
if exist "C:\Users\veeresh988V\Desktop\llama\llama-server.exe" (
    set "LLAMA_SERVER_EXE=C:\Users\veeresh988V\Desktop\llama\llama-server.exe"
) else if exist "C:\Users\HP\Downloads\llama,,ccppp mode\llama-server.exe" (
    set "LLAMA_SERVER_EXE=C:\Users\HP\Downloads\llama,,ccppp mode\llama-server.exe"
) else (
    set "LLAMA_SERVER_EXE=%~dp0llama-server.exe"
)

echo.
echo [2/5] Starting llama.cpp LLM Server (Port 11434)...
start "Llama LLM Server" /d "%~dp0" /min "%LLAMA_SERVER_EXE%" --port 11434 -m "%~dp0google_gemma-4-E4B-it-Q4_K_M.gguf" -c 8192 -t 4 -b 512 --flash-attn on

echo.
echo [3/5] Starting llama.cpp Embedding Server (Port 11435)...
start "Llama Embedding Server" /d "%~dp0" /min "%LLAMA_SERVER_EXE%" --port 11435 -m "%~dp0nomic-embed-text-v1.5.f16.gguf" -t 2 --embedding

echo.
echo [4/5] Starting Docker Database Service (ShaktiDB)...
docker rm -f shakthidb_service > nul 2>&1
docker-compose up -d

echo.
echo Waiting 12 seconds for models to load in RAM...
timeout /t 12 >nul

echo.
echo [5/5] Launching Local API Server & Web Dashboard...
set LLM_BACKEND=llama.cpp
set EMBEDDING_HOST=http://127.0.0.1:11435
set OMP_NUM_THREADS=4
set MKL_NUM_THREADS=4
set OPENBLAS_NUM_THREADS=4

start http://127.0.0.1:8000/
echo.
echo ==================================================
echo   AICyberAuditBox API Server Running Live on 8000
echo   Press Ctrl+C in this terminal to stop server.
echo ==================================================
python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000
pause
