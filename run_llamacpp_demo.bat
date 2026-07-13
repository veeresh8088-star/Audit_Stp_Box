@echo off
title AICyberAuditBox llama.cpp Unified Launcher
echo ==================================================
echo   Starting AICyberAuditBox with llama.cpp backend
echo ==================================================

echo.
echo [1/4] Stopping any existing Ollama or llama-server processes...
taskkill /F /IM ollama.exe /T >nul 2>&1
taskkill /F /IM llama-server.exe /T >nul 2>&1

echo.
set "LLAMA_SERVER_EXE="
if exist "C:\Users\veeresh988V\Desktop\llama\llama-server.exe" (
    set "LLAMA_SERVER_EXE=C:\Users\veeresh988V\Desktop\llama\llama-server.exe"
) else if exist "C:\Users\HP\Downloads\llama,,ccppp mode\llama-server.exe" (
    set "LLAMA_SERVER_EXE=C:\Users\HP\Downloads\llama,,ccppp mode\llama-server.exe"
) else (
    set "LLAMA_SERVER_EXE=%~dp0llama-server.exe"
)

echo [2/4] Starting llama-server LLM on port 11434...
start "Llama LLM Server" /d "%~dp0" /min "%LLAMA_SERVER_EXE%" --port 11434 -m "%~dp0google_gemma-4-E4B-it-Q4_K_M.gguf" -c 4096 -t 8 -b 512 --flash-attn on

echo.
echo [3/4] Starting llama-server Embeddings on port 11435...
start "Llama Embedding Server" /d "%~dp0" /min "%LLAMA_SERVER_EXE%" --port 11435 -m "%~dp0nomic-embed-text-v1.5.f16.gguf" -t 4 --embedding

echo.
echo Waiting 15 seconds for backend servers to initialize...
timeout /t 15 >nul

echo.
echo [4/4] Setting environment variables and launching Streamlit...
set LLM_BACKEND=llama.cpp
set EMBEDDING_HOST=http://127.0.0.1:11435

call run_demo.bat
