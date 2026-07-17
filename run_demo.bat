@echo off
title AICyberAuditBox Demo Launcher
echo ==========================================
echo    AICyberAuditBox
echo ==========================================

goto :check_llamacpp

:check_llamacpp
echo [1/3] Checking llama.cpp (AI Engine)...
python -c "import socket; s=socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', 11434))" >nul 2>&1
if %errorlevel% neq 0 goto :llamacpp_llm_error

python -c "import socket; s=socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', 11435))" >nul 2>&1
if %errorlevel% neq 0 goto :llamacpp_embed_error

echo [v] OK: llama.cpp backend is active.
goto :db_check

:llamacpp_llm_error
echo [ERROR] llama.cpp LLM server is not running on port 11434!
exit /b 1

:llamacpp_embed_error
echo [ERROR] llama.cpp Embedding server is not running on port 11435!
exit /b 1

:db_check
echo.
echo [2/3] Checking Database (ShaktiDB)...
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
docker rm -f shakthidb_service > nul 2>&1
docker-compose up -d
goto :docker_done

:docker_fail
echo [ERROR] Docker is not running or Docker Desktop is not detected!
echo         ShaktiDB PostgreSQL is required to run the Master-Slave Database Architecture.
echo         Please start Docker Desktop and run this script again.
exit /b 1

:docker_done

echo.
echo [3/3] Launching Dashboard...
if not exist ".deps_installed" goto :install_deps
echo [v] Dependencies already installed. Skipping.
goto :start_app

:install_deps
echo Installing dependencies ^(first run only^)...
pip install -r requirements.txt --quiet
echo. > .deps_installed
echo [v] Dependencies installed and cached.

:start_app
set PYTHONWARNINGS=ignore
set TRANSFORMERS_NO_ADVISORY_WARNINGS=1
python -m streamlit run src/ui/app.py --server.port 8501 --server.address 0.0.0.0
