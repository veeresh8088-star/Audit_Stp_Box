@echo off
title AICyberAuditBox Demo Launcher
echo ==========================================
echo    AICyberAuditBox
echo ==========================================

echo.
echo [1/3] Checking Ollama (AI Engine)...
python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:11434/', timeout=2)" >nul 2>&1
if %errorlevel% equ 0 goto :ollama_active

echo [i] NOTE: Ollama is not running. Starting it automatically...
start "" /b "%localappdata%\Programs\Ollama\ollama.exe" serve
echo Waiting for Ollama to initialize...
timeout /t 6 >nul
goto :ollama_done

:ollama_active
echo [v] OK: Ollama is active.

:ollama_done

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
python -m streamlit run src/ui/app.py --server.port 8501
