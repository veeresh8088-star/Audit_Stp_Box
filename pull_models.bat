@echo off
title Pulling Offline AI Models (ISO 27001 Auditor)
echo ==========================================
echo    AICyberAuditBox - Offline Models Download
echo ==========================================
echo.
echo Downloading required models for private auditing.
echo These run efficiently on local hardware.
echo.

echo.
echo [1/3] Downloading Qwen 2.5 (7B) [~4.7 GB]...
ollama pull qwen2.5:7b

echo.
echo [2/3] Downloading Gemma 2 (9B) [~5.4 GB]...
ollama pull gemma2:9b

echo.
echo [3/3] Downloading Gemma 4 (12B) [~7.0 GB]...
ollama pull gemma4:12b

echo.
echo ==========================================
echo All selected models have been pulled!
pause
