@echo off
title Pulling Offline AI Models (Fast & High Performance)
echo ==========================================
echo    AICyberAuditBox - Offline Models Download
echo ==========================================
echo.
echo Downloading performance and lightweight models (0.5B-8B parameters).
echo These are excellent for reasoning, document auditing, and run efficiently on local hardware.
echo.

echo [1/8] Downloading Llama 3.2 (1B) [Ultra Fast Inference]...
ollama pull llama3.2:1b

echo.
echo [2/8] Downloading Llama 3.2 (3B) [Fast Inference]...
ollama pull llama3.2

echo.
echo [3/8] Downloading Llama 3.1 (8B) [~4.7 GB]...
ollama pull llama3.1

echo.
echo [4/8] Downloading Qwen 2.5 (7B) [~4.7 GB]...
ollama pull qwen2.5:7b

echo.
echo [5/8] Downloading Qwen 2.5 (3B) [~1.9 GB]...
ollama pull qwen2.5:3b

echo.
echo [6/8] Downloading Qwen 2.5 (1.5B) [~986 MB]...
ollama pull qwen2.5:1.5b

echo.
echo [7/8] Downloading Qwen 2.5 (0.5B) [~394 MB]...
ollama pull qwen2.5:0.5b

echo.
echo [8/8] Downloading Gemma 2 (2B) [~1.6 GB]...
ollama pull gemma2:2b

echo.
echo ==========================================
echo All selected models have been pulled!
pause
