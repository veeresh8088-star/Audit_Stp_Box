# 📑 Migration, Tech Stack & Token-Based Architecture Report

**Document ID:** ARCH-MIG-2026-V3  
**Project:** AICyberAuditBox (ShaktiDB + LangGraph Audit Engine)  
**Date:** July 24, 2026  
**Author:** AI Compliance & Systems Architecture Team  

---

## Executive Summary

This report documents the architectural evolution of the **AICyberAuditBox** system from a single-threaded Streamlit prototype into a production-grade, asynchronous **FastAPI + LangGraph + ShaktiDB (PostgreSQL Master-Slave)** platform.

It details the full **Technology Stack** (including the **Active HTML5/Vanilla JS Bundle** and the **React/Vite Enterprise Blueprint**), cross-platform local LLM execution model (**Windows `.exe` vs macOS / Linux native binaries**), safety guardrails, background execution models, UI visual updates, and specifies a **Token-Based Architecture & Rate-Limiting Specification** for enterprise scaling, tenant isolation, and API quota management.

---

## Section 1: Comprehensive Technology Stack

```
+-----------------------------------------------------------------------------------+
|                            AICyberAuditBox TECH STACK                              |
|                                                                                   |
|  [ Active Local UI ] -> HTML5, Modern CSS3 (Glassmorphism), Vanilla JS (ES6)      |
|  [ Enterprise UI ]  -> React + Vite Blueprint (frontend/src/App.jsx)              |
|                                         |                                         |
|  [ Backend API ] ---> FastAPI (Python 3.14), Uvicorn Server, RESTful JSON Endpoints|
|                                         |                                         |
|  [ AI Engine ] -----> LangGraph State Machine (4-Gate Validation & Reflection)    |
|                                         |                                         |
|  [ Local LLM ] -----> llama.cpp (llama-server.exe / macOS Metal Native Binary)    |
|                       Gemma 4 (e4b) & Gemma 2 (2b) GGUF Models                    |
|                                         |                                         |
|  [ Vector & RAG ] -> Nomic Embed Text v1.5 + BAAI/bge-reranker-base               |
|                                         |                                         |
|  [ Database ] -----> ShaktiDB (PostgreSQL Master-Slave Replication in Docker)    |
|                       + Local SQLite Fallback Engine (SQLAlchemy ORM)             |
|                                         |                                         |
|  [ OCR & Parsers] -> pdfplumber, python-docx, openpyxl, EasyOCR (Image OCR)       |
+-----------------------------------------------------------------------------------+
```

### Core Technologies Breakdown

1. **Frontend Architecture (Dual Deployment Modes):**
   * **Active Integrated Bundle (`src/api/static/`):** Pure HTML5 + Vanilla JS (ES6 Async/Await) + Modern CSS3 served directly by FastAPI. Zero Node.js or `npm` installation required for instant offline execution.
   * **Enterprise Blueprint (`frontend/src/`):** React 18 + Vite Component Architecture (`App.jsx`, `components/`) designed for multi-tenant web application scaling.

2. **Backend Framework & Server:**
   * **FastAPI (Python 3.14):** Asynchronous, high-throughput REST API layer providing non-blocking request handling.
   * **Uvicorn:** Production-grade ASGI server running on `http://127.0.0.1:8000`.

3. **AI & Audit Orchestration:**
   * **LangGraph:** Stateful graph state machine managing control retrieval, generation, validation, and reflection loops.
   * **NativeOllamaChain & query_llm:** Custom zero-dependency HTTP wrappers for non-blocking local inference.

4. **Database & Master-Slave Replication Architecture:**
   * **ShaktiDB (PostgreSQL 15):** High-availability Master-Slave database cluster running in Docker (`docker-compose.yml` on port `15234`).
   * **SQLite Local Fallback:** Automatic zero-config fallback to `data/local_audit.db` if PostgreSQL is offline.
   * **SQLAlchemy ORM:** Multi-engine abstraction with dynamic connection binding (`force_master()` context manager).

5. **Local LLM & Embedding Engines:**
   * **llama.cpp:** High-performance local C/C++ LLM runner supporting GGUF quantizations (`google_gemma-4-E4B-it-Q4_K_M.gguf`).
   * **Nomic Embed Text (v1.5):** 768-dimensional vector embedding model for document paragraph chunking (`nomic-embed-text-v1.5.f16.gguf`).
   * **BGE Reranker Base:** `BAAI/bge-reranker-base` cross-encoder for Deep mode evidence rescoring.

6. **Document Ingestion & OCR Parsers:**
   * **Text Parsers:** `pdfplumber`, `PyPDF2`, `python-docx`, `openpyxl`, `pandas`.
   * **Hybrid OCR Engine:** `EasyOCR` (English GPU/CPU pipeline) for extracting text from embedded screenshots, ID badges, scanned logbooks, and architecture diagrams.

---

## Section 2: Cross-Platform Binary Resolution (Windows `.exe` vs macOS / Linux)

To guarantee 100% offline local execution across different operating systems without requiring users to install Python LLM dependencies or Heavy C++ build tools, the system implements **Platform-Aware Binary Resolution**:

### 1. Windows Operating System (`llama-server.exe`)
* **Executable Binary:** Pre-compiled Windows x64 binary `llama-server.exe` located in project root or system path.
* **Launcher Script (`run_all.bat`):** Launches `llama-server.exe` with port `11434` for LLM generation and port `11435` for embedding generation.

### 2. macOS Operating System (Native Metal Acceleration)
* **Executable Binary:** Native POSIX Mach-O binary `./llama-server` compiled with **Apple Silicon Metal Acceleration (`GGML_METAL=ON`)** for M1/M2/M3/M4 chips.
* **Launcher Script (`run_all.sh`):** Launches Mach-O binary with GPU offloading (`--ngl 99`).

### 3. Cross-Platform Resolution Logic Matrix

| Operating System | Binary Target | Hardware Acceleration | Execution Port | Default Launch Command |
|---|---|---|---|---|
| **Windows 10/11** | `llama-server.exe` | CPU OpenMP / AVX2 / CUDA | `11434` (LLM) <br> `11435` (Embed) | `run_all.bat` |
| **macOS (Apple Silicon)** | `./llama-server` (Mach-O) | Apple Metal GPU (`-ngl 99`) | `11434` (LLM) <br> `11435` (Embed) | `./run_all.sh` |
| **Linux (Ubuntu/RHEL)** | `./llama-server` (ELF64) | CUDA / ROCm / OpenBLAS | `11434` (LLM) <br> `11435` (Embed) | `./run_all.sh` |

---

## Section 3: Core System Migration & Technical Architecture

### 1. Monolithic Streamlit to FastAPI Micro-Service Decoupling
* **Migration Fix:** Created asynchronous FastAPI backend (`src/api/endpoints/audit.py`, `src/api/endpoints/controls.py`) with non-blocking background workers (`src/core/bg_worker.py`) using thread-safe state stores (`_bg_store`, `_bg_running`, `_bg_lock`).

### 2. LangGraph 4-Gate Audit State Machine
* **Engine:** State machine configured in `src/ai/audit_graph.py` with 4 strict validation gates: Leakage Guardrail, Verbatim Citation Grounding, Scope Matrix, and Self-Correction Reflection Pass.

### 3. Multi-Role Access Control & Chat Isolation
* **Migration Fix:** Added `username` column to `ChatMessage` in `src/db/database.py`. Scoped `/chats/send`, `/chats/history`, `/chats/sessions`, and `/chats/clear` API endpoints to filter strictly by `username`.

### 4. Real-Time Audit Stop API & Progress Watchdog
* **Migration Fix:** Implemented `POST /api/audit/stop/{session_id}` endpoint in `audit.py` with `_bg_stop_flags` check at every control boundary. Integrated `⛔ Stop Analysis` button in UI.

### 5. ShaktiDB Commit & Audit Records Finalization
* **Migration Fix:** Added `PUT /api/audit/findings/commit-session/{session_id}` endpoint. Added unreviewed warning banner (`⚠️ Notice...`) and `💾 Save to Shakthi DB` button to finalize findings and recalculate compliance scores.

### 6. VAPT & ISO 27001 Dual-Workflow Reconciliation
* **Migration Fix:** When VAPT is selected, UI hides Quick/Deep radios, displays Streamlit VAPT explainer notice, and runs pure-Python instant technical extraction (< 0.5s).

### 7. Per-Control Latency Telemetry & 9-Min Timeout
* **Migration Fix:** Enforced per-control latency logging in `data/audit_run_latency.log` with a hard 9-minute (`540s`) thread join timeout per LLM node call.

### 8. Visual & UI Refinement (Green COMPLIANT Badges)
* **Migration Fix:** Case-insensitive status matching (`COMPLIANT` -> Green badge `rgba(16, 185, 129, 0.22)`), fixed control title formatting (`5.15 Access Control`), and added **🟢 Compliant** and **🔴 Non-Compliant** filter cards.

---

## Section 4: Token-Based Architecture & Future Scaling Specifications

```
+-----------------------------------------------------------------------------------+
|                            TOKEN-BASED ARCHITECTURE FLOW                          |
|                                                                                   |
|  [ Client / UI ] ---> ( JWT Bearer Token ) ---> [ FastAPI Token Middleware ]      |
|                                                          |                        |
|                                                          v                        |
|                                               [ Token Bucket Rate Limiter ]       |
|                                                          |                        |
|                                                          v                        |
|  [ LLM Inference ] <--- ( Budget Capping ) <--- [ Token Estimator & Log ]         |
|                                                          |                        |
|                                                          v                        |
|                                               [ TokenUsageLog in ShaktiDB ]       |
+-----------------------------------------------------------------------------------+
```

### 1. Token Authentication & JWT Session Security
* **JWT Bearer Authentication:** Secure API access via `Authorization: Bearer <JWT_TOKEN>`.
* **Payload:** `username`, `role`, `tenant_id`, `session_id`, `token_quota`, `exp`.

### 2. Token Budgeting & LLM Context Capping
* **Prompt Token Estimation:** Converted prompt length to token counts (`len(prompt) // 4` or `tiktoken`).
* **Control Token Budget Capping:** Max **8,192 input tokens** / **1,024 output tokens** per control.

### 3. Rate Limiting & Quota Tiers (Token Bucket Algorithm)

| Tenant Tier | Requests / Min | Session Token Quota | Max Parallel Audits | Features Included |
|---|---|---|---|---|
| **Auditee** | 20 req/min | 50,000 tokens | 1 scan | View findings, AI Copilot Chat |
| **Auditor** | 60 req/min | 500,000 tokens | 3 scans | Full RAG audit, DOCX/PDF exports, Shakthi DB commit |
| **Enterprise / Admin** | 120 req/min | Unlimited | 10 scans | Multi-tenant management, custom controls, full telemetry |

### 4. Database Telemetry & Token Accounting Schema
New table added to `src/db/database.py`: `TokenUsageLog` (`id`, `tenant_id`, `username`, `session_id`, `control_id`, `prompt_tokens`, `completion_tokens`, `total_tokens`, `model_name`, `backend_engine`, `created_at`).
