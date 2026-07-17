# AICyberAuditBox — Technical System Architecture & Directory Specification

This document defines the formal system architecture, modular layout, step-by-step pipeline lifecycles, and technical schemas of the compliance auditing platform.

---

## 1. Modular System Layers
This compliance platform is structured into a decoupled, four-tier architecture:

*   **Layer 1: Presentation & Exporters**
    *   *Core Tech*: Streamlit, FPDF2, python-docx
    *   *Responsibility*: Manages user dashboards, active scan sessions, and report export formatting.
    *   *Input*: User interactions & file uploads.
    *   *Output*: Dynamic HTML views & PDF/DOCX downloads.
    
*   **Layer 2: AI Workflows & State Graph**
    *   *Core Tech*: LangGraph, Pydantic, Python RegEx
    *   *Responsibility*: Orchestrates compliance evaluation nodes, scoping mapping, and revision loops.
    *   *Input*: Scanned document context & control checklists.
    *   *Output*: Structured finding schemas & validation scores.

*   **Layer 3: RAG Engine & Core Utilities**
    *   *Core Tech*: BM25, Cosine Similarity, SHA256 hashes
    *   *Responsibility*: Handles document vector indexing, similarity search, grounding verification, and security scans.
    *   *Input*: Raw document texts & search query strings.
    *   *Output*: Relevant text chunks & security scan status.

*   **Layer 4: Data Persistence Layer**
    *   *Core Tech*: ShaktiDB (PostgreSQL), SQLAlchemy
    *   *Responsibility*: Tracks past runs, active checkpoints, and logs.
    *   *Input*: Transaction payloads & scan checkpoints.
    *   *Output*: Persisted audit runs & system event logs.

---

## 2. Directory File Registry
The system codebase is divided into modular packages under the `src/` directory:

### 2.1 Presentation & Exporters (`src/ui/`)
*   **[app.py](file:///c:/Users/HP/Desktop/llama,cpp/au/src/ui/app.py)**
    *   *Responsibility*: Entry point of the Streamlit dashboard. Manages application state, active tabs, deferred OCR processing, and clamped progress calculations.
*   **[auth.py](file:///c:/Users/HP/Desktop/llama,cpp/au/src/ui/auth.py)**
    *   *Responsibility*: Role-Based Access Control (RBAC). Isolates Auditor and Auditee views.
*   **[report_exporter.py](file:///c:/Users/HP/Desktop/llama,cpp/au/src/ui/report_exporter.py)**
    *   *Responsibility*: Compiles report findings into high-fidelity PDF and Word documents with generic editable placeholders.

### 2.2 AI Workflows & State Graph (`src/ai/`)
*   **[audit_graph.py](file:///c:/Users/HP/Desktop/llama,cpp/au/src/ai/audit_graph.py)**
    *   *Responsibility*: Compiles the LangGraph state machine workflow directing retrieve, draft, validate, and revision nodes.
*   **[audit_chains.py](file:///c:/Users/HP/Desktop/llama,cpp/au/src/ai/audit_chains.py)**
    *   *Responsibility*: Defines prompt templates and parses raw LLM output into structured Pydantic find schemas.
*   **[scoping_engine.py](file:///c:/Users/HP/Desktop/llama,cpp/au/src/ai/scoping_engine.py)**
    *   *Responsibility*: Maps uploaded policy files to candidate controls using keyword rules and vector similarities.

### 2.3 RAG Engine & Core Utilities (`src/core/`)
*   **[retrieval.py](file:///c:/Users/HP/Desktop/llama,cpp/au/src/core/retrieval.py)**
    *   *Responsibility*: Combines BM25 and Nomic vector search. Manages persistent binary disk caching.
*   **[validator.py](file:///c:/Users/HP/Desktop/llama,cpp/au/src/core/validator.py)**
    *   *Responsibility*: Cross-checks cited quotes against raw texts using alphanumeric normalization and prefix backtracking.
*   **[llm_client.py](file:///c:/Users/HP/Desktop/llama,cpp/au/src/core/llm_client.py)**
    *   *Responsibility*: Unified client wrapper interface for Ollama or llama.cpp backend servers.
*   **[input_guardrail.py](file:///c:/Users/HP/Desktop/llama,cpp/au/src/core/input_guardrail.py)**
    *   *Responsibility*: Validates file hashes and signatures to block malware uploads immediately.

### 2.4 Data Persistence Layer (`src/db/`)
*   **[database.py](file:///c:/Users/HP/Desktop/llama,cpp/au/src/db/database.py)**
    *   *Responsibility*: Implements the SQLAlchemy database models, transaction locks, and checkpoints.

---

## 3. Data Processing Pipeline Lifecycle
The step-by-step lifecycle of an audit execution follows a strict sequence:

1.  **Upload**: User drops document files into the Streamlit file uploader widget.
2.  **Threat Scan**: Immediate check of the binary buffer for PE headers or blacklisted hashes.
3.  **Metadata Save**: File written to data directory and registered in SQLAlchemy DB.
4.  **Idle Registry**: File displayed in the scanned registry list (no text extraction is run yet).
5.  **Click Run**: User clicks "Run Analysis" to start the analysis process.
6.  **OCR & Index**: Deferred text extraction and vector chunk indexing are processed.
7.  **Scope Filter**: Scopes mapped to controls; queries filtered to restrict cross-file matching.
8.  **Graph Exec**: Retrieve node runs hybrid search; Generator drafts compliance findings.
9.  **Grounding**: Validator scans cited quotes using alphanumeric check and prefix fallback.
10. **DB Commit**: Structured findings, statuses, and logs committed to ShaktiDB.
11. **Export**: Findings exported to PDF or DOCX using placeholders (`[Auditor Firm Name]`).

---

## 4. Key Engineering Paradigms

### 💾 4.1 Persistent Local RAG Cache (Indexing Layer)
*   **Concept**: Bypasses CPU vector calculations on re-runs by serializing chunk representations.
*   **Format**: Dictionary of hash-to-float vectors written via `pickle` to `.embeddings_cache.pkl`.
*   **Result**: RAG retrieval starts in under `50ms` (0% CPU overhead).

### ⏳ 4.2 Deferred Ingestion & OCR (UX Optimization)
*   **Concept**: Prevents browser tab hangs during file selections by delaying heavy IO.
*   **Mechanism**: Sidebar file uploader registers files instantly as `None` placeholders. Text extraction and indexing are delayed to run sequentially within the background analysis thread.

### 🛡️ 4.3 Ingestion-Time Malware Block (Security Layer)
*   **Concept**: Stops executable exploits from reaching disk storage.
*   **Checks**: Checks for executable headers (`b'MZ'`) and compares SHA256 hashes against blacklists. Rejects uploads and renders red security alerts before any write operations occur.
