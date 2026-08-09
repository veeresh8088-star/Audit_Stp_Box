# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

AICyberAuditBox — an offline-first AI auditing platform with two audit modes:

1. **ISO 27001 compliance auditing** — an agentic RAG pipeline (LangGraph) that evaluates uploaded
   evidence documents against ISO 27001 controls and produces Compliant / Partially Compliant /
   Non-Compliant / Out-Of-Scope findings with P1–P4 severity.
2. **VAPT (technical pentest) report parsing** — deterministic parsers for scanner output
   (Nessus, Burp Suite, Nmap, Qualys, Trivy) mapped to CWE/OWASP Top 10.

Everything runs locally/offline: local LLM inference via `llama-server.exe` (llama.cpp), a local
Postgres ("ShaktiDB") with SQLite fallback, and a FastAPI backend serving a static HTML/JS frontend
(no Streamlit, despite what README.md's "Architecture" section says — that section is stale).

## Running the app

```bat
run_all.bat
```
This is the full one-click launcher: kills stale processes on ports 8000/443/11434/11435, generates
a self-signed cert if missing, starts two llama.cpp servers (LLM on 11434, embeddings on 11435),
starts Redis + Postgres (`docker-compose up -d`), then runs `python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000`.

Alternatives:
- `run_api.bat` — assumes LLM server already running; just checks Docker/Ollama and starts the API.
- `run_api_llamacpp.bat` — same but hard-fails if the llama.cpp LLM/embedding servers aren't already up on 11434/11435.
- `run_llamacpp_demo.bat` — starts just the llama.cpp servers.
- `stop_all.bat` — tears everything down.
- Manual: `docker-compose up -d` then `python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000`.

Dashboard: `http://localhost:8000/`.

## Tests

There is no pytest suite/config — tests are standalone scripts run directly, and they expect the
full stack (LLM servers + DB) to already be running:

```bat
python tests/run_evals.py                       :: Faithfulness/retrieval eval suite (4 scenarios incl. adversarial prompt injection)
python tests/test_10_users_audit_evidence.py     :: 10-user concurrent audit + Excel scoping load test
python -m py_compile src/ui/app.py               :: syntax check (README reference; path is stale, see below)
```

## Environment variables

No `.env.example` exists; variables are read via `os.environ.get(...)` with defaults scattered
across modules. Key ones (see `run_all.bat` for the full set used in production-like runs):

- `LLM_BACKEND` (fixed to `llama.cpp` — `get_llm_backend()` in `src/core/llm_client.py` no longer supports Ollama despite legacy naming)
- `OLLAMA_HOST` (default `http://127.0.0.1:11434`), `EMBEDDING_HOST` (default via port 11435)
- `LLM_HOSTS` — comma-separated ports/URLs to enable round-robin multi-instance load balancing (see `port_pool.py` / `llm_client.py`)
- `REDIS_URL`, `MAX_CONCURRENT_AUDITS`, `JWT_SECRET`
- `ADMIN_DEFAULT_PASSWORD`, `ADMIN_TOTP_SECRET` (first-boot admin bootstrap)
- `API_PORT` (default 8000)

## Architecture

### Request flow (ISO audit)
`src/api/main.py` (FastAPI app, security headers + CORS middleware) mounts routers from
`src/api/endpoints/{auth,controls,logs,audit,license}.py`. The audit endpoint
(`src/api/endpoints/audit.py`) handles evidence upload, kicks off a background worker
(`src/core/bg_worker.py`), and streams progress via `src/core/bg_state.py` (in-memory + Redis
metrics in `src/core/redis_metrics.py`).

### LangGraph state machine (the core auditing logic)
`src/ai/audit_graph.py` compiles a 4-node graph per control: **retrieve → generate → validate →
(reflect → validate)**.
- `retrieve_node`: pulls relevant document chunks via `src/core/retrieval.py`. Supports two modes:
  standard (search across all uploaded files) and **Excel-scoping two-phase mode** — when an
  uploaded Excel checklist locks a control to specific filenames, retrieval is restricted to only
  those files (`locked_filenames`), so the LLM never sees unrelated evidence.
- `generate_node`: calls the LLM via `src/ai/audit_chains.py` chains (`get_generator_chain`, or
  `get_excel_scoping_chain` for judge-only two-phase mode) with a hard timeout and heartbeat
  progress updates so long generations don't appear stuck.
- `validate_node`: runs `src/core/validator.py::post_process`, which enforces **grounding**
  (evidence quote must appear verbatim in source text) and checks for prompt-injection/leakage.
  Includes a "fast-path guardrail" that bypasses reflection when the evidence quote is a verified
  exact substring of the document. Failed validation triggers a max of 1 reflection retry
  (`reflection_node`, via `get_reflection_chain`) before falling back to a NON_COMPLIANT/PARTIAL
  finding with `requires_human_review=True`.
- Reasoning constraints for what counts as a valid finding/gap are defined in `.agents/AGENTS.md`
  (intent-based control evaluation, no framework creep from NIST/CIS/SOC2/PCI, no hallucinated
  gaps, conservative acceptability) — these rules are baked into the prompts in `audit_chains.py`
  and should stay in sync with that file.

### LLM access
All inference goes through `src/core/llm_client.py`, which talks exclusively to `llama-server.exe`
(llama.cpp's native `/completion` and `/embedding` endpoints, with an OpenAI-compatible
`/v1/embeddings` fallback). `src/core/port_pool.py` (`LLMPortPoolManager`, a process-wide singleton)
leases per-port mutex locks so concurrent audits round-robin across configured LLM ports without
prompt collisions. Timeouts scale dynamically with the number of concurrently active audit sessions
(read from Redis metrics, or the in-memory `_bg_running` set if Redis is down) — see
`_calculate_adaptive_timeout()` in `audit_graph.py`.

### Database (`src/db/database.py`)
SQLAlchemy models for a Master + 2-Slave Postgres topology ("ShaktiDB", schema bootstrapped by
`init.sql` inside the `shakthidb` Docker container on port 15234) with automatic fallback to a local
SQLite file (`data/sqlite/shakthidb_sqlite.db`) if Postgres is unreachable. `force_master()` pins the
current thread's DB routing to the master engine for read-after-write consistency (used right after
writes). Core tables: `users`, `audit_reports`, `evidence_files`, `findings`, `admin_audit_logs`,
`auditor_learning_rules`, plus checkpointing/chat/system-event tables. Findings carry a large set of
forensic fields (evidence_quote, hallucination_check, confidence, human_verified, etc.) beyond the
basic compliance status.

### Crash-resilient checkpointing
Progress is persisted every ~10 controls (`AuditCheckpoint`); on restart, the API surfaces a
"resume interrupted audit" path that continues from the last checkpoint and merges prior results
(see `get_resumable_checkpoint` in `src/core/bg_worker.py`).

### Knowledge loop
`src/ai/knowledge_loop.py` reads `AuditorLearningRule` entries (auditor corrections/false-positive
feedback saved via the UI) and injects them as few-shot guidance into the generator prompt for
matching controls, so the auditor's past corrections aren't repeated by the LLM.

### VAPT parsing pipeline
`src/core/parsers/` — `base_parser.py` defines the common interface; `{burp,nessus,nmap,qualys,trivy}_parser.py`
each parse a specific scanner's raw output into `finding_schema.py::Finding` objects;
`control_mapper.py` deterministically maps CWE IDs to OWASP Top 10 (2021) categories via a static
lookup table (not LLM-driven — this path is separate from the ISO RAG pipeline).

### Document ingestion
`src/core/parsers/doc_parsers.py::extract_text` handles PDF (+OCR via EasyOCR for scanned pages),
Word, Excel (all sheets), PowerPoint, CSV, plain text, images, and recursively-extracted ZIP
folders. `src/core/excel_scoping_parser.py` specifically parses uploaded Excel audit
checklists to derive the `locked_filenames` used by the two-phase retrieval mode above.
`src/core/input_guardrail.py::scan_file_security` screens uploads before processing.
`src/core/pii_redactor.py` redacts PII from extracted text.

### Auth & licensing
`src/core/auth.py` — SHA256 password hashing, TOTP (pyotp) 2FA, ISO 27001 A.5.17-compliant password
policy, email-format username validation. `src/api/endpoints/license.py` +
`generate_license_key.py` handle license key issuance/validation. JWT session tokens are signed with
`JWT_SECRET` (PyJWT).

## Known inconsistencies to be aware of

- `README.md`'s "Architecture" section references `src/ui/app.py` (Streamlit) — that no longer
  exists. The real entry point is `src/api/main.py` (FastAPI) + `src/api/static/` (static frontend).
- `get_llm_backend()` in `llm_client.py` always returns `"llama.cpp"`; Ollama-named env vars
  (`OLLAMA_HOST`) are kept only as a fallback default value for the llama.cpp server URL.
- Large local model binaries (`*.gguf`, several GB) and `llama-server.exe` live directly in the repo
  root — expect slow `ls`/search operations there and avoid reading these binary files.
