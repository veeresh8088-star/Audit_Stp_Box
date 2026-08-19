# Product Requirements Document (PRD)
## Project: AICyberAuditBox - Audit Checkpointing, Stop/Resume & Knowledge Loop Sync

### 1. Overview
Ensure fault-tolerant audit execution through per-control database checkpoints, responsive stop/resume control lifecycle, and seamless export/import synchronization of the auditor feedback knowledge loop.

### 2. Requirements & Verification Scope

#### Feature 1: Granular Audit Checkpointing
- During multi-control audit execution, the platform must persist checkpoint progress (`AuditCheckpoint`) in the database after every single control evaluation.
- `GET /api/audit/status/{session_id}` must return active checkpoint metadata (`completed_batches`, `total_controls`, `status`).

#### Feature 2: Audit Stop & Unblock Lifecycle
- `POST /api/audit/stop/{session_id}` must signal background workers to stop execution, release leased LLM slots, and unblock the session state.

#### Feature 3: Resume Audit from Exact Checkpoint
- `POST /api/audit/resume-checkpoint` must query the latest `AuditCheckpoint`, restore all already-completed finding results, and skip previously evaluated controls without re-running them through the LLM.

#### Feature 4: Knowledge Loop Feedback Export
- `GET /api/audit/feedback/export` must securely export all `AuditorFeedback` human corrections and few-shot calibration examples in valid JSON format.

#### Feature 5: Knowledge Loop Feedback Import & PII Redaction
- `POST /api/audit/feedback/import` must accept uploaded feedback JSON files, validate records, redact PII (emails, IPs, phones), prevent duplicates, and inject them into future RAG prompt few-shot context.
