# Offline AI Auditor — Knowledge Loop Backup & Restore Solution

This document details the architectural approach and implementation details for backing up and restoring false-positive feedback loops in the offline AI auditor.

## Problem Statement
When a compliance audit completes, security policy mandates require wiping all transient database records (including reports, findings, evidence files, and historical feedback loops) to ensure clean environments. However, losing auditor corrections means the local LLM will lose its context guidelines and repeat false-positive findings during future audits of the same target company.

---

## Proposed Solution: JSON-Based Feedback Backup

To prevent framework decay and retain custom learning records, we introduce a **Backup & Restore** system using structured **JSON** files.

### Architectural Workflow
1. **Auditor Action:** The auditor reviews compliance scans and marks false findings as **False Positive** or **Compliant**, adding custom review notes.
2. **Persistence:** The API maps and writes these corrections to the `AuditorFeedback` memory table.
3. **Backup Export:** Before wiping the database, the Admin/Auditor exports the memory loop via:
   `GET /api/audit/feedback/export` -> Downloads `auditor_feedback_memory_backup.json`.
4. **Wipe:** The Admin executes a complete database wipe.
5. **Restore Import:** Years later, when starting a new audit cycle, the Admin uploads the backup file via:
   `POST /api/audit/feedback/import` -> Restores the feedback memory records.

---

## Why JSON is the Best Format

We selected **JSON (.json)** over alternative formats (CSV, Excel, or SQL dumps) for the following core reasons:

### 1. Robust handling of multi-line policy extracts
* **Context:** Auditor feedback and evidence snippets contain raw extracts from policy documents, logs, and configuration scripts. These values frequently contain newlines (`\n`), backslashes, quotation marks (`"`, `'`), and commas.
* **Format Comparison:**
  * **CSV:** Standard comma-separated parsers are highly susceptible to structural breakage and column shifting when parsing multi-line text strings containing quotes and commas.
  * **JSON:** String escaping and nested structures are a native specification of the JSON format, guaranteeing 100% data integrity upon import.

### 2. Schema Flexibility and Future-Proofing
* **Context:** As the AI Auditor expands, new model variables or confidence metrics (e.g. `hallucination_check`, `confidence_score`) may be added to feedback tables.
* **Format Comparison:**
  * **SQL Dumps:** Bound to the specific table schema at the time of export. Importing old SQL dumps into updated database schemas will trigger relational constraint failures.
  * **JSON:** Parsed as schema-agnostic key-value collections. Unrecognized fields are safely ignored, while missing fields default gracefully, ensuring long-term backwards compatibility.

### 3. Lightweight & Zero Dependency
* **Context:** The workspace runs completely offline. Minimizing heavy libraries is critical.
* **Format Comparison:**
  * **Excel (.xlsx):** Requires loading heavy libraries such as `openpyxl` and `pandas` to reconstruct spreadsheets on the backend.
  * **JSON:** Both JavaScript and Python feature optimized, standard library decoders (`json.loads`, `JSON.parse`) that process file transactions in microseconds with zero overhead.
