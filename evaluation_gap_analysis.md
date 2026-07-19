# Evaluation and Safety Analysis Report

This document details the evaluation results of the security controls and safety mechanisms implemented in the AICyberAuditBox platform. Controls are evaluated against the RAGAS framework (RAG Evaluation Lab) and the Agent Safety & Governance standards.

---

## System Control Implementation

The following table summarizes the implementation status and mechanics for each security control. All validation and scanning layers are fully integrated into the primary audit pipeline.

| Control | Implementation Details | Status |
| :--- | :--- | :--- |
| G1 - Faithfulness & Relevancy | Evaluated in `tests/run_evals.py` via `compute_semantic_scores()`. Faithfulness is checked against validation grounding states, and relevancy is calculated using vector embeddings on port 11435. | OK |
| G2 - Context Recall & Precision | Evaluated in `tests/run_evals.py` via `compute_retrieval_scores()`. Retrieved context chunks are cross-referenced against expected key phrases and keywords. | OK |
| G3 - PII Redaction | Implemented in `src/core/pii_redactor.py` and `src/ui/report_exporter.py` as a regex-based text scrubber that filters out emails, IP addresses, and phone numbers before reports are exported. | OK |
| G4 - Audit Metadata Logs | Orchestrated in `src/ai/audit_graph.py`, where the final validation node logs execution metrics (token counts, run latency, and correction retries) to the database. | OK |
| G5 - Input Guardrail | Integrated via `src/core/input_guardrail.py` and file upload hooks in `src/ui/app.py`. Incoming files undergo magic byte verification, macro checks, zip bomb protection, and size boundaries validation. | OK |
| G6 - Custom Excel Scoping | Added to the sidebar layout in `src/ui/app.py`: parses `.xlsx`/`.xls` scopes via pandas, auto-maps input columns, checks corresponding controls, and safely updates the session state configuration. | OK |

---

## 1. RAGAS Evaluation Scorecard

The quality of the retrieval and generation stages is monitored across four primary metrics:

| RAGAS Metric | Definition | Implementation Details | Status |
| :--- | :--- | :--- | :--- |
| Faithfulness | Outcomes are grounded in source documentation | Checked by grounding gates in `validator.py` (GROUNDED status is mapped to a numeric score). | OK |
| Answer Relevancy | Response alignment with control requirements | Calculated via cosine similarity between the control description and finding embeddings. | OK |
| Context Recall | RAG retrieval coverage of required source information | Cross-referenced against expected target phrases within the evaluation suite. | OK |
| Context Precision | Concentration of relevant information in retrieved chunks | Evaluated by calculating the percentage of retrieved chunks that contain control-relevant keywords. | OK |

---

## 2. Agent Safety & Governance Scorecard

Safety, logging, and governance layers align with standard agent safety specifications:

| Safety Lab | Focus Area | Implementation Details | Status |
| :--- | :--- | :--- | :--- |
| Lab 2: Input Guardrails | Ingestion file filtering | Configured in `input_guardrail.py` to run magic byte signature checks, office macro detection, decompression ratios, and null byte scans. | OK |
| Lab 3: Prompt Injection | Adversarial text resilience | Checked in `validator.py` (Gate 1), which flags prompts containing template leakage or override patterns. | OK |
| Lab 4: Output Guardrails | PII / formatting filters | Scrubbing regexes in `pii_redactor.py` filter emails, IP addresses, and phone numbers before generating reports. | OK |
| Lab 5 & 6: Context Assembly | Safe context bounds | Managed in `retrieval.py` using sliding windows and token budgets to prevent prompt length overflow. | OK |
| Lab 7: Audit Logs | Execution trace logs | Writers in `audit_graph.py` record execution metadata and status traces directly to database logs. | OK |
| Lab 8: Human Approval Gates | Manual override flow | Handled in `app.py` by flagging warnings that require manual inspection and override in the dashboard. | OK |

---

## 3. Security Scanning Architecture (Input Guardrail Detail)

The file-scanning pipeline is written in native Python to ensure fast offline performance on Windows, requiring no external binaries:

```
[ Upload Document ]
        |
        +--> Layer 1: Magic Bytes Check (struct) ---> Detects extension spoofing (.exe renamed to .pdf)
        |
        +--> Layer 2: Macro Scan (zipfile) ---------> Detects VBA macro contents inside Office formats
        |
        +--> Layer 3: ZIP Bomb Check (zipfile) ------> Detects hazardous compression expansion ratios (>100:1)
        |
        +--> Layer 4: Text Content Scan (len) ------> Detects null bytes (\x00) and oversize blocks (>50MB)
```

**Note on scanning failures:** If any layer triggers a check failure, it logs a `WARNING` entry to the database and displays a notification in the Streamlit client. However, document processing is **not blocked**; the system defers to human operators to inspect and make the final decision.
