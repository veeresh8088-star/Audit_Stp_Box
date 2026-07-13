# 📋 Evaluation & Safety Analysis Report

This report evaluates the verification, testing, and safety mechanisms of **AICyberAuditBox** against two major frameworks:
1. **RAGAS Scorecard** (RAG Evaluation Lab)
2. **Agent Safety & Governance Labs** (Agent Safety Lab)

---

## 🛠️ System Control Implementation

Overview of how each control is systematically implemented inside the codebase. All validation layers are fully integrated.

| Control | Files Changed | Where it is & How it works |
| :--- | :--- | :--- |
| **G1 – Faithfulness + Relevancy** | `tests/run_evals.py` | Deployed inside the test suite: `compute_semantic_scores()` extracts faithfulness directly from validation grounding states, and relevancy via vector embeddings comparison on port 11435. |
| **G2 – Context Recall + Precision** | `tests/run_evals.py` | Deployed inside the test suite: `compute_retrieval_scores()` cross-references retrieved context paragraphs against expected key phrases and keywords. |
| **G3 – PII Redaction** | `src/core/pii_redactor.py`, `src/ui/report_exporter.py` | Deployed inside `pii_redactor.py`: a dedicated text scrubber filters emails, IP addresses, and phone numbers from findings before generating DOCX and PDF reports. |
| **G4 – Audit Metadata Logs** | `src/ai/audit_graph.py` | Deployed inside `audit_graph.py`: the final validator node writes detailed execution statistics (token lengths, latency, retries) to the database logging table. |
| **G5 – Input Guardrail** | `src/core/input_guardrail.py`, `src/ui/app.py` | Deployed inside `input_guardrail.py` and upload hooks: a 4-layer file checker scans magic bytes, VBA macros, ZIP compression ratios, and text bounds during upload. |

---

## 1. RAGAS Evaluation Scorecard

The RAGAS framework focuses on evaluating the quality of Retrieval-Augmented Generation pipelines using four key metrics:

| RAGAS Metric | Definition | Where it is & How it works | Status |
| :--- | :--- | :--- | :--- |
| **Faithfulness** | Grounding verification | Checked by forensic grounding gates in `validator.py` (`GROUNDED` status mapped to numeric score). | **OK** |
| **Answer Relevancy** | Alignment with control query | Cosine similarity calculated between control and findings embeddings using the local embedding server. | **OK** |
| **Context Recall** | Information coverage | Validated against target phrases mapped inside the automated evaluation suite. | **OK** |
| **Context Precision** | Retrieval chunk priority | Assessed based on the ratio of retrieved context chunks containing at least one control-relevant keyword. | **OK** |

---

## 2. Agent Safety & Governance Scorecard

The Agent Safety Lab specifies guardrails, governance, and tracing. Below is how the system maps to these safety labs:

| Safety Lab | Focus Area | Where it is & How it works | Status |
| :--- | :--- | :--- | :--- |
| **Lab 2: Input Guardrails** | Ingestion file filtering | Deployed inside `input_guardrail.py`: magic signature checks, Office macro scanning, decompression ratios, and null byte scans. | **OK** |
| **Lab 3: Prompt Injection** | Adversarial text resilience | Deployed inside `validator.py`: Gate 1 checks context matching and prompts for leakage or override attempts. | **OK** |
| **Lab 4: Output Guardrails** | PII / formatting filters | Deployed inside `pii_redactor.py`: regex pattern filters scrub emails, IPs, and phone numbers before report export. | **OK** |
| **Lab 5 & 6: Context Assembly** | Safe context bounds | Deployed inside `retrieval.py`: token budgets and sliding windows prevent prompt overflow. | **OK** |
| **Lab 7: Audit Logs** | Execution trace logs | Deployed inside `audit_graph.py`: detailed execution traces are written to the SQLite/PostgreSQL DB logs. | **OK** |
| **Lab 8: Human Approval Gates** | Manual override flow | Deployed inside `app.py`: validation warning states set the review flag for operator override. | **OK** |

---

## 3. Security Scanning Architecture (Input Guardrail Detail)

The file-scanning pipeline runs in pure Python (no external binaries or libraries required) to preserve offline performance on Windows:

```
[ Upload Document ]
        │
        ├──► Layer 1: Magic Bytes Check (struct) ────► Detects extension spoofing (.exe renamed to .pdf)
        │
        ├──► Layer 2: Macro Scan (zipfile) ──────────► Detects VBA macro contents inside Office formats
        │
        ├──► Layer 3: ZIP Bomb Check (zipfile) ──────► Detects hazardous compression expansion ratios (>100:1)
        │
        └──► Layer 4: Text Content Scan (len) ──────► Detects null bytes (\x00) and oversize blocks (>50MB)
```

> [!IMPORTANT]
> If any layer triggers a check failure, it writes a `WARNING` entry to the database and surfaces a warning notification inside the Streamlit client app. However, it **does not block** document processing, allowing human operators to inspect and decide.
