# 📊 Multi-Document Audit Guide (Quick Audit Mode)
**Project Name:** AICyberAuditBox — Local Audit  
**Capability:** Multi-Document Processing, RAG Retrieval, and Validation  

---

## 1. Overview
When performing compliance audits, security policies and evidence are rarely contained within a single file. Auditors often need to upload a package of documents (e.g., standard operating procedures, asset registers, and configuration screenshots).

This guide explains the pipeline mechanics of how the **AICyberAuditBox** processes, retrieves, evaluates, and validates compliance across **multiple uploaded documents simultaneously** during a **Quick Audit** run.

### 1.1 Why Not Document-by-Document? (The Fragmentation Problem)
In standard compliance auditing, evidence is often distributed across separate files:
* **High-Level Policy (Doc A)**: Says *"MSI must have an incident plan."*
* **Response Runbook (Doc B)**: Outlines the *6 phases* of an incident.
* **Roles Matrix (Doc C)**: Lists the *names and contact info* of the response team.

If the system audited each document separately, it would produce **three fragmented and incorrect results**:
* Auditing **Doc A** alone returns `PARTIAL_COMPLIANT` (missing operational phases and team roles).
* Auditing **Doc B** alone returns `NON_COMPLIANT` (missing policy statements and team roles).
* Auditing **Doc C** alone returns `NON_COMPLIANT` (unstructured roster with no context).

**The Solution:** Instead of looping control-by-control for each document, the RAG engine aggregates context from **all uploaded documents simultaneously**. The LLM receives a consolidated view of the entire package, enabling a **single, unified, and highly accurate compliance status** for each control.

---

## 2. Ingestion & Database Stage

Every uploaded file—regardless of format—goes through a specialized parser and is stored in the database:

* **File Type Parsing:** The Streamlit dashboard parses files based on format:
  * **PDFs / Images:** Loaded page-by-page, incorporating OCR text extraction.
  * **Word (.docx):** Extracted by paragraph boundaries.
  * **Excel / CSV:** Read row-by-row in cohesive blocks of 5 rows.
* **Unified Database Indexing:** All parsed chunks are stored in a single unified table (`DocumentChunk` in ShaktiDB).
* **Metadata Tagging:** Crucially, each database record is tagged with its source file's `filename` and `page_number`/`row_index` so that citations can be mapped back to their origin.

---

## 3. Retrieval & Diversity Enforcement (RAG)

When auditing a specific control, the RAG engine queries all chunks associated with the uploaded files:

```
                +-------------------------------------------+
                |   Hybrid Search (Vector + BM25 Keyword)   |
                +-------------------------------------------+
                                      |
                                      v
                +-------------------------------------------+
                |   Global Relevance Ranking (All Chunks)   |
                +-------------------------------------------+
                                      |
                                      v
                +-------------------------------------------+
                |   Multi-Document Diversity Enforcement    |
                | (Guarantees at least 1 chunk per document)|
                +-------------------------------------------+
                                      |
                                      v
                +-------------------------------------------+
                |      Final Selected Prompt Context        |
                +-------------------------------------------+
```

1. **Global Ranking:** Chunks from all files are fetched and ranked together using a hybrid score (60% semantic similarity + 40% keyword match).
2. **Evidence Diversity Enforcement:** To prevent a single long policy document from dominating the context budget and hiding evidence in secondary files, the RAG engine enforces diversity. It ensures that **at least one relevant chunk from each uploaded file is injected** into the final context, even if its raw score was slightly lower than other chunks.

---

## 4. Context Size Decision

To optimize CPU performance and memory consumption, the system makes a threshold-based choice:

* **Small Combined Size (< 35KB / ~8,000 tokens):**
  * **Action:** Bypasses chunking entirely and sends the **entire combined text of all documents** to the LLM.
  * **Benefit:** Guarantees 100% information coverage.
* **Large Combined Size (>= 35KB / ~8,000 tokens):**
  * **Action:** Selects only the globally ranked chunks (including the diversity chunks) up to a max budget of **1,800 to 2,200 tokens**.
  * **Benefit:** Caps CPU prefill latency to under 3 minutes and prevents context window crashes.

---

## 5. Quick Audit Evaluation & Validation Gate

In a Quick Audit, the orchestrator evaluates the prompt context in a single pass:

```
  +------------------+         +---------------------+         +----------------------+
  |  Combined Files  |         |    LLM Generator    |         |  Grounding Validator |
  +------------------+         +---------------------+         +----------------------+
           |                              |                               |
           | --- Sends Context Prompt --> |                               |
           |                              | --- Draft Report -----------> |
           |                              |     (Status: NON_COMPLIANT    |
           |                              |      Evidence: NOT_FOUND)     |
           |                              |                               | -- Scans ALL chunks
           |                              |                               |    for ALL files in DB
           |                              |                               |
           |                              | <--- Keywords exist in C ---- | (Evidence in File C)
           |                              |                               |
           |                              | === Validation REJECTED! ===  |
           |                              | === Override to PARTIAL ====  |
           |                              | --- Flags Human Review -----> |
           v                              v                               v
```

1. **LLM Evaluation (Single-Pass):** The LLM reviews the context once and generates its draft compliance status, cited evidence, and gaps. Because it is Quick Mode, **no self-correction retries** are performed.
2. **Validator Verbatim Check:** The custom validator scans the database to ensure the LLM's cited quote exists word-for-word in at least one of the uploaded files.
3. **Smart Validator Override:** If the LLM output is `NOT_FOUND` (because the evidence chunk did not fit in the RAG budget), the validator runs a keyword scan (`potential_evidence_exists()`) across **the database chunks of all uploaded files**. If matching keywords are found in any file, the validator automatically overrides the LLM's draft:
   * **Status:** Upgraded to `PARTIAL_COMPLIANT`.
   * **Grounded:** Set to `NOT_GROUNDED`.
   * **Warning Appended:** `[AUDIT GAP CHECK] Potential evidence exists in document 'evidence_C.xlsx'. Manual review recommended.`
   * **Flag Set:** `requires_human_review = True`.
