# Summary of Discussion & Project Updates

This document summarizes the tasks, code refinements, and project discussions completed on July 14, 2026.

---

## 1. Report Humanization & PDF Generation

We modified the evaluation and safety gap analysis reports to remove all AI-generated patterns and ensure clean rendering during PDF export.

* **Formatting Fixes:**
  * Removed all AI-style emojis from document and section headers (e.g., `📋`, `🛠️`, `🔍`, `🚨`).
  * Replaced Unicode box-drawing characters (`│`, `├──►`, `└──►`) in the security scanning architecture diagram with standard ASCII lines (`|`, `+-->`, `--->`). This fixes the missing lines in PDF exports when standard converters lack specialized Unicode fonts.
  * Converted raw GitHub markdown alerts (`> [!IMPORTANT]`) to standard bolded text sections so they render correctly in standard markdown-to-pdf tools.
  * Replaced copy-pasted en-dashes (`–`) with standard hyphens (`-`).
* **PDF Compilation:**
  * Created a dedicated Python script `scripts/generate_gap_pdf.py` that parses the markdown reports and generates clean, professional PDFs with styled tables and borders.
  * Recompiled the files to:
    * `EVALUATION_GAP_ANALYSIS.pdf` (Workspace)
    * `evaluation_gap_analysis.pdf` (OneDrive)

---

## 2. Ingestion Consistency Fixes

We discussed how the system handles inconsistencies in ingesting PDFs, scanned files, and other formats:
* **Chunking bug resolved:** A bug was identified where paragraphs longer than 800 characters were silently truncated at 1,200 characters, leading to lost clauses during database ingestion.
* **Paragraph Ingestion Splitter:** The parser now dynamically splits large paragraphs by single newlines (`\n`) before building sliding RAG windows, preserving 100% of the policy text.
* **RAG Bypass:** Files under 35KB bypass chunking and are loaded directly into the LLM context to ensure complete coverage.
* **Verbatim Grounding Fallback:** Added a fallback search in `validator.py` that checks the raw file text to verify quotes that span across chunk boundaries.
* **OCR Support:** Scanned PDFs and images are scanned via EasyOCR alongside standard text extraction.

---

## 3. Scorecard & Framework Questions (DeepEval / RaaGa)

We prepared responses for the project check questions:
* **Status:** All core safety guardrails (input checking, prompt injection checks, context safety buffers, audit logs, and human approval gates) are fully verified and OK.
* **RaaGa (RAGAS) / DeepEval Metrics:** These evaluate the RAG pipeline's quality. They map to the four metrics inside the automated test suite (`tests/run_evals.py`):
  * **Faithfulness:** Verifying findings are grounded in documents (prevents hallucinations).
  * **Answer Relevancy:** Checking if the reasoning directly addresses the control.
  * **Context Recall:** Measuring if the retriever found all required information.
  * **Context Precision:** Evaluating the prioritization of retrieved chunks.
* **Future Upgrade Plan:** We recommended transitioning from simple pass/fail gates to mathematical semantic scoring (0.0 to 1.0) using an LLM-as-a-judge node to track the metrics dynamically.

---

## 4. Scoping & VAPT Implementation

We verified the details for points 5 and 6 on manual scoping and VAPT:
* **Manual Scoping (Item 5):** Verified that the custom sidebar uploader parses `.xlsx`/`.xls` sheets using pandas, maps columns automatically, auto-checks corresponding controls, and updates the expected evidence mapping.
* **VAPT Support (Item 6):** Support was added by integrating 15 specialized pentesting and vulnerability assessment controls (VAPT-1 to VAPT-15) covering rules of engagement, OSINT, service scanning, and API audits into the core database.
* **Mentor's VAPT workflow:** Clarified that the user uploads raw PT/VA scan reports as evidence. The AI then reads these scans to find security gaps, maps them to VAPT controls, and generates a structured audit findings report with risk levels (High/Medium/Low) and recommendations.
