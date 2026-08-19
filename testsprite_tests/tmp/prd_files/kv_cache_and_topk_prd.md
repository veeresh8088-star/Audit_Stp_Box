# Product Requirements Document (PRD)
## Project: AICyberAuditBox - KV Cache & Zero-Missed-Evidence TOP_K Retrieval

### 1. Overview & Objectives
Ensure optimal LLM memory management via Flash Attention KV-Cache allocation and complete, lossless evidence retrieval across multi-file audit uploads through dynamic TOP_K expansion and cross-document evidence diversity.

### 2. Features & Requirements

#### Feature 1: Dynamic KV Cache & Flash Attention Allocation
- The local inference engine (`llama-server.exe`) must allocate a guaranteed context window of at least 16k tokens per parallel slot (`-np`), scaling dynamically with available host RAM (`max(32768, 16384 * np)`).
- Flash attention (`--flash-attn on`) and continuous batching (`--cont-batching`) must be enabled to prevent memory spikes and maximize token throughput during concurrent control evaluations.

#### Feature 2: High-Recall Multi-Document TOP_K Evidence Retrieval
- The RAG retrieval pipeline must configure a high candidate retrieval floor (`TOP_K >= 20` in Deep mode) across all supported file types (PDF, DOCX, TXT, XLSX, CSV, PPTX, Image).
- Real BM25 (Okapi) dual flavored queries (Policy terms vs Operational Evidence terms) combined with dense embeddings (hybrid 40% BM25 + 60% Vector) must be applied across all document chunks.

#### Feature 3: Cross-Document Evidence Diversity & Zero-Missed Evidence
- When multiple evidence files are attached to a session, the RAG engine must enforce evidence diversity by ensuring every uploaded file with relevant content (`score > 0.15`) has representation in the final context window.
- The pipeline must return both Policy requirements and Operational proof records without omission (Needle-in-a-Haystack test).

#### Feature 4: Safety & Fallback Guarantees
- If primary candidate selection yields insufficient tokens, the engine must trigger an automatic 2nd pass with expanded token limits before falling back to full text, preventing false `NOT_FOUND` audit findings.
