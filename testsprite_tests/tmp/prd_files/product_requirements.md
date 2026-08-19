# AICyberAuditBox ISO 27001 & VAPT RAG Flows PRD

## 1. ISO 27001 Compliance RAG Flow
- **Objective**: Evaluates uploaded ISMS documents and operational evidence against ISO 27001:2022 Annex A controls.
- **RAG Behavior**:
  - Uses dual Policy + Evidence keyword signals and semantic vector embeddings.
  - Hybrid scoring (0.4 keyword + 0.6 vector similarity) with Cross-Encoder reranking.
  - Generates ISO finding drafts enforcing the Policy vs Evidence split (both rule and operational proof).

## 2. VAPT Technical Vulnerability RAG Flow
- **Objective**: Ingests vulnerability assessment and penetration testing scan logs (Nmap, Nessus, Burp, OWASP).
- **RAG Behavior**:
  - Ingests raw scan logs, open ports, CVE definitions, and weak ciphers.
  - Activates `VAPT_GENERATOR_PROMPT_TEMPLATE` and `VAPT_REFLECTION_PROMPT_TEMPLATE`.
  - Extracts verbatim Proof of Concept (POC) snippets, calculates CVSS scores, and maps to `VAPT-1` through `VAPT-15` and OWASP categories without demanding policy documents.
