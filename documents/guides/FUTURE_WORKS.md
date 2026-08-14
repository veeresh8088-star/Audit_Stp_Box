# Future Works & Architectural Roadmap — AICyberAuditBox

This document outlines planned architectural enhancements, design pattern integrations, and future feature proposals for **AICyberAuditBox**.

---

## 1. Current Architecture Overview

Currently, **AICyberAuditBox** employs a robust **4-Node Single-Agent LangGraph State Machine** (`retrieve ➔ generate ➔ validate ➔ reflect`) executing 100% offline via local LLM inference (`llama-server.exe`). 

It already incorporates **6 of 8 common Agentic AI design patterns**:
- **Sequential Workflow**: Deterministic node ordering (`START` → `retrieve` → `generate` → `validate`).
- **Router Pattern**: Dual-mode execution (Excel Checklist Scoping vs. Standard RAG) and VAPT parsing routing.
- **Reflection & Self-Correction**: Grounding validator that routes back to a `reflect` node on verification failure.
- **Memory-Based Workflow**: Knowledge loop (`knowledge_loop.py`) injecting past auditor corrections into prompts.
- **Human-in-the-Loop**: Flagging ambiguous findings for auditor review (`requires_human_review`).
- **Retry & Recovery**: Adaptive timeouts, SQLite DB fallbacks, and locked retrieval fail-safes.

---

## 2. Feature Proposal: Multi-Agent Collaboration Framework (Pattern 6)

### 2.1 Concept & Architecture
Transition from a single-agent node graph to a **Multi-Agent Supervisory System** where specialized autonomous agents collaborate on complex audit controls.

```
                    ┌───────────────────────────────┐
                    │  Supervisor / Coordinator     │
                    │            Agent              │
                    └──────────────┬────────────────┘
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         ▼                         ▼                         ▼
┌──────────────────┐    ┌────────────────────┐    ┌────────────────────┐
│    Evidence      │    │   ISO Compliance   │    │ Quality & Grounding│
│ Researcher Agent │    │   Auditor Agent    │    │  Reviewer Agent    │
└──────────────────┘    └────────────────────┘    └────────────────────┘
```

### 2.2 Proposed Agent Roles & Responsibilities
1. **Evidence Researcher Agent**
   - **Task**: Deep multi-document search across PDFs, Word docs, Excel sheets, and ZIP archives.
   - **Capabilities**: Formulates iterative semantic queries, resolves terminology synonyms, and extracts candidate evidence passages.
2. **ISO Compliance Auditor Agent**
   - **Task**: Intent-based evaluation against ISO 27001 control requirements (`.agents/AGENTS.md`).
   - **Capabilities**: Applies strict intent-over-keyword rules, evaluates control objectives, and drafts compliance status (Compliant / Partial / Non-Compliant).
3. **Quality & Grounding Reviewer Agent**
   - **Task**: Independent verification and adversarial check.
   - **Capabilities**: Verifies verbatim quote grounding, screens for prompt injection, checks for missing evidence, and triggers re-investigation or human review escalation.

### 2.3 Benefits
- **Higher Precision**: Eliminates single-prompt context clutter by giving each agent a focused persona and constrained responsibility.
- **Complex Cross-Document Reasoning**: Enables iterative search loops (e.g. cross-referencing HR onboarding policy against physical access logs).
- **Domain Specialization**: Facilitates adding specialized sub-agents (e.g., VAPT Technical Agent, Cloud Infrastructure Agent).

### 2.4 Performance Mitigations for Offline Local LLMs
Multi-agent collaboration increases LLM invocation count per control (from ~1–2 calls to 4–6 calls). To maintain high offline performance:
- **Port Pool Parallelization**: Leverage `src/core/port_pool.py` to route agent sub-tasks across multiple parallel `llama-server.exe` instances.
- **Hierarchical Agent Execution**: Run lightweight researcher/reviewer tasks using smaller/faster quantized models (e.g., 2B models) while reserving 4B–7B models for primary compliance reasoning.

---

## 3. Feature Proposal: Advanced Parallel Execution & Multi-Instance Scaling (Pattern 3)

- **Distributed Control Evaluation**: Evaluate non-dependent ISO controls concurrently across available CPU/GPU worker threads.
- **Dynamic Resource Guardrails**: Implement token bucket rate-limiting and dynamic RAM management (`src/core/redis_metrics.py`) to scale concurrent audit capacity seamlessly without system exhaustion.

---

## 4. Feature Proposal: Interactive Conversational Audit Assistant (Human-in-the-Loop 2.0)

- **Auditor Chat Co-Pilot**: An interactive UI sidecar allowing human auditors to:
  - Ask follow-up questions about specific control findings.
  - Request targeted re-evaluation with custom evidence files.
  - Instantly convert auditor corrections into long-term learning rules saved to `AuditorLearningRule`.

---

## 5. Feature Proposal: Automated Cross-Framework Control Mapping

- **Unified Security Knowledge Graph**: Map technical pentest (VAPT) findings (CWE / OWASP Top 10) directly into corresponding ISO 27001 control findings (e.g., A.8.8 Management of technical vulnerabilities).
- **Automated Evidence Correlation**: Automatically attach VAPT scanner evidence (Nessus/Burp/Nmap) to relevant ISO control evidence buckets.

---

## 6. Implementation Roadmap

| Phase | Horizon | Target Feature | Key Files to Modify |
| :---: | :---: | :--- | :--- |
| **Phase 1** | Short-Term | Parallel multi-instance LLM evaluation (Pattern 3 optimization) | `src/core/port_pool.py`, `src/core/bg_worker.py` |
| **Phase 2** | Medium-Term | Interactive Auditor Chat Co-Pilot (Human-in-the-Loop 2.0) | `src/api/endpoints/audit.py`, `src/api/static/index.html` |
| **Phase 3** | Long-Term | Multi-Agent Collaboration Framework (Pattern 6 integration) | `src/ai/audit_graph.py`, `src/ai/audit_chains.py` |
| **Phase 4** | Long-Term | VAPT-to-ISO Unified Evidence Mapping | `src/core/parsers/control_mapper.py`, `src/db/database.py` |
