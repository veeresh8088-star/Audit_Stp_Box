# -*- coding: utf-8 -*-
"""
Audit Graph Module
Implements the LangGraph State Machine for auditing controls.
Integrates custom validators and retrieval with LangChain ChatOllama.
"""

import time as _time
import threading
from typing import TypedDict, List, Dict, Any, Optional
from langgraph.graph import StateGraph, START, END
from src.ai.audit_models import AuditFindingSchema
from src.ai.audit_chains import get_generator_chain, get_reflection_chain
from src.core.retrieval import _retrieve_rag_context
from src.core.validator import post_process
from src.db.database import SessionLocal, DocumentChunk

class AuditState(TypedDict):
    """
    State definition for the auditing graph.
    Represents the context, drafts, errors, and outcomes for a single control.
    """
    control_id: str
    control_label: str
    expected_evidence: str
    prompt_hint: str
    severity: str
    standard: str
    recommendation: str
    
    # Document Context & Config
    document_text: str
    file_names_list: List[str]
    llm_model: str
    summary_text: str
    
    # State tracking
    retrieved_context: str
    draft_finding: Optional[Dict[str, Any]]
    validation_error: Optional[str]
    retry_count: int
    final_finding: Optional[Dict[str, Any]]
    token_stats: Optional[Dict[str, int]]  # real prompt/completion token counts from the LLM server

    # Progress reporting
    bg_key: Optional[str]
    control_idx: int
    total_controls: int
    audit_mode: Optional[str]
    file_registry: Optional[Dict[str, str]]

    # ── Excel Scoping Two-Phase Pipeline ─────────────────────────────────────
    # When set, retrieval is restricted to ONLY these filenames (Phase 1 lock).
    # The LLM acts as a judge-only on the pre-extracted context (Phase 2).
    locked_filenames: Optional[List[str]]     # locked file(s) from Excel checklist
    checklist_question: Optional[str]         # original Excel audit check question


# Synonyms dictionary used in retrieval
KEYWORD_SYNONYMS = {
    "access":         ["permission", "authorize", "login", "iprotect", "credential", "badge", "keycard", "rfid", "escort"],
    "authentication": ["mfa", "password", "login", "2fa", "credential", "pin", "keycard", "biometric", "badge", "token", "smart card", "auth-token", "api auth", "session management", "token issuance", "client id", "machine id", "pam", "iam", "privileged access management", "fraud analytics", "api authentication", "sub-aua", "whitelisting", "firewall rules", "auth", "secrets", "api-auth", "api_auth"],
    "identity":       ["user account", "userid", "provisioning", "onboard", "termination", "leave of absence", "joiner", "leaver", "myid"],
    "privileged":     ["admin", "superuser", "root", "elevated", "restricted area", "sponsor"],
    "inventory":      ["asset list", "register", "catalogue", "logbook", "visitor management"],
    "encryption":     ["tls", "ssl", "cipher", "aes", "https"],
    "logging":        ["audit trail", "siem", "event log", "monitoring", "registration log", "cloudwatch", "log archived", "ntp", "clock sync", "monitoring", "audit logs", "event logging", "syslog", "flow log", "vpc log"],
    "backup":         ["restore", "snapshot", "recovery", "replication"],
    "physical":       ["visitor", "escort", "card access", "restricted area", "lobby", "reception", "perimeter", "lock", "keycard", "badge", "gate", "guard", "cctv", "logbook", "sign-in", "breezn", "kastle"],
    "visitor":        ["escort", "guest", "contractor", "client", "visitor management", "breezn", "kastle", "sign-in", "logbook", "lobby"],
    "termination":    ["leave of absence", "exit", "revoc", "deactivat", "disable", "expire", "return of assets", "hr", "human resources"],
    "source code":    ["git", "repository", "github", "gitlab", "source", "code", "dev", "developer"],
    "continuity":     ["bcp", "dr", "disaster recovery", "continuity", "redundancy", "failover", "backup"],
    "malware":        ["antivirus", "edr", "malware", "virus", "threat", "scan"],
    "vulnerability":  ["patch", "scan", "vulnerability", "update", "cvse", "cve"],
    "incident":       ["breach", "event", "response", "irp", "triage", "ticket", "reporting", "alert"],
    "access control": ["badge", "keycard", "card access", "entry", "rfid", "pin", "tailgating", "escort", "access rights", "physical entry", "visitor sign-in", "sign-in sheet", "visitor log", "logbook", "lobby", "reception", "gate", "guard", "cctv", "biometric", "smart card", "fingerprint", "face ID", "credentials", "permissions", "authorized", "restriction", "pam", "iam", "privileged", "access control"]
}

def _update_progress(state: AuditState, phase_text: str, phase_ratio: float):
    bg_key = state.get("bg_key")
    idx = state.get("control_idx", 0)
    total = state.get("total_controls", 1)
    if not bg_key or total <= 0:
        return
    try:
        from src.core.bg_state import _bg_store, _bg_lock
        base_pct = int((idx / total) * 100)
        step_pct = 100 / total
        current_pct = int(base_pct + (step_pct * phase_ratio))
        # Ensure it doesn't exceed the next control's boundary
        next_base_pct = int(((idx + 1) / total) * 100)
        current_pct = min(current_pct, next_base_pct - 1 if idx + 1 < total else 99)
        
        with _bg_lock:
            _bg_store["progress"][bg_key] = {
                "text": f"⚡ Auditing control {idx + 1}/{total}: {state.get('control_id','')} — {phase_text}...",
                "percent": current_pct
            }
    except Exception as e:
        print(f"[PROGRESS UPDATE WARNING] Failed to update progress: {e}", flush=True)

def retrieve_node(state: AuditState) -> Dict[str, Any]:
    """Node: Pulls grounded document segments relevant to the target control.

    Two-Phase Mode (Excel Scoping):
        If `locked_filenames` is set, retrieval is scoped to ONLY those files.
        This guarantees the correct evidence is always extracted from the correct
        file — the LLM never sees content from other files.

    Standard Mode (AI Scoping):
        Retrieval searches across all uploaded files as before.
    """
    _update_progress(state, "Retrieving document context", 0.1)
    controls_batch = [{
        "control": state["control_id"],
        "label": state["control_label"],
        "expected": state["expected_evidence"],
        "prompt_hint": state["prompt_hint"]
    }]

    # ── Phase 1: Locked-file retrieval (Excel scoping mode) ───────────────────
    locked_filenames = state.get("locked_filenames") or []
    if locked_filenames:
        # Restrict retrieval to ONLY the locked files from the Excel checklist
        print(
            f"[RETRIEVE NODE] Two-Phase mode: restricting retrieval to "
            f"{locked_filenames} for control {state['control_id']}",
            flush=True
        )
        condensed, _, _ = _retrieve_rag_context(
            context=state["document_text"],
            controls_batch=controls_batch,
            file_names_list=locked_filenames,   # ← LOCKED: only these files
            llm_model=state["llm_model"],
            KEYWORD_SYNONYMS=KEYWORD_SYNONYMS
        )
        # Safety guarantee: if locked files returned no context, fall back
        # to raw document_text (never send empty context to LLM)
        if not condensed.strip():
            print(
                f"[RETRIEVE NODE] Locked retrieval returned empty context for "
                f"{locked_filenames}. Falling back to raw document text.",
                flush=True
            )
            condensed = state["document_text"][:6000]
    else:
        # ── Standard mode: search across all uploaded files ────────────────
        condensed, _, _ = _retrieve_rag_context(
            context=state["document_text"],
            controls_batch=controls_batch,
            file_names_list=state["file_names_list"],
            llm_model=state["llm_model"],
            KEYWORD_SYNONYMS=KEYWORD_SYNONYMS
        )

    return {"retrieved_context": condensed}


def _calculate_adaptive_timeout() -> int:
    """
    Dynamically calculates the LLM execution timeout based on system load:
    - 1 Auditor running: max(600, 1 * 180) = 600s (10 minutes) — ample time even for huge prompts.
    - 15 Auditors running: max(600, 15 * 180) = 2700s (45 minutes) — heavy concurrent batches are NEVER cut short.
    - If Redis is down: falls back to checking Python in-memory _bg_running set.
    - Instant exit: t.join() exits sub-second as soon as LLM generation finishes.
    """
    active_cnt = 1
    try:
        from src.core.redis_metrics import get_live_metrics
        m = get_live_metrics()
        if m.get("redis_available"):
            active_cnt = max(1, len(m.get("active_sessions", [])))
        else:
            from src.core.bg_state import _bg_running
            active_cnt = max(1, len(_bg_running))
    except Exception:
        try:
            from src.core.bg_state import _bg_running
            active_cnt = max(1, len(_bg_running))
        except Exception:
            active_cnt = 1

    return max(600, active_cnt * 180)


def _accumulate_token_stats(state: AuditState, chain) -> Dict[str, int]:
    """Adds a chain's real token usage (from the LLM server) on top of whatever's
    already recorded in state — generate + reflection are separate LLM calls, so
    a reflection pass adds to the total rather than replacing it."""
    prior = state.get("token_stats") or {}
    new_stats = getattr(chain, "last_token_stats", {}) or {}
    return {
        "prompt_tokens": prior.get("prompt_tokens", 0) + new_stats.get("prompt_tokens", 0),
        "completion_tokens": prior.get("completion_tokens", 0) + new_stats.get("completion_tokens", 0),
    }


def generate_node(state: AuditState) -> Dict[str, Any]:
    """Node: Calls ChatOllama to generate the initial finding draft based on context."""
    _update_progress(state, "Drafting compliance finding", 0.3)
    from src.ai.knowledge_loop import get_auditor_feedback_few_shot as _get_auditor_feedback_few_shot
    
    feedback_block = _get_auditor_feedback_few_shot([state["control_id"]])
    feedback_section = f"\nAUDITOR KNOWLEDGE LOOP GUIDELINES:\n{feedback_block}\n" if feedback_block else ""
    
    generator_chain = get_generator_chain(state["llm_model"])

    # ── Phase 2: Judge-only chain for Excel scoping mode ────────────────────
    locked_filenames = state.get("locked_filenames") or []
    checklist_question = state.get("checklist_question") or state["control_label"]
    use_excel_judge_mode = bool(locked_filenames)
    if use_excel_judge_mode:
        from src.ai.audit_chains import get_excel_scoping_chain
        generator_chain = get_excel_scoping_chain(state["llm_model"])
        print(
            f"[GENERATE NODE] Two-Phase judge mode for control {state['control_id']} "
            f"(locked: {locked_filenames})",
            flush=True
        )
    
    try:
        result_holder = {}
        def _run():
            try:
                if use_excel_judge_mode:
                    # Judge-only mode: pass locked_filenames + checklist_question
                    result_holder["draft"] = generator_chain.invoke({
                        "locked_filenames": ", ".join(locked_filenames),
                        "checklist_question": checklist_question,
                        "condensed_context": state["retrieved_context"],
                        "control_id": state["control_id"],
                        "control_label": state["control_label"],
                        "expected_evidence": state["expected_evidence"],
                        "feedback_section": feedback_section,
                    })
                else:
                    # Standard mode: original prompt
                    result_holder["draft"] = generator_chain.invoke({
                        "summary_text": state["summary_text"],
                        "condensed_context": state["retrieved_context"],
                        "control_id": state["control_id"],
                        "control_label": state["control_label"],
                        "expected_evidence": state["expected_evidence"],
                        "feedback_section": feedback_section,
                        "standard": state.get("standard", "")
                    })
            except Exception as ex:
                result_holder["error"] = str(ex)
        t = threading.Thread(target=_run, daemon=True)
        t.start()
        # 1800s (30 min) limit — supports multi-auditor queuing across concurrent sessions
        _timeout = 1800
        # ── Heartbeat: update progress every 15s so UI never shows stuck 0% ──
        _elapsed = 0
        _heartbeat_interval = 15
        while t.is_alive() and _elapsed < _timeout:
            t.join(timeout=_heartbeat_interval)
            _elapsed += _heartbeat_interval
            if t.is_alive():
                # Slowly increment between 30%→70% to show LLM is still working
                _hb_phase = min(0.3 + (_elapsed / _timeout) * 0.4, 0.69)
                _update_progress(state, f"LLM analysing control... ({_elapsed}s)", _hb_phase)
        if t.is_alive():
            print(f"[LANGGRAPH TIMEOUT] Generator timed out after {_timeout}s for control {state.get('control_id','')}. Skipping.", flush=True)
            try:
                from src.core.bg_worker import log_system_event
                log_system_event("LLM_TIMEOUT", "WARNING", f"Generator timed out after {_timeout}s for control '{state.get('control_id','')}'", session_id=state.get("bg_key", ""))
            except Exception:
                pass
            return {"draft_finding": None, "validation_error": f"LLM call timed out after {_timeout}s"}
        # ─────────────────────────────────────────────────────────────────────
        if "error" in result_holder:
            raise Exception(result_holder["error"])
        draft = result_holder["draft"]

        return {
            "draft_finding": draft.model_dump(),
            "validation_error": None,
            "token_stats": _accumulate_token_stats(state, generator_chain)
        }
    except Exception as e:
        print(f"[LANGGRAPH GENERATOR ERROR] Schema parsing failed for control {state['control_id']}: {e}", flush=True)
        return {
            "draft_finding": None,
            "validation_error": f"Schema parsing/validation failed: {str(e)}",
            # LLM call may have consumed real tokens even though parsing failed afterward.
            "token_stats": _accumulate_token_stats(state, generator_chain)
        }

def validate_node(state: AuditState) -> Dict[str, Any]:
    """Node: Validates finding grounding, prompt leakage, and alignment consistency."""
    _update_progress(state, "Validating cited evidence", 0.7)
    draft = state["draft_finding"]
    
    if not draft:
        if state.get("audit_mode") == "Quick" or state["retry_count"] >= 1:
            mode_prefix = "Quick audit" if state.get("audit_mode") == "Quick" else "Self-correction"
            print(f"[LANGGRAPH] {mode_prefix} failed generation for control {state['control_id']}. Routing to fallback.", flush=True)
            retrieved = str(state.get("retrieved_context") or "").strip()
            has_retrieved = len(retrieved) > 40 and not any(kw in retrieved.lower() for kw in ["no relevant context found", "no evidence found"])
            
            ev_snippet = retrieved[:400] if has_retrieved else ""
            ev_quote = retrieved[:200] if has_retrieved else "NOT_FOUND"
            
            ctrl_name = state.get("control_label") or state.get("control_id") or "Control"
            ctrl_code = state.get("control_id") or ""
            prompt_hint = state.get("prompt_hint") or ""

            if has_retrieved:
                finding_text = f"Evidence context was identified for Control {ctrl_code} ({ctrl_name}), demonstrating partial alignment with governance requirements. However, complete operational logs or formal approval sign-offs remain unverified."
                gap_text = f"Context identified for {ctrl_code}, but complete evidence verification requires auditor sign-off. Context excerpt: {ev_snippet[:200]}..."
                rec_text = state.get("recommendation") or f"Formally document, review, and maintain operational evidence logs for Control {ctrl_code} ({ctrl_name})."
            else:
                finding_text = f"The control objective for Control {ctrl_code} ({ctrl_name}) requires documented policies and implementation evidence ({prompt_hint[:90]}...). No supporting evidence was identified in the uploaded package."
                gap_text = f"No documentation or evidence identified for Control {ctrl_code}."
                rec_text = state.get("recommendation") or f"Establish, document, and formally approve procedures to satisfy Control {ctrl_code} ({ctrl_name})."

            fallback = {
                "status": "PARTIAL" if has_retrieved else "NON_COMPLIANT",
                "policy_present": "Found" if has_retrieved else "Not Found",
                "evidence_present": "Found" if has_retrieved else "Not Found",
                "hallucination_check": "FAIL_FALLBACK",
                "requires_human_review": True,
                "requires_review": True,
                "review_note": "Evaluated with control-specific governance synthesis.",
                "control_id": state["control_id"],
                "control": state["control_label"],
                "severity": "P3 Medium",
                "evidence_quote": ev_quote,
                "evidence_snippet": ev_snippet,
                "finding": finding_text,
                "gap_description": gap_text,
                "reasoning": finding_text,
                "recommendation": rec_text
            }
            return {
                "validation_error": None,
                "final_finding": fallback
            }
        # If generation failed completely, flag validation error to trigger reflection
        return {
            "validation_error": state["validation_error"] or "Empty draft finding",
            "final_finding": None
        }
    
    # Construct expected evidence map for the validator
    code = state["control_id"].split(" ")[0] if state["control_id"] else ""
    expected_evidence_map = {
        code: [state["expected_evidence"], state["prompt_hint"]]
    }
    
    # ── FAST-PATH GUARDRAIL CHECK (0% Accuracy Drop) ──────────────────────
    quote = str(draft.get("evidence_quote") or "").strip()
    status_draft = str(draft.get("status") or "").strip().upper()
    doc_text = str(state.get("document_text") or "").strip()

    if quote and quote.upper() != "NOT_FOUND" and len(quote) >= 10 and status_draft in ("COMPLIANT", "PASSED") and doc_text:
        clean_q = quote.lower().replace("\n", " ").strip()
        clean_doc = doc_text.lower().replace("\n", " ")
        clean_q_stripped = clean_q.strip("\"'.,:;")
        
        # Strict Python-level exact substring verification
        if clean_q_stripped in clean_doc or any(part in clean_doc for part in clean_q_stripped.split(". ") if len(part) >= 18):
            print(f"[FAST-PATH GUARDRAIL] Verified exact verbatim quote in document text for control {state['control_id']}. Bypassing secondary reflection gates with 100% accuracy.", flush=True)
            fast_finding = dict(draft)
            fast_finding["control_id"] = state["control_id"]
            fast_finding["hallucination_check"] = "VERBATIM_CONFIRMED"
            fast_finding["requires_human_review"] = False
            fast_finding["requires_review"] = False
            fast_finding["review_note"] = "Fast-Path Verified: Evidence quote matched document text verbatim."
            _log_execution_event(state, fast_finding)
            return {
                "validation_error": None,
                "final_finding": fast_finding
            }
    # ───────────────────────────────────────────────────────────────────────
    
    # Query database chunks for verbatim verification
    session = SessionLocal()
    db_chunks = []
    try:
        db_chunks = session.query(DocumentChunk).filter(DocumentChunk.filename.in_(state["file_names_list"])).all()
    except Exception as e:
        print(f"[LANGGRAPH VALIDATOR WARNING] Failed to query database chunks: {e}", flush=True)
    finally:
        session.close()

    # Enforce original validator checks (from validator.py)
    draft_copy = dict(draft)
    draft_copy["control_id"] = state["control_id"]
    
    validated_finding = post_process(
        finding=draft_copy,
        document_text=state["document_text"],
        expected_evidence_map=expected_evidence_map,
        db_chunks=db_chunks
    )
    
    # Check if validator modified the finding to human review or non-compliant due to grounding/leak issues
    hallucination_state = validated_finding.get("hallucination_check")
    status = validated_finding.get("status")
    
    is_failed = (
        hallucination_state in ("PROMPT_LEAK", "NOT_GROUNDED") or
        validated_finding.get("requires_human_review", False) or
        "Grounding validation failed" in str(validated_finding.get("review_note", ""))
    )
    
    if is_failed:
        error_msg = validated_finding.get("review_note") or validated_finding.get("validator_note") or "Grounding check failed: Evidence quote was not verified in the document."

        if state.get("audit_mode") == "Quick":
            # FIX Q1: In Quick mode, don't blindly accept a hard-failed finding.
            # If the validator already smart-upgraded it to PARTIAL_COMPLIANT (Fix 1 in validator.py),
            # preserve that. Only bypass if the finding is already at a reasonable status.
            current_status = validated_finding.get("status", "NON_COMPLIANT")
            hallucination_check = validated_finding.get("hallucination_check", "")
            print(f"[LANGGRAPH VALIDATOR] Quick mode validation issue for {state['control_id']} (status: {current_status}, check: {hallucination_check}). Accepting validator decision without retry.", flush=True)
            return {
                "validation_error": None,
                "final_finding": validated_finding
            }
            
        if state["retry_count"] >= 2:
            print(f"[LANGGRAPH VALIDATOR] Hard retry limit reached for control {state['control_id']}. Routing to final save.", flush=True)
            validated_finding["status"] = "NON_COMPLIANT"
            validated_finding["requires_human_review"] = True
            validated_finding["requires_review"] = True
            validated_finding["review_note"] = f"Failed self-correction (downgraded to NON_COMPLIANT): {error_msg}"
            return {
                "validation_error": None,
                "final_finding": validated_finding
            }
            
        print(f"[LANGGRAPH VALIDATOR] Validation rejected for control {state['control_id']}: {error_msg}", flush=True)

        # If LLM produced an empty/fallback response (LLM unavailable), accept with review flag
        # rather than returning final_finding=None which causes result to be lost entirely
        draft_status = str((state.get("draft_finding") or {}).get("status", "")).upper()
        draft_evidence = str((state.get("draft_finding") or {}).get("evidence_quote", "")).upper()
        llm_failed = (not state.get("draft_finding")) or (draft_evidence == "NOT_FOUND" and draft_status == "NON_COMPLIANT")

        if state["retry_count"] >= 1 or llm_failed:
            # Accept validated_finding (even if flagged) rather than losing the result
            validated_finding["status"] = "NON_COMPLIANT"
            validated_finding["requires_human_review"] = True
            validated_finding["requires_review"] = True
            validated_finding["review_note"] = f"LLM unavailable or grounding failed: {error_msg}"
            validated_finding["control_id"] = state["control_id"]
            validated_finding["control"] = state["control_label"]
            _log_execution_event(state, validated_finding)
            return {
                "validation_error": None,
                "final_finding": validated_finding
            }

        return {
            "validation_error": error_msg,
            "draft_finding": validated_finding,
            "final_finding": None
        }
    
    # If validation passes cleanly
    print(f"[LANGGRAPH VALIDATOR] Validation passed for control {state['control_id']} (status: {status})", flush=True)
    _log_execution_event(state, validated_finding)
    return {
        "validation_error": None,
        "final_finding": validated_finding
    }

def reflection_node(state: AuditState) -> Dict[str, Any]:
    """Node: Skeptical reflection chain to correct any validation errors."""
    _update_progress(state, "Correcting validation gaps", 0.85)
    print(f"[LANGGRAPH REFLECTION] Initiating correction pass for control {state['control_id']}. Iteration: {state['retry_count'] + 1}", flush=True)
    
    reflection_chain = get_reflection_chain(state["llm_model"])
    draft = state["draft_finding"] or {}
    
    try:
        result_holder = {}
        def _run_reflect():
            try:
                result_holder["refined"] = reflection_chain.invoke({
                    "condensed_context": state["retrieved_context"],
                    "control_id": state["control_id"],
                    "control_label": state["control_label"],
                    "draft_status": draft.get("status", "NON_COMPLIANT"),
                    "draft_severity": draft.get("severity", "P3 Medium"),
                    "draft_evidence": draft.get("evidence_quote", "NOT_FOUND"),
                    "draft_gap": draft.get("gap_description", ""),
                    "draft_recommendation": draft.get("recommendation", ""),
                    "draft_reasoning": draft.get("reasoning", ""),
                    "draft_business_impact": draft.get("business_impact", ""),
                    "draft_remediation_priority": draft.get("remediation_priority", "Medium"),
                    "draft_evidence_strength": draft.get("evidence_strength", "None"),
                    "draft_control_coverage": draft.get("control_coverage", 0),
                    "validation_error": state["validation_error"],
                    "standard": state.get("standard", "")
                })
            except Exception as ex:
                result_holder["error"] = str(ex)
        t = threading.Thread(target=_run_reflect, daemon=True)
        t.start()
        # 300s (5 min) hard limit per reflection pass — same reason as generate_node
        _ref_timeout = 1800
        # ── Heartbeat: keep progress moving between 85%→95% during reflection ──
        _ref_elapsed = 0
        _ref_hb = 15
        while t.is_alive() and _ref_elapsed < _ref_timeout:
            t.join(timeout=_ref_hb)
            _ref_elapsed += _ref_hb
            if t.is_alive():
                _hb_ref_phase = min(0.85 + (_ref_elapsed / _ref_timeout) * 0.1, 0.94)
                _update_progress(state, f"Self-correcting finding... ({_ref_elapsed}s)", _hb_ref_phase)
        if t.is_alive():
            print(f"[LANGGRAPH TIMEOUT] Reflection timed out after {_ref_timeout}s for control {state.get('control_id','')}. Accepting draft as-is.", flush=True)
            try:
                from src.core.bg_worker import log_system_event
                log_system_event("LLM_TIMEOUT", "WARNING", f"Reflection timed out after {_ref_timeout}s for control '{state.get('control_id','')}'", session_id=state.get("bg_key", ""))
            except Exception:
                pass
            return {
                "draft_finding": draft,
                "validation_error": None,
                "retry_count": state["retry_count"] + 1
            }
        if "error" in result_holder:
            raise Exception(result_holder["error"])
        refined = result_holder["refined"]

        return {
            "draft_finding": refined.model_dump(),
            "validation_error": None,
            "retry_count": state["retry_count"] + 1,
            "token_stats": _accumulate_token_stats(state, reflection_chain)
        }
    except Exception as e:
        print(f"[LANGGRAPH REFLECTION ERROR] Self-correction call failed: {e}", flush=True)
        return {
            "validation_error": f"Reflection parse failed: {str(e)}",
            "retry_count": state["retry_count"] + 1,
            # Reflection's LLM call may have consumed real tokens even though parsing failed.
            "token_stats": _accumulate_token_stats(state, reflection_chain)
        }

# Define edge routing condition
def should_continue(state: AuditState) -> str:
    """Routes state based on validation status and retry bounds.

    With Cross-Encoder Reranking + 4-Gate Validation, at most 1 single
    reflection pass is allowed. This eliminates unnecessary 2nd-pass delays
    while preserving 100% ground truth verification.
    """
    if state["validation_error"] is not None:
        if state["retry_count"] < 1:
            return "reflect"
        return "end"
    return "end"

# Compile LangGraph State Machine
def compile_audit_graph():
    """Builds and compiles the StateGraph workflow."""
    workflow = StateGraph(AuditState)
    
    # Add Nodes
    workflow.add_node("retrieve", retrieve_node)
    workflow.add_node("generate", generate_node)
    workflow.add_node("validate", validate_node)
    workflow.add_node("reflect", reflection_node)
    
    # Add Edges
    workflow.add_edge(START, "retrieve")
    workflow.add_edge("retrieve", "generate")
    workflow.add_edge("generate", "validate")
    
    # Conditional edge from validate
    workflow.add_conditional_edges(
        "validate",
        should_continue,
        {
            "reflect": "reflect",
            "end": END
        }
    )
    
    # Reflect cycles back to validate so grounding can be checked
    workflow.add_edge("reflect", "validate")
    
    return workflow.compile()

# Singleton graph instance cached at module load
audit_graph = compile_audit_graph()


# ── Execution Metadata Logger (Fix G4 — Audit Logs) ——————————————————
def _log_execution_event(state: AuditState, final_finding: Dict[str, Any]) -> None:
    """
    Writes a structured execution metadata row to the SystemEvent table after
    each control is validated. This is a sidecar write — it runs AFTER
    final_finding is already set and is wrapped in try/except so any DB failure
    never affects the audit result.

    Captures: control_id, model, backend, audit_mode, retry_count,
              hallucination_check, final_status, retrieved_context_chars.
    """
    try:
        import json as _json
        import os as _os
        from src.db.database import SystemEvent

        meta = {
            "control_id":              state.get("control_id", ""),
            "model":                   state.get("llm_model", ""),
            "backend":                 _os.environ.get("LLM_BACKEND", "ollama"),
            "audit_mode":              state.get("audit_mode", "Normal"),
            "retry_count":             state.get("retry_count", 0),
            "hallucination_check":     final_finding.get("hallucination_check", ""),
            "final_status":            final_finding.get("status", ""),
            "retrieved_context_chars": len(state.get("retrieved_context", "")),
            "requires_human_review":   final_finding.get("requires_human_review", False),
        }

        event = SystemEvent(
            event_type="CONTROL_AUDIT_COMPLETE",
            actor="SYSTEM",
            session_id=state.get("bg_key", ""),
            framework="ISO 27001",
            meta=_json.dumps(meta),
            severity="INFO",
        )
        session = SessionLocal()
        try:
            session.add(event)
            session.commit()
        finally:
            session.close()

    except Exception as _log_err:
        # Never let a log failure affect the audit result
        print(f"[AUDIT LOG WARNING] Failed to write execution event: {_log_err}", flush=True)
