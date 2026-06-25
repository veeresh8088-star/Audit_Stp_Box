# -*- coding: utf-8 -*-
"""
Audit Graph Module
Implements the LangGraph State Machine for auditing controls.
Integrates custom validators and retrieval with LangChain ChatOllama.
"""

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
    ollama_model: str
    summary_text: str
    
    # State tracking
    retrieved_context: str
    draft_finding: Optional[Dict[str, Any]]
    validation_error: Optional[str]
    retry_count: int
    final_finding: Optional[Dict[str, Any]]

    # Progress reporting
    bg_key: Optional[str]
    control_idx: int
    total_controls: int


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
                "text": f"⚡ Auditing control {idx + 1}/{total}: {state['control_id']} — {phase_text}...",
                "percent": current_pct
            }
    except Exception as e:
        print(f"[PROGRESS UPDATE WARNING] Failed to update progress: {e}", flush=True)

def retrieve_node(state: AuditState) -> Dict[str, Any]:
    """Node: Pulls grounded document segments relevant to the target control."""
    _update_progress(state, "Retrieving document context", 0.1)
    controls_batch = [{
        "control": state["control_id"],
        "label": state["control_label"],
        "expected": state["expected_evidence"],
        "prompt_hint": state["prompt_hint"]
    }]
    
    condensed, _, _ = _retrieve_rag_context(
        context=state["document_text"],
        controls_batch=controls_batch,
        file_names_list=state["file_names_list"],
        ollama_model=state["ollama_model"],
        KEYWORD_SYNONYMS=KEYWORD_SYNONYMS
    )
    
    return {"retrieved_context": condensed}

def generate_node(state: AuditState) -> Dict[str, Any]:
    """Node: Calls ChatOllama to generate the initial finding draft based on context."""
    _update_progress(state, "Drafting compliance finding", 0.3)
    from src.ai.knowledge_loop import get_auditor_feedback_few_shot as _get_auditor_feedback_few_shot
    
    feedback_block = _get_auditor_feedback_few_shot([state["control_id"]])
    feedback_section = f"\nAUDITOR KNOWLEDGE LOOP GUIDELINES:\n{feedback_block}\n" if feedback_block else ""
    
    generator_chain = get_generator_chain(state["ollama_model"])
    
    try:
        draft = generator_chain.invoke({
            "summary_text": state["summary_text"],
            "condensed_context": state["retrieved_context"],
            "control_id": state["control_id"],
            "control_label": state["control_label"],
            "expected_evidence": state["expected_evidence"],
            "feedback_section": feedback_section
        })
        
        return {
            "draft_finding": draft.model_dump(),
            "validation_error": None
        }
    except Exception as e:
        print(f"[LANGGRAPH GENERATOR ERROR] Schema parsing failed for control {state['control_id']}: {e}", flush=True)
        return {
            "draft_finding": None,
            "validation_error": f"Schema parsing/validation failed: {str(e)}"
        }

def validate_node(state: AuditState) -> Dict[str, Any]:
    """Node: Validates finding grounding, prompt leakage, and alignment consistency."""
    _update_progress(state, "Validating cited evidence", 0.7)
    draft = state["draft_finding"]
    
    if not draft:
        if state["retry_count"] >= 2:
            print(f"[LANGGRAPH] Hard retry limit reached for control {state['control_id']}. Routing to final save.", flush=True)
            fallback = {
                "status": "HUMAN_REVIEW",
                "requires_human_review": True,
                "requires_review": True,
                "review_note": f"Failed self-correction: {state['validation_error']}",
                "control_id": state["control_id"],
                "control": state["control_label"],
                "severity": "P3 Medium",
                "evidence_quote": "NOT_FOUND",
                "evidence_snippet": "",
                "finding": f"Self-correction loop failed for control {state['control_id']}. Verification required.",
                "gap_description": f"Self-correction loop failed for control {state['control_id']}. Verification required.",
                "reasoning": f"Graph execution failed: {state['validation_error']}",
                "recommendation": state.get("recommendation") or f"Review policies and verify implementation for {state['control_id']}."
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
        
        if state["retry_count"] >= 2:
            print(f"[LANGGRAPH VALIDATOR] Hard retry limit reached for control {state['control_id']}. Routing to final save.", flush=True)
            validated_finding["status"] = "HUMAN_REVIEW"
            validated_finding["requires_human_review"] = True
            validated_finding["requires_review"] = True
            validated_finding["review_note"] = f"Failed self-correction: {error_msg}"
            return {
                "validation_error": None,
                "final_finding": validated_finding
            }
            
        print(f"[LANGGRAPH VALIDATOR] Validation rejected for control {state['control_id']}: {error_msg}", flush=True)
        return {
            "validation_error": error_msg,
            "draft_finding": validated_finding, # Keep the updated validator state (e.g. requires_review=True)
            "final_finding": None
        }
    
    # If validation passes cleanly
    print(f"[LANGGRAPH VALIDATOR] Validation passed for control {state['control_id']} (status: {status})", flush=True)
    return {
        "validation_error": None,
        "final_finding": validated_finding
    }

def reflection_node(state: AuditState) -> Dict[str, Any]:
    """Node: Skeptical reflection chain to correct any validation errors."""
    _update_progress(state, "Correcting validation gaps", 0.85)
    print(f"[LANGGRAPH REFLECTION] Initiating correction pass for control {state['control_id']}. Iteration: {state['retry_count'] + 1}", flush=True)
    
    reflection_chain = get_reflection_chain(state["ollama_model"])
    draft = state["draft_finding"] or {}
    
    try:
        refined = reflection_chain.invoke({
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
            "validation_error": state["validation_error"]
        })
        
        return {
            "draft_finding": refined.model_dump(),
            "validation_error": None,
            "retry_count": state["retry_count"] + 1
        }
    except Exception as e:
        print(f"[LANGGRAPH REFLECTION ERROR] Self-correction call failed: {e}", flush=True)
        return {
            "validation_error": f"Reflection parse failed: {str(e)}",
            "retry_count": state["retry_count"] + 1
        }

# Define edge routing condition
def should_continue(state: AuditState) -> str:
    """Routes state based on validation status and retry bounds."""
    if state["validation_error"] is not None:
        return "reflect"
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
