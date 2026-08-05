import os
import io
import sys
import time
import json
import uuid
import threading
from datetime import datetime, timezone
from src.db.database import (
    SessionLocal,
    User,
    AuditReport,
    EvidenceFile,
    Finding,
    ComplianceScore,
    AuditCheckpoint,
    AuditTrail,
    SystemEvent,
    force_master,
    get_all_custom_controls
)

def log_system_event(event_type, severity, details, session_id=None, actor="rk1@gmail.com"):
    """Logs an audit error/warning/event into SystemEvent for the Privacy-Safe System Log Trail."""
    try:
        with force_master():
            db = SessionLocal()
            db.add(SystemEvent(
                event_type=event_type,
                severity=severity,
                actor=actor or "Auditor",
                session_id=session_id or "System",
                meta=details
            ))
            db.commit()
            db.close()
    except Exception as _e:
        print(f"[SYSTEM EVENT LOG ERROR] {_e}", flush=True)
from src.core.controls_data import USE_CASES
from src.core.input_guardrail import scan_file_security
from src.core.parsers.doc_parsers import extract_text
from src.core.retrieval import save_document_chunks
from src.core.bg_state import _bg_store, _bg_results, _bg_running, _bg_lock, _bg_stop_flags
from src.ai.audit_graph import audit_graph
from src.core.token_tracker import record_token_metrics

_CUSTOM_USE_CASES_CACHE = []
_CUSTOM_UC_CACHE_TS = 0
BACKEND_NAME = "Ollama"

# ── GLOBAL TOPIC → ISO CONTROL MAPPING TABLE ─────────────────────────────
TOPIC_CONTROL_MAP = {
    # Authentication & Identity
    "multi-factor authentication": ["8.5", "5.17", "5.16"],
    "mfa": ["8.5", "5.17"], "otp": ["8.5", "5.17"], "2fa": ["8.5", "5.17"],
    "two-factor": ["8.5", "5.17"], "password": ["8.5", "5.17"],
    "authentication": ["8.5", "5.17", "5.15"], "authentication process": ["8.5", "5.17"],
    "authentication information": ["5.17"], "identity management": ["5.16", "5.15"],
    "iam": ["5.16", "5.15", "8.2", "5.18"], "idam": ["5.16", "5.15", "8.2", "5.18"],
    "single sign-on": ["8.5", "5.16"], "sso": ["8.5", "5.16"],
    # Privileged Access / PAM
    "privileged access": ["8.2", "5.15", "5.18"], "pam": ["8.2", "5.15", "5.18"],
    "pim": ["8.2", "5.15"], "admin access": ["8.2", "5.18"],
    "root access": ["8.2", "5.18"], "role based access": ["5.15", "5.18", "8.2"],
    "rbac": ["5.15", "5.18"], "access rights": ["5.18", "5.15"],
    "access control": ["5.15", "5.18", "8.3"], "access management": ["5.15", "5.18"],
    # Monitoring & Logging
    "monitoring": ["8.16", "7.4", "5.22"], "cloudwatch": ["8.16", "7.4"],
    "aws cloudwatch": ["8.16", "7.4", "5.23"], "cloud monitoring": ["8.16", "5.23", "5.22", "7.4"],
    "siem": ["8.16", "8.15"], "alerting": ["8.16", "5.25"],
    "logging": ["8.15", "8.16", "5.28"], "log management": ["8.15", "5.28"],
    "log archival": ["8.15", "5.28"], "log archive": ["8.15", "5.28"],
    "archived log": ["8.15", "5.28"], "audit log": ["8.15", "5.28"],
    "prod log": ["8.15", "5.28"], "syslog": ["8.15"], "event logs": ["8.15"],
    "collection of evidence": ["5.28"], "evidence collection": ["5.28"],
    # NTP / Clock
    "ntp": ["8.17"], "ntp server": ["8.17"], "clock synchronization": ["8.17"],
    "clock sync": ["8.17"], "ntp clock sync": ["8.17"],
    "time sync": ["8.17"], "time server": ["8.17"], "timestamp": ["8.17"],
    # Cloud Services
    "cloud": ["5.23", "8.16"], "aws": ["5.23", "8.16"], "azure": ["5.23"], "gcp": ["5.23"],
    "cloud services": ["5.23"], "cloud security": ["5.23"],
    # Network Security
    "network security": ["8.20", "8.21", "8.22"], "firewall": ["8.20", "VAPT-13"],
    "network segmentation": ["8.22", "VAPT-13"], "vpn": ["6.7", "8.20"],
    "remote working": ["6.7"], "remote access": ["6.7", "8.20"],
    # Vulnerability & Patch
    "vulnerability": ["8.8", "VAPT-11"], "patch": ["VAPT-12", "8.8"],
    "patch management": ["VAPT-12", "8.8"], "vulnerability scan": ["8.8", "VAPT-3"],
    "penetration test": ["VAPT-5", "VAPT-6", "8.29"],
    "pentest": ["VAPT-5", "VAPT-6"], "vapt": ["VAPT-5", "VAPT-6", "8.29"],
    # Operations & Procedures
    "operating procedures": ["5.37"], "documented procedures": ["5.37"],
    "sop": ["5.37"], "operational procedure": ["5.37"],
    "standard operating procedure": ["5.37"],
    # Business Continuity
    "business continuity": ["5.29", "5.30"], "bcp": ["5.29", "5.30"],
    "disaster recovery": ["5.29", "5.30"], "dr": ["5.29", "5.30"],
    "backup": ["8.13"], "data backup": ["8.13"], "backup policy": ["8.13"],
    # HR & Personnel
    "hr security": ["5.1", "5.37"], "background check": ["5.1"],
    "screening": ["5.1"], "onboarding": ["5.1"], "offboarding": ["5.1"],
    "terms of employment": ["5.1"],
    # Physical Security
    "physical security": ["7.1", "7.2", "7.4"], "visitor": ["7.2"],
    "visitor log": ["7.2"], "cctv": ["7.4"], "badge": ["7.2"],
    "physical access": ["7.1", "7.2"],
    # Supplier / Vendor
    "supplier": ["5.19", "5.21", "5.22"], "vendor": ["5.19", "5.21", "5.22"],
    "third party": ["5.19", "5.22"], "supplier security": ["5.19", "5.21", "5.22"],
    # Application & Software
    "software development": ["8.25", "8.28"], "sdlc": ["8.25", "8.28"],
    "secure coding": ["8.28"], "code review": ["8.28"],
    "api security": ["8.26"], "fraud analytics": ["8.26"],
    # Cryptography & Key Management
    "encryption": ["8.24"], "cryptography": ["8.24"],
    "kms": ["8.24"], "ssl": ["8.24"], "tls": ["8.24"], "key management": ["8.24"],
    # Incident & Risk
    "incident": ["5.24", "5.25", "5.26"], "incident response": ["5.24", "5.25"],
    "security incident": ["5.24"], "incident management": ["5.24", "5.25"],
    "risk assessment": ["5.12"], "risk management": ["5.12"], "risk": ["5.12"]
}

def log_dev_latency(message: str):
    """Appends performance and execution log entries for developer latency tracking."""
    try:
        os.makedirs("data", exist_ok=True)
        with open("data/audit_run_latency.log", "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")
    except Exception:
        pass

def _resolve_ollama_model(model_choice):
    """Map UI model name to Ollama model identifier."""
    MODEL_MAP = {
        "Gemma 4 (e4b)": "gemma4:e4b",
        "Gemma 4 (2b)": "gemma-2-2b-it",
    }
    if model_choice in MODEL_MAP:
        return MODEL_MAP[model_choice]
    if "12B" in model_choice:
        return "gemma4:12b"
    if "e4b" in model_choice or "4B" in model_choice:
        return "gemma4:e4b"
    if "Gemma" in model_choice or "9B" in model_choice or "2B" in model_choice:
        return "gemma2:9b"
    return "qwen2.5:7b"

def _load_custom_use_cases(force: bool = False) -> list:
    global _CUSTOM_USE_CASES_CACHE, _CUSTOM_UC_CACHE_TS
    now = time.time()
    if not force and (now - _CUSTOM_UC_CACHE_TS) < 60 and _CUSTOM_USE_CASES_CACHE:
        return _CUSTOM_USE_CASES_CACHE

    try:
        rows = get_all_custom_controls(active_only=True)
    except Exception:
        return []

    custom_ucs = []
    for idx, row in enumerate(rows):
        sl = 10000 + idx
        name = row["control_name"]
        cid = row["control_id"]
        desc = row["description"] or name
        cat = row["category"]
        kws = ", ".join(row["keywords"]) if row["keywords"] else name

        custom_ucs.append({
            "sl": sl,
            "standard": "Custom",
            "category": f"Custom — {cat}",
            "label": f"{name} ({cid}) [Custom]",
            "icon": "🔧",
            "use_case": name,
            "expected": f"Evidence of compliance with {name}. {desc}",
            "format": "PDF",
            "prompt_hint": (
                f"Verify compliance against the custom control: {name} ({cid}). "
                f"Category: {cat}. "
                f"Description: {desc}. "
                f"Relevant keywords: {kws}. "
                f"Check whether the uploaded documents demonstrate that this control "
                f"has been implemented, documented, and is being followed."
            ),
            "scope_tags": [cat],
            "severity": "MEDIUM",
            "finding": f"No documented evidence found for custom control {cid} ({name}).",
            "recommendation": (
                f"Establish, document, and implement procedures to satisfy "
                f"the custom control {cid} ({name})."
            ),
            "_is_custom": True,
        })

    _CUSTOM_USE_CASES_CACHE = custom_ucs
    _CUSTOM_UC_CACHE_TS = now
    return custom_ucs

def _get_expected_evidence(uc, custom_evidence=None):
    if custom_evidence is not None:
        return custom_evidence.get(uc["use_case"], uc["expected"])
    return uc["expected"]

def _build_controls_for_audit(selected_sls=None, custom_evidence=None):
    all_ucs = list(USE_CASES) + _load_custom_use_cases()
    controls = []
    for uc in all_ucs:
        if selected_sls is None or uc["sl"] in selected_sls:
            controls.append({
                "control": uc["use_case"],
                "label": uc["label"],
                "expected": _get_expected_evidence(uc, custom_evidence),
                "prompt_hint": uc["prompt_hint"],
                "severity": uc.get("severity", "MEDIUM"),
                "standard": uc.get("standard", ""),
                "recommendation": uc.get("recommendation", ""),
            })
    return controls

def get_num_ctx(model_name: str) -> int:
    name = model_name.lower()
    if "12b" in name:
        return 6144
    if any(x in name for x in ["7b", "8b", "9b", "27b"]):
        return 8192
    if "3b" in name or "e4b" in name:
        return 4096
    return 4096

def _generate_context_summary(context, ollama_model):
    """Generates a brief document scope summary using the configured LLM backend.
    Routes through query_llm() so it correctly uses llama.cpp or Ollama.
    Hard timeout of 15s — skips gracefully if LLM is unresponsive."""
    import re
    files = re.split(r'--- FILE: (.*?) ---', context)
    sample_text = ""
    if len(files) > 1:
        for idx in range(1, len(files), 2):
            fname = files[idx]
            fcontent = files[idx+1] if idx+1 < len(files) else ""
            sample_text += f"FILE: {fname}\n{fcontent.strip()[:1000]}\n\n"
    else:
        sample_text = context[:8000]

    sample_text = sample_text[:8000]   # Keep prompt short for fast response

    summary_prompt = f"""You are a forensic compliance auditor assistant.
Analyze the following document beginning text and extract its overall scope:
1. What is the main purpose of this document?
2. What are the key topics it covers?
3. What does it explicitly state it does NOT cover (exclusions)?

Keep your response brief, under 150 words.

--- START DOCUMENT TEXT ---
{sample_text}
--- END DOCUMENT TEXT ---

Output:"""

    try:
        from src.core.llm_client import query_llm
        # Use query_llm which correctly routes to llama.cpp or Ollama
        summary = query_llm(
            prompt=summary_prompt,
            model=ollama_model,
            num_ctx=get_num_ctx(ollama_model),
            temperature=0.0,
            timeout=15     # Hard 15s cap — skip gracefully if model is cold
        )
        return summary if summary.strip() else "Document scope summary unavailable."
    except Exception as e:
        print(f"[CONTEXT SUMMARY] Skipped (LLM unavailable or timeout): {e}", flush=True)
        return "Document scope summary unavailable (LLM not ready)."

def _checkpoint_create(session_id, bg_key, ai_model, selected_sls, file_names, context_str, total_controls, batch_size):
    with force_master():
        db = SessionLocal()
        try:
            db.query(AuditCheckpoint).filter(
                AuditCheckpoint.status.in_(["in_progress", "failed"])
            ).update({AuditCheckpoint.status: "discarded"}, synchronize_session=False)

            db.query(AuditCheckpoint).filter(
                AuditCheckpoint.session_id == session_id
            ).delete(synchronize_session=False)

            chk = AuditCheckpoint(
                session_id=session_id,
                bg_key=bg_key,
                ai_model=ai_model,
                selected_sls_json=json.dumps(list(selected_sls)),
                file_names_json=json.dumps(file_names),
                context_text=context_str,
                total_controls=total_controls,
                completed_batches=0,
                batch_size=batch_size,
                partial_results_json="[]",
                status="in_progress",
            )
            db.add(chk)
            db.commit()
            chk_id = chk.id
            return chk_id
        except Exception as e:
            print(f"[checkpoint] Failed to create checkpoint: {e}", flush=True)
            return None
        finally:
            db.close()

def _checkpoint_update(session_id, completed_batches, all_results_so_far):
    with force_master():
        db = SessionLocal()
        try:
            chk = db.query(AuditCheckpoint).filter(
                AuditCheckpoint.session_id == session_id,
                AuditCheckpoint.status == "in_progress"
            ).first()
            if chk:
                chk.completed_batches = completed_batches
                chk.partial_results_json = json.dumps(all_results_so_far)
                chk.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
                db.commit()
        except Exception as e:
            print(f"[checkpoint] Failed to update checkpoint: {e}", flush=True)
        finally:
            db.close()

def _checkpoint_finish(session_id, status="completed"):
    with force_master():
        db = SessionLocal()
        try:
            chk = db.query(AuditCheckpoint).filter(
                AuditCheckpoint.session_id == session_id,
                AuditCheckpoint.status.in_(["in_progress", "failed"])
            ).first()
            if chk:
                chk.status = status
                chk.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
                db.commit()
        except Exception as e:
            print(f"[checkpoint] Failed to finish checkpoint: {e}", flush=True)
        finally:
            db.close()

def get_resumable_checkpoint(session_id):
    db = SessionLocal()
    try:
        return db.query(AuditCheckpoint).filter(
            AuditCheckpoint.session_id == session_id,
            AuditCheckpoint.status.in_(["in_progress", "failed"])
        ).order_by(AuditCheckpoint.created_at.desc()).first()
    except Exception as e:
        print(f"[checkpoint] Failed to get checkpoint: {e}", flush=True)
        return None
    finally:
        db.close()

def get_global_resumable_checkpoint():
    db = SessionLocal()
    try:
        return db.query(AuditCheckpoint).filter(
            AuditCheckpoint.status.in_(["in_progress", "failed"])
        ).order_by(AuditCheckpoint.created_at.desc()).first()
    except Exception as e:
        print(f"[checkpoint] Failed to get global checkpoint: {e}", flush=True)
        return None
    finally:
        db.close()

def generate_ollama_findings(context, file_names_list, selected_sls, model_choice, bg_key=None, batch_size=None, checkpoint_session_id=None, audit_mode="Deep", custom_docs=None, custom_evidence=None, file_registry=None):
    os.environ["RAG_RERANK_MODE"] = "quick" if "quick" in str(audit_mode).lower() else "deep"
    ollama_model = _resolve_ollama_model(model_choice)
    controls = _build_controls_for_audit(selected_sls, custom_evidence)
    scanned_files_str = ", ".join(file_names_list) if file_names_list else "None"

    # ── SCOPING MODE DETERMINATION & ISOLATION ─────────────────────────────
    # Mode 1: EXCEL UPLOAD SCOPE (custom_evidence provided from uploaded Excel checklist)
    # Mode 2: CUSTOM / MANUAL SCOPE (user manually selected specific subset of controls < 30)
    # Mode 3: AI AUTO-SCOPING (full control pool scan; runs Evidence-First topic pre-filter)
    is_excel_scope = custom_evidence is not None
    is_manual_scope = (selected_sls is not None and len(selected_sls) < 30)

    is_auto_scoping = (not is_excel_scope) and (not is_manual_scope) and (
        "auto" in str(audit_mode).lower() or 
        "scope" in str(audit_mode).lower() or 
        selected_sls is None or 
        len(controls) >= 30
    )

    filtered_controls = []
    out_of_scope_results = []

    if is_auto_scoping:
        import re
        from src.core.llm_client import query_llm

        def _extract_topics_llm(file_names_list, context_text):
            """Extract security topics from evidence using LLM (file names + per-file snippets)."""
            file_summaries = []
            chunks = context_text.split("\n\n") if context_text else []
            fnames = file_names_list or []
            for i, fname in enumerate(fnames):
                snippet = (chunks[i][:300] if i < len(chunks) else "").replace("\n", " ").strip()
                file_summaries.append(f"FILE: {fname}\nCONTENT: {snippet}")
            files_block = "\n\n".join(file_summaries) if file_summaries else context_text[:2000]

            prompt = f"""You are a security auditor assistant. Below are evidence files for an ISO 27001 audit.
Extract the specific security topics these files cover.
Rules:
- Return ONLY a JSON array of short topic strings (1-4 words each)
- Cover ALL files listed
- Focus on: authentication, access control, logging, NTP/clock, cloud, backup, encryption, fraud, monitoring
- Maximum 20 topics, no duplicates
- No explanation, just the JSON array

Evidence Files:
{files_block}

Return format: ["topic1", "topic2", ...]"""

            try:
                response = query_llm(
                    prompt, model=ollama_model, num_ctx=4096, temperature=0.0, timeout=120,
                    stop=["<end_of_turn>", "<eos>", "<|im_end|>", "</s>"]
                )
                if not response:
                    return []
                match = re.search(r'\[.*?\]', response, re.DOTALL)
                if match:
                    topics = __import__("json").loads(match.group())
                    return [t.lower().strip() for t in topics if isinstance(t, str)]
                lines = [l.strip().strip('"\'').strip('-').strip() for l in response.splitlines() if l.strip()]
                return [l.lower() for l in lines if 2 < len(l) < 60 and not l.startswith('{')]
            except Exception as e:
                print(f"[AI AUTO-SCOPE] LLM topic extraction failed: {e}", flush=True)
                return []

        def _ctrl_prefix(ctrl_str):
            parts = ctrl_str.strip().split()
            return parts[0] if parts else ctrl_str

        print(f"[AI AUTO-SCOPE] Starting Evidence-First scoping for {len(controls)} controls...", flush=True)
        topics = _extract_topics_llm(file_names_list, context or "")

        if topics:
            print(f"[AI AUTO-SCOPE] LLM extracted topics: {topics}", flush=True)
            matched_ids = set()
            for topic in topics:
                for key, ctrl_ids in TOPIC_CONTROL_MAP.items():
                    if key in topic or topic in key:
                        matched_ids.update(ctrl_ids)

            for c in controls:
                prefix = _ctrl_prefix(c["control"])
                if prefix in matched_ids:
                    filtered_controls.append(c)
                else:
                    out_of_scope_results.append({
                        "control_id": c["control"], "control": c["label"],
                        "relevance_score": 0, "evidence_found": "Not Relevant",
                        "evidence_snippet": "", "status": "Out of Scope", "severity": "N/A",
                        "finding": "Control does not apply to this document scope",
                        "recommendation": "",
                        "reasoning": f"AI Evidence-First Scoping: topics {topics} did not match this control.",
                        "source_files": scanned_files_str,
                    })
            print(f"[AI AUTO-SCOPE] Evidence-First filtered {len(controls)} → {len(filtered_controls)} controls.", flush=True)

            if not filtered_controls:
                print(f"[AI AUTO-SCOPE] WARNING: 0 controls matched map. Running keyword fallback.", flush=True)
                stopwords = {"whether","is","are","the","and","for","with","available","enabled","done","used","audit","evidence","check","system","information","security","management","policies","policy","shall","should","must","will","has","have","been","that","this","also","from","into","their","which","data","user","users","access","control","controls","process","processes","document","documents","record","records","activity","activities","include","including","ensure","required","requirement","requirements","related","relevant","review","reviews","update","updates","implement","implementation","define","defined","maintain","maintained","establish","established","appropriate","effective","internal","external","based","provide","provided","all","each","other","any","not","only","such","may","its","use","organization","asset","assets","risk","risks","measure","measures","protect","protection"}
                full_text = (str(context or "") + " " + " ".join(file_names_list or [])).lower()
                out_of_scope_results = []
                for c in controls:
                    combined = (c.get("label","") + " " + c.get("expected","") + " " + c.get("prompt_hint","")).lower()
                    phrases = re.findall(r'\b[a-z]{5,}(?:\s+[a-z]{4,}){1,3}\b', combined)
                    phrases = [p for p in phrases if not any(w in stopwords for w in p.split())]
                    single_kw = [w for w in set(re.findall(r'\b[a-z]{7,}\b', combined)) if w not in stopwords]
                    score = sum(3 for p in phrases if p in full_text) + sum(1 for w in single_kw if w in full_text)
                    if score >= 3:
                        filtered_controls.append(c)
                    else:
                        out_of_scope_results.append({
                            "control_id": c["control"], "control": c["label"],
                            "relevance_score": score, "evidence_found": "Not Relevant",
                            "evidence_snippet": "", "status": "Out of Scope", "severity": "N/A",
                            "finding": "Control does not apply to this document scope",
                            "recommendation": "",
                            "reasoning": f"Safety net keyword fallback: score {score} < 3.",
                            "source_files": scanned_files_str,
                        })
                print(f"[AI AUTO-SCOPE] Safety net keyword: {len(filtered_controls)} controls matched.", flush=True)
        else:
            print(f"[AI AUTO-SCOPE] LLM unavailable — using keyword fallback.", flush=True)
            import re
            stopwords = {"whether","is","are","the","and","for","with","available","enabled","done","used","audit","evidence","check","system","information","security","management","policies","policy","shall","should","must","will","has","have","been","that","this","also","from","into","their","which","data","user","users","access","control","controls","process","processes","document","documents","record","records","activity","activities","include","including","ensure","required","requirement","requirements","related","relevant","review","reviews","update","updates","implement","implementation","define","defined","maintain","maintained","establish","established","appropriate","effective","internal","external","based","provide","provided","all","each","other","any","not","only","such","may","its","use","organization","asset","assets","risk","risks","measure","measures","protect","protection"}
            full_text = (str(context or "") + " " + " ".join(file_names_list or [])).lower()
            for c in controls:
                combined = (c.get("label","") + " " + c.get("expected","") + " " + c.get("prompt_hint","")).lower()
                phrases = re.findall(r'\b[a-z]{5,}(?:\s+[a-z]{4,}){1,3}\b', combined)
                phrases = [p for p in phrases if not any(w in stopwords for w in p.split())]
                single_kw = [w for w in set(re.findall(r'\b[a-z]{7,}\b', combined)) if w not in stopwords]
                score = sum(3 for p in phrases if p in full_text) + sum(1 for w in single_kw if w in full_text)
                if score >= 5:
                    filtered_controls.append(c)
                else:
                    out_of_scope_results.append({
                        "control_id": c["control"], "control": c["label"],
                        "relevance_score": score, "evidence_found": "Not Relevant",
                        "evidence_snippet": "", "status": "Out of Scope", "severity": "N/A",
                        "finding": "Control does not apply to this document scope",
                        "recommendation": "",
                        "reasoning": f"Keyword fallback: score {score} below threshold 5.",
                        "source_files": scanned_files_str,
                    })

        if filtered_controls:
            print(f"[AI AUTO-SCOPE] Final: {len(filtered_controls)} controls will be audited by LLM.", flush=True)
            controls = filtered_controls
            all_results = out_of_scope_results
        else:
            print(f"[AI AUTO-SCOPE] ULTIMATE SAFETY NET: All filters returned 0 — auditing ALL {len(controls)} controls.", flush=True)
            all_results = []
    else:
        print(f"[MANUAL/EXCEL SCOPE] Auditing all {len(controls)} controls selected by user/Excel checklist without auto-scoping pre-filter.", flush=True)
        all_results = []





    if not controls:
        all_results = []
        for uc in USE_CASES:
            all_results.append({
                "control_id": uc["use_case"],
                "control": uc["label"],
                "relevance_score": 0,
                "evidence_found": "Not Relevant",
                "evidence_snippet": "",
                "status": "Out of Scope",
                "severity": "N/A",
                "finding": "Control does not apply to this document type",
                "recommendation": "",
                "reasoning": "Control is out of scope for the detected document type.",
                "source_files": scanned_files_str,
            })
        return [], all_results

    all_results = []
    total = len(controls)
    overall_start_time = time.time()
    
    msg = f"[AUDIT START] Starting LangGraph ISO 27001 Audit for {total} controls (Model: {model_choice}, Mode: {audit_mode})"
    print(f"\n[{time.strftime('%H:%M:%S')}] {msg}", flush=True)
    log_dev_latency(msg)

    # Generate context summary
    summary_text = _generate_context_summary(context, ollama_model)

    # ── Universal Pre-Ingest for Top 6 RAG Vector Retrieval across ALL Scoping Modes (Manual, AI Auto-Scoping, Excel) ──
    if file_registry:
        for fname, ftext in file_registry.items():
            if fname and ftext:
                try:
                    save_document_chunks(fname, ftext)
                except Exception as _e_ingest:
                    print(f"[RAG INGEST WARNING] Pre-ingest for '{fname}' failed: {_e_ingest}", flush=True)

    for idx, c in enumerate(controls):
        # ── STOP FLAG CHECK ─────────────────────────────────────────────
        if _bg_stop_flags.get(bg_key):
            print(f"[AUDIT STOPPED] User requested stop at control {idx + 1}/{total}. Exiting early.", flush=True)
            break
        # ────────────────────────────────────────────────────────────────
        control_start_time = time.time()
        start_msg = f"-> Running Control {idx + 1}/{total}: {c['control']} ({c['label']})"
        print(f"[{time.strftime('%H:%M:%S')}]   {start_msg}", flush=True)
        log_dev_latency(f"[{idx + 1}/{total}] {start_msg}")

        # ── Strict Scoping: 1 control → 1 specific evidence file ─────────────
        # When an Excel scope sheet maps a control to a specific evidence file,
        # ONLY that file (+ shared policy docs) should be audited for that control.
        # This prevents evidence bleed across controls (e.g. MFA screenshots
        # appearing as evidence for Clock Sync or Capacity Management).
        control_context = context
        control_file_names = file_names_list
        target_evidence_files = []   # Track which specific evidence files this control maps to

        target_doc_name = None
        docs_source = custom_docs if custom_docs is not None else {}
        if docs_source and c["control"] in docs_source:
            target_doc_name = docs_source[c["control"]]

        if target_doc_name:
            # Normalise filenames for fuzzy matching (strip extension + punctuation)
            def _norm_fn(s):
                if not s: return ""
                s_no_ext = os.path.splitext(s)[0]
                import re as _re
                return _re.sub(r'[^a-z0-9]', '', s_no_ext.lower())

            # ── Step A: Find which uploaded files are mapped to ANY control in Excel.
            # Unmapped files are shared policy documents that apply to all controls.
            all_mapped_norms = set()
            for mapped_v in docs_source.values():
                all_mapped_norms.add(_norm_fn(mapped_v))

            policy_doc_files = []   # Files not mapped to any control = shared policy docs
            for fname in file_names_list:
                norm_fname = _norm_fn(fname)
                is_any_mapped = any(
                    norm_fname and nm and (norm_fname in nm or nm in norm_fname)
                    for nm in all_mapped_norms
                )
                if not is_any_mapped:
                    policy_doc_files.append(fname)

            # ── Step B: Match the specific evidence file for THIS control.
            norm_target = _norm_fn(target_doc_name)
            matched_files = []
            for fname in file_names_list:
                norm_fname = _norm_fn(fname)
                if norm_target and norm_fname and (norm_target in norm_fname or norm_fname in norm_target):
                    matched_files.append(fname)

            reg_source = file_registry if file_registry is not None else {}

            if matched_files:
                # PRIMARY context: ONLY the evidence file mapped to this control.
                matched_texts = [reg_source.get(fname, "") for fname in matched_files if reg_source.get(fname)]
                # SECONDARY context: shared policy documents (not evidence-mapped to any control)
                # e.g. an ISO policy.docx uploaded alongside evidence screenshots.
                policy_texts = [reg_source.get(f, "") for f in policy_doc_files if reg_source.get(f)]
                all_context_parts = matched_texts + policy_texts
                if all_context_parts:
                    control_context = "\n\n".join(all_context_parts)
                # STRICT: RAG searches ONLY the matched evidence file + policy docs.
                # This guarantees that e.g. NTP screenshots are never searched for MFA controls.
                control_file_names = matched_files + policy_doc_files
                target_evidence_files = matched_files   # Used for source_files provenance below
                print(
                    f"[SCOPING] Control {c['control']}: "
                    f"Evidence={matched_files}, Policy docs={policy_doc_files}, "
                    f"RAG pool={len(control_file_names)} files (strict — no bleed)",
                    flush=True
                )
            else:
                # Mapped file not found among uploads — fall back to all files.
                print(
                    f"[SCOPING WARNING] Control {c['control']}: Target '{target_doc_name}' "
                    f"not matched among uploads {file_names_list}. "
                    f"Falling back to full evidence pool.",
                    flush=True
                )
                control_file_names = file_names_list
                control_context = context

        # If no Excel scoping for this control, use all uploaded files (unchanged).

        # Assemble graph inputs mapping exactly to LangGraph AuditState schema
        state_input = {
            "control_id": c["control"],
            "control_label": c["label"],
            "expected_evidence": c["expected"],
            "prompt_hint": c["prompt_hint"],
            "severity": c["severity"],
            "standard": c.get("standard", "ISO 27001:2022"),
            "recommendation": c.get("recommendation", ""),
            
            # Context & Config
            "document_text": control_context,
            "file_names_list": control_file_names,
            "ollama_model": ollama_model,
            "summary_text": summary_text,
            
            # State tracking
            "retrieved_context": "",
            "draft_finding": None,
            "validation_error": None,
            "retry_count": 0,
            "final_finding": None,
            
            # Progress tracking
            "bg_key": bg_key,
            "control_idx": idx,
            "total_controls": total,
            "audit_mode": audit_mode,
            "file_registry": file_registry or {}
        }
        
        try:
            # Invoke LangGraph
            state_output = audit_graph.invoke(state_input)
            result = state_output.get("final_finding")
            if result:
                # ── Evidence provenance fix ───────────────────────────────────────
                # Validator sets source_files only when grounding succeeds (quote found).
                # If validator did not set it (e.g. NOT_GROUNDED), fall back to the
                # specific evidence file targeted for this control, NOT all 8 files.
                # This ensures Evidence Source Location always shows 1 accurate file.
                existing_src = result.get("source_files") or ""
                if not existing_src.strip():
                    if target_evidence_files:
                        result["source_files"] = ", ".join(target_evidence_files)
                    else:
                        # No Excel scoping: leave empty — don't dump all filenames
                        result["source_files"] = ""
                all_results.append(result)
            ctrl_duration = time.time() - control_start_time
            res_status = result.get("status", "Unknown") if result else "None"
            
            c_mins = int(ctrl_duration // 60)
            c_secs = round(ctrl_duration % 60, 1)
            c_lat_str = f"{c_mins}m {c_secs}s" if c_mins > 0 else f"0m {c_secs}s"

            ctrl_p_toks = int(len(str(control_context or "")) / 3.8) + 650
            ctrl_c_toks = int(len(str(result.get("reasoning", "") if result else "")) / 3.8) + 120
            ctrl_t_toks = ctrl_p_toks + ctrl_c_toks

            print(f"[{time.strftime('%H:%M:%S')}] ⚡ [CONTROL EVALUATED] {c['control']} ({c['label']}) | Status: {res_status} | Latency: {c_lat_str} ({ctrl_duration:.1f}s) | Tokens Used: {ctrl_t_toks:,} (Prompt: {ctrl_p_toks:,}, Completion: {ctrl_c_toks:,})", flush=True)
            log_dev_latency(f"[{idx + 1}/{total}] [SUCCESS] Control {c['control']} {c['label']} completed in {ctrl_duration:.2f}s ({c_lat_str}) | Tokens: {ctrl_t_toks:,}")
        except Exception as e:
            print(f"[AUDIT ERROR] Error evaluating control {c['control']}: {e}", flush=True)
            log_dev_latency(f"ERROR: Control {c['control']} failed: {e}")

        # Update progress and checkpoint periodically
        if bg_key:
            pct = int(((idx + 1) / total) * 100)
            with _bg_lock:
                _bg_store["progress"][bg_key] = {
                    "text": f"Scanning: {idx + 1}/{total} controls...",
                    "percent": pct
                }
        if checkpoint_session_id and batch_size and (idx + 1) % batch_size == 0:
            completed_batches = (idx + 1) // batch_size
            _checkpoint_update(checkpoint_session_id, completed_batches, all_results)

    resolved_list = [r["control_id"] for r in all_results if (r.get("status") or "").upper() in ("COMPLIANT", "ACCEPTED", "PASS")]
    findings_list = [r for r in all_results if (r.get("status") or "").upper() not in ("COMPLIANT", "ACCEPTED", "PASS")]
    
    total_audit_time = time.time() - overall_start_time
    tot_mins = int(total_audit_time // 60)
    tot_secs = round(total_audit_time % 60, 1)
    tot_lat_str = f"{tot_mins}m {tot_secs}s" if tot_mins > 0 else f"0m {tot_secs}s"

    end_msg = f"[AUDIT COMPLETE] Evaluated {total} controls in {tot_lat_str} ({total_audit_time:.1f}s). Compliant: {len(resolved_list)}, Gaps: {len(findings_list)}"
    print(f"[{time.strftime('%H:%M:%S')}] {end_msg}\n", flush=True)
    log_dev_latency(end_msg)

    # Record benchmark metrics for Excel tracker & Terminal Summary Box
    try:
        from src.core.token_tracker import record_token_metrics
        text_chars = len(str(context or ""))
        total_file_bytes = 0
        file_details = []
        file_types_summary = {}

        if file_registry:
            for fname, fmeta in file_registry.items():
                sz = 0
                txt_c = 0
                if isinstance(fmeta, dict):
                    sz = fmeta.get("size_bytes", 0)
                    txt_c = len(fmeta.get("text", ""))
                elif isinstance(fmeta, str):
                    txt_c = len(fmeta)
                    sz = max(512, txt_c * 2)

                total_file_bytes += sz
                ext = os.path.splitext(str(fname))[1].lower().replace('.', '') or 'doc'
                file_types_summary[ext] = file_types_summary.get(ext, 0) + 1
                file_details.append({
                    "name": fname,
                    "ext": ext,
                    "size_bytes": sz,
                    "size_kb": round(sz / 1024, 1),
                    "char_count": txt_c
                })

        if not file_types_summary and file_names_list:
            for fn in file_names_list:
                ext = os.path.splitext(str(fn))[1].lower().replace('.', '') or 'doc'
                file_types_summary[ext] = file_types_summary.get(ext, 0) + 1

        if total_file_bytes == 0:
            total_file_bytes = max(1024, text_chars * 2)

        cpu_cores_cnt = os.cpu_count() or 4

        prompt_toks = int(text_chars / 3.8) + (total * 800)
        comp_toks = total * 175
        tot_tokens_all = prompt_toks + comp_toks
        avg_tokens_ctrl = round(tot_tokens_all / max(1, total), 1)

        avg_lat_sec = total_audit_time / max(1, total)
        avg_mins = int(avg_lat_sec // 60)
        avg_secs = round(avg_lat_sec % 60, 1)
        avg_lat_str = f"{avg_mins}m {avg_secs}s" if avg_mins > 0 else f"0m {avg_secs}s"
        
        mode_str = str(audit_mode).lower()
        if "excel" in mode_str or "manual" in mode_str:
            scoping_label = "Excel / Manual Scoping"
        elif "auto" in mode_str or "quick" in mode_str:
            scoping_label = "AI Auto-Scoping"
        else:
            scoping_label = "Excel / Manual Scoping"

        record_token_metrics(
            session_id=checkpoint_session_id or bg_key or "SESSION-LATEST",
            scoping_mode=scoping_label,
            file_names=file_names_list or ["Uploaded Evidence Documents"],
            total_file_size_bytes=total_file_bytes,
            extracted_text_chars=text_chars,
            controls_count=total,
            prompt_tokens=prompt_toks,
            completion_tokens=comp_toks,
            total_latency_sec=total_audit_time,
            compliant_count=len(resolved_list),
            non_compliant_count=len(findings_list),
            out_of_scope_count=len(out_of_scope_results) if 'out_of_scope_results' in locals() else 0,
            folder_name="Audit Evidence Package",
            cpu_cores=cpu_cores_cnt,
            file_details=file_details,
            file_types_summary=file_types_summary
        )

        total_files_cnt = len(file_names_list) if file_names_list else 0
        file_size_mb = round(total_file_bytes / (1024 * 1024), 2)
        file_size_kb = round(total_file_bytes / 1024, 1)
        total_text_chunks = len([c for c in str(context or "").split("\n\n") if len(c.strip()) > 20])
        if total_text_chunks == 0:
            total_text_chunks = max(1, int(text_chars / 500))

        file_types_str = ", ".join([f"{ext.upper()}: {cnt}" for ext, cnt in file_types_summary.items()]) if file_types_summary else "N/A"
        auditor_user = getattr(locals().get("req", None), "auditor_username", None) or os.environ.get("CURRENT_AUDITOR", "rk1@gmail.com")

        summary_box = f"""====================================================================================
 • Session ID                      : {checkpoint_session_id or bg_key or 'SESSION-LATEST'}
 • Auditor Username                : {auditor_user}
 • Scoping Detection Mode          : {scoping_label}
 • System CPU Hardware Specs       : {cpu_cores_cnt} Logical CPU Cores
 • Total Evidence Files Count      : {total_files_cnt} Files
 • File Extensions Breakdown       : {file_types_str}
 • Total Evidence File Size        : {file_size_mb} MB ({file_size_kb:,} KB)
 • Total Text Chunks Analyzed      : {total_text_chunks} Chunks ({text_chars:,} Chars)
 • Total Controls Evaluated        : {total}
 • Compliant Controls              : {len(resolved_list)}
 • Non-Compliant Gaps              : {len(findings_list)}
 • Prompt Input Tokens             : {prompt_toks:,} Tokens
 • Completion Output Tokens        : {comp_toks:,} Tokens
 • Total Audit Tokens Used         : {tot_tokens_all:,} Tokens
 • Average Tokens per Control      : {avg_tokens_ctrl:,} Tokens/Control
 • Overall Audit Latency           : {tot_lat_str} ({total_audit_time:.1f} seconds)
 • Average Latency per Control     : {avg_lat_str} ({avg_lat_sec:.1f} seconds/control)
====================================================================================
"""
        print("\n" + summary_box, flush=True)
        log_dev_latency(summary_box)

    except Exception as _bm_err:
        print(f"[BENCHMARK ERROR] Failed to record token metrics: {_bm_err}", flush=True)

    return resolved_list, findings_list, all_results

# FIX: Increased default from 2 to 4 concurrent audits.
# With 8 CPU cores and 10 simultaneous users: 4 audits run in parallel,
# remaining 6 queue cleanly and wait instead of being dropped or erroring.
# Override at startup: set env var MAX_CONCURRENT_AUDITS=N
_audit_semaphore = threading.Semaphore(int(os.environ.get("MAX_CONCURRENT_AUDITS", "4")))

def _run_ollama_bg(bg_key, files_data, selected_sls_copy, ai_model, session_id=None, audit_mode="Deep", custom_docs=None, custom_evidence=None, file_registry=None):
    print(f"[_run_ollama_bg] Starting thread for key {bg_key} with model {ai_model}...", flush=True)
    _sid = session_id or bg_key
    acquired_slot = False
    try:
        if not _audit_semaphore.acquire(timeout=0.1):
            print(f"[_run_ollama_bg] Task {bg_key} queued waiting for an available CPU slot...", flush=True)
            with _bg_lock:
                _bg_store["progress"][bg_key] = {
                    "text": "⚡ Initializing Audit Engine...",
                    "percent": 0
                }
            _audit_semaphore.acquire()
        acquired_slot = True

        # ── Pre-flight: verify LLM server is reachable (3s timeout) ──────────
        import os as _os
        import requests as _req
        from src.core.llm_client import get_llm_backend, _resolve_host
        _backend = get_llm_backend()
        _is_llamacpp = _backend in ("llama.cpp", "llamacpp")
        _llm_host = _resolve_host()
        _health_url = f"{_llm_host}/health" if _is_llamacpp else f"{_llm_host}/api/tags"
        try:
            _hr = _req.get(_health_url, timeout=3)
            if _hr.status_code not in (200, 201):
                raise Exception(f"Server returned HTTP {_hr.status_code} on {_health_url}")
            print(f"[_run_ollama_bg] LLM server health check OK ({_health_url}): {_hr.status_code}", flush=True)
        except Exception as _hc_err:
            _backend_label = "llama.cpp" if _is_llamacpp else "Ollama"
            _err_msg = (
                f"Cannot connect to {_backend_label} server at {_llm_host}. "
                "Please start the service before running audits."
            )
            print(f"[_run_ollama_bg ERROR] {_err_msg}", flush=True)
            log_system_event("LLM_OFFLINE_ERROR", "ERROR", _err_msg, session_id=_sid)
            with _bg_lock:
                _bg_store["progress"][bg_key] = {"text": f"Error: {_backend_label} offline", "percent": 0}
            _checkpoint_finish(_sid, "failed")
            return

        print(f"[_run_ollama_bg] Pipeline executing for session {_sid}...", flush=True)
        with _bg_lock:
            _bg_store["progress"][bg_key] = {
                "text": "🔍 Scanning file security...",
                "percent": 0
            }
        ctx = ""
        file_names_list = []
        for f_data in files_data:
            name = f_data["name"]
            file_bytes = f_data["bytes"]
            f_like = io.BytesIO(file_bytes)
            f_like.name = name
            is_clean, reason = scan_file_security(f_like)
            if not is_clean:
                print(f"[_run_ollama_bg] Security alert! Malware scan failed for file {name}: {reason}", flush=True)
                log_system_event("MALWARE_BLOCKED", "CRITICAL", f"File blocked by security scan: {name} ({reason})", session_id=_sid)
                with _bg_lock:
                    _bg_results[bg_key] = {"error": f"🚨 SECURITY ALERT: '{name}' BLOCKED! {reason}"}
                    _bg_store["progress"].pop(bg_key, None)
                _checkpoint_finish(_sid, "failed")
                return

            text = f_data.get("text")
            if not text:
                text = extract_text(f_like)

            ctx += f"--- FILE: {name} ---\n{text}\n\n"
            save_document_chunks(name, text)
            file_names_list.append(name)
        context_str = ctx.strip()

        # Update scanned files to "Reviewing" in database
        try:
            with force_master():
                db_write = SessionLocal()
                db_write.query(EvidenceFile).filter(
                    EvidenceFile.filename.in_(file_names_list)
                ).update({EvidenceFile.status: "Processing"}, synchronize_session=False)
                db_write.commit()
                db_write.close()
        except Exception as e:
            print(f"[PIPELINE] Failed to update active files status to Reviewing: {e}", flush=True)

        _total_ctrl_count = len(selected_sls_copy)
        _batch_sz = 1 if ("7B" in ai_model or "8B" in ai_model or "9B" in ai_model or "Escalation" in ai_model) else 4
        _checkpoint_create(
            _sid, bg_key, ai_model,
            selected_sls_copy, file_names_list, context_str,
            _total_ctrl_count, _batch_sz
        )

        with _bg_lock:
            _bg_store["progress"][bg_key] = {
                "text": f"Scanning controls with {ai_model.split(' - ')[0]}...",
                "percent": 0
            }

        resolved_combined, findings_combined, all_results_combined = generate_ollama_findings(
            context_str, file_names_list, selected_sls_copy, ai_model, bg_key=bg_key,
            checkpoint_session_id=_sid, audit_mode=audit_mode,
            custom_docs=custom_docs, custom_evidence=custom_evidence, file_registry=file_registry
        )

        resolved_mapping = {}
        for ctrl in resolved_combined:
            resolved_mapping[ctrl] = file_names_list
        for finding in findings_combined:
            finding["status"] = finding.get("status", "Non-Compliant")
            finding["comment"] = ""
            finding["editing"] = False
            
        with _bg_lock:
            _bg_results[bg_key] = {
                "findings": findings_combined,
                "resolved_list": resolved_combined,
                "resolved_count": len(resolved_mapping),
                "resolved_controls": set(resolved_mapping.keys()),
                "context": context_str
            }

        # Update scanned files to "Completed" and save results in database
        try:
            with force_master():
                db_write = SessionLocal()
                
                # 1. Update Evidence File statuses
                db_write.query(EvidenceFile).filter(
                    EvidenceFile.filename.in_(file_names_list)
                ).update({EvidenceFile.status: "Completed"}, synchronize_session=False)
                
                # 2. Retrieve report and insert findings
                report = db_write.query(AuditReport).filter(AuditReport.session_id == _sid).first()
                if report:
                    # Clear existing findings for this report
                    db_write.query(Finding).filter(Finding.report_id == report.id).delete()
                    for f in all_results_combined:
                        f_desc = f.get("description") or f.get("finding") or f.get("gap_detected") or f.get("reasoning") or "Evaluated against ISO 27001 / VAPT compliance standards."
                        f_status = f.get("status", "Non-Compliant")
                        is_comp = (f_status or "").upper() in ("COMPLIANT", "ACCEPTED", "PASS")
                        f_recom = f.get("recommendation") or f.get("remediation") or (f"Maintain current documented policies and verification procedures for {f.get('control_id')}." if is_comp else f"Establish formal policy documentation, access controls, and logging evidence for {f.get('control_id')}.")

                        db_write.add(Finding(
                            report_id=report.id,
                            control_id=f.get("control_id"),
                            control_name=f.get("control_label") or f.get("control"),
                            severity="N/A" if is_comp else f.get("severity", "P3 Medium"),
                            description=f_desc,
                            gap_detected=f_desc,
                            relevance_score=f.get("relevance_score", 0),
                            evidence_found=f.get("evidence_found", ""),
                            evidence_snippet=f.get("evidence_snippet", ""),
                            recommendation=f_recom,
                            reasoning=f.get("reasoning") or f_desc or "",
                            status="COMPLIANT" if is_comp else f_status,
                            policy_present=f.get("policy_present") or ("Compliant" if is_comp else "No"),
                            evidence_present=f.get("evidence_present") or ("Compliant" if is_comp else "No"),
                            source_files=f.get("source_files", "")
                        ))
                    
                    # 3. Calculate score and update ComplianceScore
                    db_write.query(ComplianceScore).filter(ComplianceScore.report_id == report.id).delete()
                    in_scope = [f for f in all_results_combined if f.get("status")]
                    compliant = [f for f in in_scope if (f.get("status") or "").upper() in ("COMPLIANT", "ACCEPTED", "PASS")]
                    score_pct = int(len(compliant) / max(len(in_scope), 1) * 100) if in_scope else 0
                    db_write.add(ComplianceScore(
                        report_id=report.id,
                        framework=report.framework,
                        score_percent=score_pct
                    ))
                    
                    report.status = "Pending Review"
                    
                db_write.commit()
                db_write.close()
        except Exception as e:
            print(f"[PIPELINE] Failed to save findings and complete files update: {e}", flush=True)
            
        _checkpoint_finish(_sid, "completed")
    except Exception as e:
        print(f"[_run_ollama_bg] Exception raised in background thread: {str(e)}", flush=True)
        log_system_event("AUDIT_EXCEPTION", "CRITICAL", f"Background audit thread exception: {str(e)}", session_id=_sid)
        with _bg_lock:
            _bg_results[bg_key] = {"error": f"Error contacting {BACKEND_NAME}: {str(e)}"}
        _checkpoint_finish(_sid, "failed")
    finally:
        if acquired_slot:
            _audit_semaphore.release()
        with _bg_lock:
            _bg_running.discard(bg_key)
            _bg_store["progress"].pop(bg_key, None)
            _bg_stop_flags.pop(bg_key, None)  # Clear stop flag on thread exit

def _run_fast_technical_vapt_bg(bg_key, files_data, selected_sls, file_registry=None):
    all_findings = []
    resolved_ctrls = set()
    try:
        from src.core.parsers import parse_tool_file, map_finding_to_control

        for fd in files_data:
            fname = fd.get("name", "")
            ftext = fd.get("text", "")
            fname_lower = fname.lower()
            if fname_lower.endswith((".html", ".htm")) and fd.get("bytes"):
                try:
                    ftext = fd.get("bytes").decode("utf-8", errors="ignore")
                except Exception:
                    pass
            elif not ftext and fd.get("bytes"):
                try:
                    ftext = fd.get("bytes").decode("utf-8", errors="ignore")
                except Exception:
                    ftext = ""

            reg_text = (file_registry or {}).get(fname, "")
            if reg_text and len(reg_text) > len(ftext or ""):
                ftext = reg_text

            actionable, info = parse_tool_file(fname, ftext or "")
            combined_tool_findings = actionable + (info or [])

            for f in combined_tool_findings:
                c_id = map_finding_to_control(f)
                f_dict = f.to_dict() if hasattr(f, "to_dict") else dict(f)
                f_dict["control_id"] = c_id
                f_dict["control"] = f_dict.get("control") or c_id
                f_dict["status"] = "Non-Compliant" if f_dict.get("severity") != "INFO" else "Informational"
                f_dict["display_status"] = "Open"
                f_dict["source_files"] = fname   # Scan FILE name, not host IP
                # ── Build structured evidence snippet (Proof of Concept block) ──
                # This is what auditors see as "Evidence". It must show:
                #   Host/IP, Port, CVE, Plugin Output — not just the Nessus plugin description.
                _target = f_dict.get("target") or ""
                _cves = f_dict.get("cve_list") or []
                _cve_str = ", ".join(_cves) if _cves else "No CVE assigned"
                _plugin_id = f_dict.get("plugin_id") or ""
                _plugin_out = f_dict.get("evidence") or ""   # Raw Plugin Output from scanner
                _tool = f_dict.get("source_tool") or "Scanner"
                # Structured PoC block
                poc_lines = []
                if _target:
                    poc_lines.append(f"Target Host: {_target}")
                if _plugin_id:
                    poc_lines.append(f"Plugin ID:   {_plugin_id}")
                if _cves:
                    poc_lines.append(f"CVE(s):      {_cve_str}")
                poc_lines.append(f"Scanner:     {_tool}")
                if _plugin_out.strip():
                    poc_lines.append(f"Plugin Output:\n{_plugin_out.strip()[:800]}")
                else:
                    poc_lines.append("Plugin Output: Not available in scan report")
                poc_block = "\n".join(poc_lines)
                f_dict["evidence_snippet"] = poc_block
                all_findings.append(f_dict)
                resolved_ctrls.add(c_id)

        # Update database with VAPT findings
        try:
            with force_master():
                db_write = SessionLocal()
                report = db_write.query(AuditReport).filter(AuditReport.session_id == bg_key).first()
                if report:
                    for f in all_findings:
                        db_write.add(Finding(
                            report_id=report.id,
                            control_id=f.get("control_id"),
                            control_name=f.get("title") or f.get("finding") or f.get("control") or f.get("control_id"),
                            severity=f.get("severity", "P3 Medium"),
                            description=f.get("description") or f.get("finding") or "",
                            gap_detected=f.get("finding") or f.get("description") or "",
                            relevance_score=f.get("relevance_score", 0),
                            evidence_found=str(f.get("severity_score", 0.0)),
                            evidence_snippet=f.get("evidence_snippet") or f.get("evidence") or "",
                            recommendation=f.get("remediation") or f.get("recommendation", ""),
                            reasoning=f.get("reasoning", ""),
                            status=f.get("status", "Non-Compliant"),
                            source_files=f.get("source_files", "")  # Now = scan filename, NOT host IP
                        ))
                    
                    # Update Compliance Score
                    db_write.query(ComplianceScore).filter(ComplianceScore.report_id == report.id).delete()
                    in_scope = [f for f in all_findings if f.get("status") in ("Compliant", "Partially Compliant", "Non-Compliant")]
                    compliant = [f for f in in_scope if f.get("status") == "Compliant"]
                    score_pct = int(len(compliant) / max(len(in_scope), 1) * 100) if in_scope else 0
                    db_write.add(ComplianceScore(
                        report_id=report.id,
                        framework=report.framework,
                        score_percent=score_pct
                    ))
                    
                    report.status = "Pending Review"
                    db_write.commit()
                db_write.close()
        except Exception as e:
            print(f"[PIPELINE-VAPT] Failed to write findings: {e}", flush=True)

        with _bg_lock:
            _bg_results[bg_key] = {
                "findings": all_findings,
                "resolved_list": list(resolved_ctrls),
                "resolved_count": len(resolved_ctrls),
                "resolved_controls": resolved_ctrls,
                "error": None,
                "completed": True
            }
        with _bg_lock:
            _bg_running.discard(bg_key)
    except Exception as e:
        with _bg_lock:
            _bg_results[bg_key] = {
                "findings": [],
                "error": str(e),
                "completed": True
            }
        with _bg_lock:
            _bg_running.discard(bg_key)
