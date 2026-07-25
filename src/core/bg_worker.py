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
    force_master,
    get_all_custom_controls
)
from src.core.controls_data import USE_CASES
from src.core.input_guardrail import scan_file_security
from src.core.parsers.doc_parsers import extract_text
from src.core.retrieval import save_document_chunks
from src.core.bg_state import _bg_store, _bg_results, _bg_running, _bg_lock, _bg_stop_flags
from src.ai.audit_graph import audit_graph

_CUSTOM_USE_CASES_CACHE = []
_CUSTOM_UC_CACHE_TS = 0
BACKEND_NAME = "Ollama"

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

def _build_controls_for_audit(selected_sls, custom_evidence=None):
    all_ucs = list(USE_CASES) + _load_custom_use_cases()
    controls = []
    for uc in all_ucs:
        if uc["sl"] in selected_sls:
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

        # Target Document Mapping Integration (excel scope uploader)
        control_context = context
        control_file_names = file_names_list

        target_doc_name = None
        docs_source = custom_docs if custom_docs is not None else {}
        if docs_source and c["control"] in docs_source:
            target_doc_name = docs_source[c["control"]]

        if target_doc_name:
            # Robust normalized matching to check if any uploaded filename matches
            def _norm_fn(s):
                if not s: return ""
                s_no_ext = os.path.splitext(s)[0]
                import re
                return re.sub(r'[^a-z0-9]', '', s_no_ext.lower())

            norm_target = _norm_fn(target_doc_name)
            matched_files = []
            for fname in file_names_list:
                norm_fname = _norm_fn(fname)
                if norm_target and norm_fname and (norm_target in norm_fname or norm_fname in norm_target):
                    matched_files.append(fname)
            if matched_files:
                control_file_names = matched_files
                reg_source = file_registry if file_registry is not None else {}
                matched_texts = [reg_source.get(fname, "") for fname in matched_files if reg_source.get(fname)]
                if matched_texts:
                    control_context = "\n\n".join(matched_texts)

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
                all_results.append(result)
            ctrl_duration = time.time() - control_start_time
            res_status = result.get("status", "Unknown") if result else "None"
            log_dev_latency(f"[{idx + 1}/{total}] [SUCCESS] Control {c['control']} {c['label']} completed in {ctrl_duration:.2f}s (Result: {res_status})")
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

    resolved_list = [r["control_id"] for r in all_results if r.get("status") == "Compliant"]
    findings_list = [r for r in all_results if r.get("status") != "Compliant"]
    
    end_msg = f"[AUDIT COMPLETE] Evaluated {total} controls in {time.time() - overall_start_time:.1f}s. Compliant: {len(resolved_list)}, Gaps: {len(findings_list)}"
    print(f"[{time.strftime('%H:%M:%S')}] {end_msg}\n", flush=True)
    log_dev_latency(end_msg)

    return resolved_list, findings_list, all_results

def _run_ollama_bg(bg_key, files_data, selected_sls_copy, ai_model, session_id=None, audit_mode="Deep", custom_docs=None, custom_evidence=None, file_registry=None):
    print(f"[_run_ollama_bg] Starting thread for key {bg_key} with model {ai_model}...", flush=True)
    _sid = session_id or bg_key
    try:
        # ── Pre-flight: verify LLM server is reachable (3s timeout) ──────────
        import os as _os
        import requests as _req
        _backend = _os.environ.get("LLM_BACKEND", "ollama").strip().lower()
        _is_llamacpp = _backend in ("llama.cpp", "llamacpp")
        _llm_host = _os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").strip()
        if not _llm_host.startswith("http"):
            _llm_host = f"http://{_llm_host}"
        _health_url = f"{_llm_host}/health" if _is_llamacpp else f"{_llm_host}/api/tags"
        try:
            _hr = _req.get(_health_url, timeout=3)
            print(f"[_run_ollama_bg] LLM server health check OK ({_health_url}): {_hr.status_code}", flush=True)
        except Exception as _hc_err:
            _backend_label = "llama.cpp" if _is_llamacpp else "Ollama"
            _err_msg = (
                f"❌ {_backend_label} server is not reachable at {_llm_host}. "
                f"Please start your LLM server and try again. ({_hc_err})"
            )
            print(f"[_run_ollama_bg] Pre-flight FAILED: {_err_msg}", flush=True)
            with _bg_lock:
                _bg_results[bg_key] = {"error": _err_msg}
                _bg_store["progress"].pop(bg_key, None)
            _checkpoint_finish(_sid, "failed")
            return
        # ─────────────────────────────────────────────────────────────────────

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
                ).update({EvidenceFile.status: "Reviewing"}, synchronize_session=False)
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
                "text": f"🤖 Scanning controls with {ai_model.split(' - ')[0]}...",
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
                        db_write.add(Finding(
                            report_id=report.id,
                            control_id=f.get("control_id"),
                            control_name=f.get("control_label") or f.get("control"),
                            severity=f.get("severity", "P3 Medium"),
                            description=f.get("finding", ""),
                            gap_detected=f.get("finding", ""),
                            relevance_score=f.get("relevance_score", 0),
                            evidence_found=f.get("evidence_found", ""),
                            evidence_snippet=f.get("evidence_snippet", ""),
                            recommendation=f.get("recommendation", ""),
                            reasoning=f.get("reasoning", ""),
                            status=f.get("status", "Non-Compliant"),
                            source_files=f.get("source_files", "")
                        ))
                    
                    # 3. Calculate score and update ComplianceScore
                    db_write.query(ComplianceScore).filter(ComplianceScore.report_id == report.id).delete()
                    in_scope = [f for f in all_results_combined if f.get("status") in ("Compliant", "Partially Compliant", "Non-Compliant")]
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
            print(f"[PIPELINE] Failed to save findings and complete files update: {e}", flush=True)
            
        _checkpoint_finish(_sid, "completed")
    except Exception as e:
        print(f"[_run_ollama_bg] Exception raised in background thread: {str(e)}", flush=True)
        with _bg_lock:
            _bg_results[bg_key] = {"error": f"Error contacting {BACKEND_NAME}: {str(e)}"}
        _checkpoint_finish(_sid, "failed")
    finally:
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
                            source_files=f.get("target") or f.get("source_files", "")
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
