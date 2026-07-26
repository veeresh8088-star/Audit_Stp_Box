from fastapi import APIRouter, HTTPException, Query, UploadFile, File, Form
from pydantic import BaseModel
from typing import List, Optional
import os
import io
import uuid
import json
import threading
from datetime import datetime, timezone
from src.db.database import (
    SessionLocal,
    User,
    AuditReport,
    EvidenceFile,
    Finding,
    ComplianceScore,
    ChatMessage,
    AuditCheckpoint,
    DocumentChunk,
    AuditRecord,
    AuditorFeedback,
    force_master
)
from src.core.bg_state import _bg_store, _bg_results, _bg_running, _bg_lock, _bg_stop_flags
from src.core.bg_worker import (
    _run_ollama_bg,
    _run_fast_technical_vapt_bg,
    get_resumable_checkpoint
)
from src.core.input_guardrail import scan_file_security
from src.core.parsers.doc_parsers import extract_text
from src.core.retrieval import save_document_chunks
from src.core.llm_client import query_llm

def retrieve_chat_context(db, session_id: str, query_text: str, top_k: int = 5) -> str:
    """Retrieves pointwise RAG context chunks from ShaktiDB document chunks."""
    report = db.query(AuditReport).filter(AuditReport.session_id == session_id).first()
    if not report:
        return ""
    
    # Get evidence files
    ev_files = db.query(EvidenceFile).filter(EvidenceFile.report_id == report.id).all()
    file_names = [f.filename for f in ev_files]
    if not file_names:
        return ""
        
    # Get chunks
    chunks = db.query(DocumentChunk).filter(DocumentChunk.filename.in_(file_names)).all()
    if not chunks:
        return ""
        
    # Embed query and chunks
    from src.core.llm_client import get_embedding
    query_vector = get_embedding(query_text)
    if not query_vector:
        # Keyword fallback
        scored = []
        q_words = [w.lower() for w in query_text.split() if len(w) > 3]
        for c in chunks:
            c_text = c.content.lower()
            score = sum(1 for w in q_words if w in c_text)
            scored.append((score, c.content))
        scored.sort(key=lambda x: x[0], reverse=True)
        return "\n\n".join([item[1] for item in scored[:top_k]])
        
    from src.core.retrieval import _cosine_similarity, _chunk_embeddings_cache
    scored = []
    for c in chunks:
        chunk_key = (c.filename, c.chunk_index)
        c_vector = _chunk_embeddings_cache.get(chunk_key)
        if not c_vector:
            c_vector = get_embedding(c.content)
            if c_vector:
                _chunk_embeddings_cache[chunk_key] = c_vector
        if c_vector:
            sim = _cosine_similarity(query_vector, c_vector)
            scored.append((sim, c.content))
            
    scored.sort(key=lambda x: x[0], reverse=True)
    return "\n\n".join([item[1] for item in scored[:top_k]])

router = APIRouter(prefix="/audit", tags=["Auditing Operations"])

# --- Request Schemas ---
class StartAuditRequest(BaseModel):
    session_id: str
    selected_sls: List[int]
    model_choice: str
    audit_mode: str = "Deep"
    custom_evidence: Optional[dict] = None
    custom_documents: Optional[dict] = None

class UpdateFindingRequest(BaseModel):
    status: str
    severity: Optional[str] = None
    description: Optional[str] = None
    evidence_snippet: Optional[str] = None
    recommendation: Optional[str] = None
    reasoning: Optional[str] = None
    policy_present: Optional[str] = None
    evidence_present: Optional[str] = None
    comment: Optional[str] = None

class ChatSendRequest(BaseModel):
    session_id: str
    message: str
    model_choice: str
    username: Optional[str] = None  # logged-in user sending this message

# --- Endpoints ---

@router.post("/sessions")
def api_create_session(
    session_title: str = Form(...),
    framework: str = Form("All Standards"),
    username: str = Form("admin")
):
    session_id = uuid.uuid4().hex
    db = SessionLocal()
    try:
        user_row = db.query(User).filter(User.username == username).first()
        user_id = user_row.id if user_row else None
        
        with force_master():
            report = AuditReport(
                session_id=session_id,
                session_title=session_title,
                auditee_id=user_id,
                framework=framework,
                status="Draft"
            )
            db.add(report)
            db.commit()
            return {"success": True, "session_id": session_id, "session_title": session_title}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create session: {e}")
    finally:
        db.close()

@router.get("/sessions")
def api_get_sessions(role: Optional[str] = None, username: Optional[str] = None):
    db = SessionLocal()
    try:
        query = db.query(AuditReport)
        if role == "auditee" and username:
            user = db.query(User).filter(User.username == username).first()
            if user:
                query = query.filter(AuditReport.auditee_id == user.id)
        
        reports = query.order_by(AuditReport.created_at.desc()).all()
        result = []
        for r in reports:
            score_row = db.query(ComplianceScore).filter(ComplianceScore.report_id == r.id).first()
            score_pct = score_row.score_percent if score_row else 0
            findings_count = db.query(Finding).filter(Finding.report_id == r.id).count()
            
            result.append({
                "id": r.id,
                "session_id": r.session_id,
                "session_title": r.session_title,
                "framework": r.framework,
                "status": r.status,
                "score_percent": score_pct,
                "findings_count": findings_count,
                "created_at": str(r.created_at)
            })
        return {"success": True, "sessions": result}
    finally:
        db.close()

@router.post("/upload")
def api_upload_evidence(
    session_id: str = Form(...),
    is_auditor_uploaded: bool = Form(True),
    files: List[UploadFile] = File(...)
):
    db = SessionLocal()
    try:
        report = db.query(AuditReport).filter(AuditReport.session_id == session_id).first()
        if not report:
            raise HTTPException(status_code=404, detail="Active audit session not found.")
        
        uploaded_details = []
        import zipfile
        
        for f in files:
            file_bytes = f.file.read()
            f_like = io.BytesIO(file_bytes)
            f_like.name = f.filename
            
            # Security Scan
            is_clean, reason = scan_file_security(f_like)
            if not is_clean:
                raise HTTPException(
                    status_code=400, 
                    detail=f"🚨 SECURITY ALERT: '{f.filename}' BLOCKED! {reason}"
                )
            
            # Store file on local disk
            ev_dir = os.path.normpath(os.path.join(os.getcwd(), "data", "evidence", str(report.id)))
            os.makedirs(ev_dir, exist_ok=True)
            prefix = "auditor_" if is_auditor_uploaded else "auditee_"
            dest_path = os.path.join(ev_dir, prefix + f.filename)
            
            f_like.seek(0)
            with open(dest_path, "wb") as dest_f:
                dest_f.write(file_bytes)
            
            # Add to database
            with force_master():
                exists = db.query(EvidenceFile).filter(
                    EvidenceFile.report_id == report.id,
                    EvidenceFile.filename == f.filename
                ).first()
                if not exists:
                    new_ev = EvidenceFile(
                        report_id=report.id,
                        filename=f.filename,
                        file_path=os.path.abspath(dest_path),
                        is_auditor_uploaded=is_auditor_uploaded,
                        status="Completed"
                    )
                    db.add(new_ev)
                    db.commit()
            
            # Extract Text and save document chunks offline
            f_like.seek(0)
            text = extract_text(f_like)
            save_document_chunks(f.filename, text)
            
            uploaded_details.append({
                "filename": f.filename,
                "status": "Processed",
                "bytes": len(file_bytes)
            })
            
        return {"success": True, "files": uploaded_details}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload processing failed: {e}")
    finally:
        db.close()

@router.get("/evidence")
def api_get_session_evidence(session_id: str):
    """Returns list of uploaded evidence files for the given session ID."""
    db = SessionLocal()
    try:
        report = db.query(AuditReport).filter(AuditReport.session_id == session_id).first()
        if not report:
            return {"success": True, "files": []}
        
        files = db.query(EvidenceFile).filter(EvidenceFile.report_id == report.id).order_by(EvidenceFile.uploaded_at.desc()).all()
        result = []
        for f in files:
            size_str = "0 KB"
            if f.file_path and os.path.exists(f.file_path):
                sz = os.path.getsize(f.file_path)
                if sz > 1024 * 1024:
                    size_str = f"{sz / (1024 * 1024):.1f} MB"
                elif sz > 1024:
                    size_str = f"{sz / 1024:.1f} KB"
                else:
                    size_str = f"{sz} B"
            result.append({
                "id": f.id,
                "filename": f.filename,
                "size_str": size_str,
                "is_auditor": bool(f.is_auditor_uploaded),
                "created_at": str(f.uploaded_at)
            })
        return {"success": True, "files": result}
    finally:
        db.close()

@router.post("/start")
def api_start_audit(req: StartAuditRequest):
    bg_key = req.session_id
    print(f"🚀 [API] /audit/start received for session {req.session_id} with {len(req.selected_sls)} controls (mode: {req.audit_mode})", flush=True)
    
    with _bg_lock:
        if bg_key in _bg_running:
            return {"success": True, "status": "already_running", "message": "Audit is already running."}
        _bg_stop_flags.pop(bg_key, None)
    
    db = SessionLocal()
    try:
        report = db.query(AuditReport).filter(AuditReport.session_id == req.session_id).first()
        if not report:
            raise HTTPException(status_code=404, detail="Session not found.")
        
        # Load evidence files text & bytes from disk
        ev_files = db.query(EvidenceFile).filter(EvidenceFile.report_id == report.id).all()
        files_data = []
        file_registry = {}
        for ev in ev_files:
            if os.path.exists(ev.file_path):
                with open(ev.file_path, "rb") as f:
                    file_bytes = f.read()

                # ── Fast-path: use cached DocumentChunks instead of re-running OCR ──
                cached_chunks = db.query(DocumentChunk).filter(
                    DocumentChunk.filename == ev.filename
                ).all()
                if cached_chunks:
                    text = " ".join(c.content for c in cached_chunks if c.content)
                    print(f"[api_start_audit] Using {len(cached_chunks)} cached chunks for '{ev.filename}' (skipping OCR)", flush=True)
                else:
                    # No cache — extract fresh (may trigger EasyOCR for images)
                    f_like = io.BytesIO(file_bytes)
                    f_like.name = ev.filename
                    text = extract_text(f_like)
                    print(f"[api_start_audit] Fresh extraction for '{ev.filename}' ({len(text)} chars)", flush=True)

                file_registry[ev.filename] = text
                files_data.append({
                    "name": ev.filename,
                    "bytes": file_bytes,
                    "text": text
                })

        
        # Determine standard/scoping
        if req.audit_mode in ("VAPT validation", "Technical findings only") or "VAPT" in (report.framework or "").upper():
            is_vapt_std = True
            is_tech_only = True
            report.framework = "VAPT Framework Controls"
            try:
                db.commit()
            except Exception:
                db.rollback()
        else:
            is_vapt_std = report.framework in ("VAPT Framework Controls", "VAPT")
            is_tech_only = False
        
        # Spawn Background Worker thread
        with _bg_lock:
            _bg_running.add(bg_key)
            _bg_store["progress"][bg_key] = {"text": "Initializing analysis...", "percent": 0}
        
        if is_tech_only:
            thread = threading.Thread(
                target=_run_fast_technical_vapt_bg,
                args=(bg_key, files_data, set(req.selected_sls), file_registry),
                daemon=True
            )
        else:
            thread = threading.Thread(
                target=_run_ollama_bg,
                args=(bg_key, files_data, set(req.selected_sls), req.model_choice),
                kwargs={
                    "session_id": req.session_id,
                    "audit_mode": req.audit_mode,
                    "file_registry": file_registry,
                    "custom_evidence": req.custom_evidence,
                    "custom_docs": req.custom_documents
                },
                daemon=True
            )
        thread.start()
        
        return {"success": True, "status": "started", "message": "Background RAG scan initialized."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scoping failed: {e}")
    finally:
        db.close()

@router.post("/stop/{session_id}")
def api_stop_audit(session_id: str):
    """Signal the background audit thread to stop and unblock session execution."""
    _bg_stop_flags[session_id] = True
    with _bg_lock:
        _bg_running.discard(session_id)
        _bg_store["progress"].pop(session_id, None)
    return {"success": True, "message": "Scan stopped successfully."}

@router.get("/status/{session_id}")

def api_get_status(session_id: str):
    with _bg_lock:
        is_running = session_id in _bg_running
        progress = _bg_store["progress"].get(session_id)
        result = _bg_results.get(session_id)
    
    # Check if complete or in progress in DB checkpoint
    checkpoint = get_resumable_checkpoint(session_id)
    checkpoint_data = None
    if checkpoint:
        checkpoint_data = {
            "completed_batches": checkpoint.completed_batches,
            "total_controls": checkpoint.total_controls,
            "status": checkpoint.status
        }
        
    if is_running:
        return {
            "status": "running",
            "progress": progress,
            "checkpoint": checkpoint_data
        }
    
    if result:
        with _bg_lock:
            _bg_results.pop(session_id, None)
            
        if result.get("error"):
            return {
                "status": "failed",
                "progress": progress,
                "checkpoint": checkpoint_data,
                "error": result["error"]
            }
            
        return {
            "status": "completed",
            "progress": progress,
            "checkpoint": checkpoint_data,
            "findings_count": len(result.get("findings", []))
        }
        
    return {"status": "idle", "checkpoint": checkpoint_data}

@router.get("/findings")
def api_get_findings(session_id: str, role: Optional[str] = None, saved_only: bool = False):
    db = SessionLocal()
    try:
        from src.core.controls_data import USE_CASES
        control_catalog = {}
        for uc in USE_CASES:
            # Map by SL and control_id (e.g. "5.15" or "5.15 ACCESS CONTROL")
            u_case = uc.get("use_case", "")
            parts = u_case.split()
            cid = parts[0].upper() if parts else str(uc.get("sl"))
            control_catalog[cid] = uc
            control_catalog[str(uc.get("sl"))] = uc

        with force_master():
            report = db.query(AuditReport).filter(AuditReport.session_id == session_id).first()
            if not report:
                raise HTTPException(status_code=404, detail="Audit session not found.")
                
            query = db.query(Finding).filter(Finding.report_id == report.id)
            if saved_only:
                query = query.filter((Finding.is_saved_to_shakthi == True) | (Finding.human_verified == True))
                
            findings = query.order_by(Finding.control_id).all()
        
        result = []
        for f in findings:
            cid_clean = (f.control_id or "").strip().upper()
            uc_info = control_catalog.get(cid_clean) or control_catalog.get(cid_clean.split()[0]) or {}
            
            is_comp = (f.status or "").upper() in ("COMPLIANT", "ACCEPTED", "PASS")
            
            # Smart description fallback hierarchy
            if f.description and len(f.description.strip()) > 5:
                desc = f.description
            elif f.gap_detected and len(f.gap_detected.strip()) > 5:
                desc = f.gap_detected
            elif uc_info.get("expected"):
                desc = f"Control Requirements: {uc_info['expected']}"
            elif uc_info.get("finding"):
                desc = uc_info["finding"]
            else:
                desc = f.reasoning or "Evaluated against ISO 27001 / VAPT compliance standards."
                
            # Smart recommendation fallback hierarchy
            if f.recommendation and len(f.recommendation.strip()) > 5:
                recom = f.recommendation
            elif f.review_note and len(f.review_note.strip()) > 5:
                recom = f.review_note
            elif uc_info.get("recommendation"):
                recom = uc_info["recommendation"]
            else:
                recom = f"Maintain current documented policies and verification procedures for {f.control_id}." if is_comp else f"Establish, document, and implement procedures to satisfy {f.control_id}."

            # Safe control name — fallback to uc_info label or control_id
            ctrl_name = f.control_name
            if not ctrl_name or ctrl_name in ("null", "undefined", "None"):
                ctrl_name = uc_info.get("label") or uc_info.get("use_case") or f.control_id or ""

            # Safe severity fallback
            sev = f.severity
            if not sev or sev in ("null", "undefined", "None"):
                raw_sev = (uc_info.get("severity") or "MEDIUM").upper()
                sev = {"CRITICAL": "P1 Critical", "HIGH": "P2 High", "MEDIUM": "P3 Medium", "LOW": "P4 Low"}.get(raw_sev, "P3 Medium")

            result.append({
                "id": f.id,
                "control_id": f.control_id,
                "control_name": ctrl_name,
                "severity": sev,
                "description": desc,
                "evidence_found": f.evidence_found,
                "evidence_snippet": f.evidence_snippet,
                "recommendation": recom,
                "reasoning": f.reasoning or "Semantic RAG compliance evaluation.",
                "status": f.status,
                "source_files": f.source_files,
                "policy_present": f.policy_present,
                "evidence_present": f.evidence_present,
                "is_saved_to_shakthi": bool(f.is_saved_to_shakthi or f.human_verified),
                "human_verified": bool(f.human_verified),
                "review_note": f.review_note or ""
            })
        return {"success": True, "findings": result, "session_title": report.session_title}
    finally:
        db.close()

@router.put("/findings/{finding_id}")
def api_update_finding(finding_id: int, req: UpdateFindingRequest):
    db = SessionLocal()
    try:
        with force_master():
            finding = db.query(Finding).filter(Finding.id == finding_id).first()
            if not finding:
                raise HTTPException(status_code=404, detail="Finding not found.")
                
            finding.status = req.status
            if req.severity: finding.severity = req.severity
            if req.description: finding.description = req.description
            if req.evidence_snippet: finding.evidence_snippet = req.evidence_snippet
            if req.recommendation: finding.recommendation = req.recommendation
            if req.reasoning: finding.reasoning = req.reasoning
            if req.policy_present: finding.policy_present = req.policy_present
            if req.evidence_present: finding.evidence_present = req.evidence_present
            
            # Explicitly mark as reviewed and saved to Shakthi DB
            finding.is_saved_to_shakthi = True
            finding.human_verified = True
            
            # Record auditor comments in database if comment is updated
            if req.comment:
                finding.review_note = req.comment
                
            # Log to AuditorFeedback to prevent false positives from recurring
            dup = db.query(AuditorFeedback).filter(
                AuditorFeedback.control_id == finding.control_id,
                AuditorFeedback.evidence_snippet == finding.evidence_snippet,
                AuditorFeedback.corrected_status == req.status,
                AuditorFeedback.finding == finding.description
            ).first()
            if not dup:
                db.add(AuditorFeedback(
                    control_id=finding.control_id,
                    evidence_snippet=finding.evidence_snippet,
                    corrected_status=req.status,
                    finding=finding.description,
                    recommendation=finding.recommendation,
                    auditor_comments=req.comment or finding.review_note or ""
                ))
                
            db.commit()
            return {"success": True, "message": "Finding successfully updated and saved to Shakthi DB."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database update failed: {e}")
    finally:
        db.close()

@router.put("/findings/commit-session/{session_id}")
def api_commit_session_findings(session_id: str, force: bool = False, auditor_user: str = "Lead Auditor"):
    """Commits and finalizes all findings for a session into Shakthi DB, with unreviewed controls warning & admin logging."""
    db = SessionLocal()
    is_force = bool(force) or str(force).lower() in ('true', '1')
    try:
        from src.db.database import AdminAuditLog
        with force_master():
            report = db.query(AuditReport).filter(AuditReport.session_id == session_id).first()
            if not report:
                raise HTTPException(status_code=404, detail="Session not found.")
                
            findings = db.query(Finding).filter(Finding.report_id == report.id).all()
            unreviewed = [f for f in findings if not bool(f.is_saved_to_shakthi) and not bool(f.human_verified)]
            
            # If there are unreviewed controls and auditor hasn't forced acceptance, trigger warning response!
            if unreviewed and not is_force:
                unreviewed_controls = [f"{f.control_id} - {f.control_name or f.status}" for f in unreviewed]
                return {
                    "success": False,
                    "requires_confirmation": True,
                    "unreviewed_count": len(unreviewed),
                    "unreviewed_controls": unreviewed_controls,
                    "message": f"Warning: {len(unreviewed)} control(s) have not been reviewed/saved to Shakthi DB yet."
                }
                
            # If auditor forces acceptance of unreviewed controls, log to Admin Audit Log!
            if unreviewed and is_force:
                unreviewed_control_ids = [f.control_id for f in unreviewed]
                db.add(AdminAuditLog(
                    auditor_user=auditor_user,
                    session_id=session_id,
                    action="FORCE_ACCEPT_UNREVIEWED_CONTROLS",
                    unreviewed_controls=json.dumps(unreviewed_control_ids),
                    details=f"Auditor forcibly accepted and committed session {session_id[:8]} with {len(unreviewed)} unreviewed control(s): {', '.join(unreviewed_control_ids)}"
                ))
                
            # Mark all findings as saved and verified in Shakthi DB
            for f in findings:
                f.is_saved_to_shakthi = True
                f.human_verified = True
                
            report.status = "Reviewed & Finalized"
            
            # Recalculate Compliance Score
            total_ctrls = len(findings)
            compliant_count = sum(1 for f in findings if (f.status or "").upper() in ("COMPLIANT", "ACCEPTED", "PASS"))
            score_pct = int((compliant_count / total_ctrls) * 100) if total_ctrls > 0 else 0
            
            score_row = db.query(ComplianceScore).filter(ComplianceScore.report_id == report.id).first()
            if score_row:
                score_row.score_percent = score_pct
            else:
                db.add(ComplianceScore(
                    report_id=report.id,
                    framework=report.framework or "ISO 27001",
                    score_percent=score_pct
                ))
            db.commit()
            return {
                "success": True, 
                "message": f"Successfully committed {total_ctrls} audit record(s) to Shakthi DB (Compliance Score: {score_pct}%).",
                "status": report.status,
                "score_percent": score_pct,
                "unreviewed_count": len(unreviewed) if force else 0
            }
    except Exception as e:
        import traceback
        print(f"[COMMIT SESSION EXCEPTION ERROR] {e}\n{traceback.format_exc()}", flush=True)
        raise HTTPException(status_code=500, detail=f"Commit to Shakthi DB failed: {e}")
    finally:
        db.close()

@router.get("/admin-logs")
def api_get_admin_logs():
    """Retrieves admin audit trail log records for force acceptances and overrides."""
    db = SessionLocal()
    try:
        from src.db.database import AdminAuditLog
        logs = db.query(AdminAuditLog).order_by(AdminAuditLog.id.desc()).limit(100).all()
        result = []
        for l in logs:
            result.append({
                "id": l.id,
                "timestamp": l.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if l.timestamp else "",
                "auditor_user": l.auditor_user,
                "session_id": l.session_id,
                "action": l.action,
                "unreviewed_controls": l.unreviewed_controls,
                "details": l.details
            })
        return {"success": True, "logs": result}
    finally:
        db.close()

@router.post("/chats/send")
def api_chat_send(req: ChatSendRequest):
    db = SessionLocal()
    try:
        # Save user message (tagged with username for role isolation)
        with force_master():
            db.add(ChatMessage(
                session_id=req.session_id,
                session_title="AI Chat Session",
                role="user",
                content=req.message,
                username=req.username
            ))
            db.commit()
            
        # Get active document chunks for RAG search
        context_text = retrieve_chat_context(db, req.session_id, req.message, top_k=5)
        
        # Build prompt
        prompt = f"""You are a professional ISO 27001 cybersecurity auditor. 
Answer the user's question offline based strictly on the following local compliance evidence context:

--- START EVIDENCE CONTEXT ---
{context_text}
--- END EVIDENCE CONTEXT ---

Question: {req.message}

Answer:"""

        # Query local LLM (Ollama / GGUF)
        from src.core.bg_worker import _resolve_ollama_model
        ollama_model = _resolve_ollama_model(req.model_choice)
        response_text = query_llm(prompt, model=ollama_model)
        
        # Save AI assistant message (tagged with same username)
        with force_master():
            db.add(ChatMessage(
                session_id=req.session_id,
                session_title="AI Chat Session",
                role="assistant",
                content=response_text,
                username=req.username
            ))
            db.commit()
            
        return {"success": True, "response": response_text}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Chat assistant query failed: {e}")
    finally:
        db.close()

@router.post("/upload-scope-excel")
def api_upload_scope_excel(file: UploadFile = File(...)):
    """Parses Excel scoping checklist and maps target ISO controls."""
    try:
        import pandas as pd
        import re as _re
        from src.core.controls_data import USE_CASES as _UC_LIST

        file_bytes = file.file.read()
        df = pd.read_excel(io.BytesIO(file_bytes))

        # Header row auto-detection
        if any("unnamed" in str(c).lower() for c in df.columns):
            for h_idx in range(min(5, len(df))):
                row_vals = [str(v).strip().lower() for v in df.iloc[h_idx].values if pd.notna(v)]
                if any(k in v for v in row_vals for k in ("audit", "check", "control", "file", "doc", "evidence", "expected")):
                    df.columns = [str(c).strip() for c in df.iloc[h_idx]]
                    df = df.iloc[h_idx+1:].reset_index(drop=True)
                    break

        col_control = None
        col_document = None
        col_evidence = None

        for col in df.columns:
            col_str = str(col).lower()
            if any(k in col_str for k in ("evidence", "expected", "proof")):
                col_evidence = col
            elif any(k in col_str for k in ("use_case", "sl", "number", "audit", "check")) or "id" in col_str.split() or col_str == "control":
                col_control = col
            elif any(k in col_str for k in ("doc", "file", "policy", "source", "name")):
                col_document = col

        if col_control is None or col_evidence is None:
            if len(df.columns) >= 3:
                col_control = df.columns[1] if len(df.columns) > 1 else df.columns[0]
                col_evidence = df.columns[2] if len(df.columns) > 2 else df.columns[1]
                col_document = df.columns[2] if len(df.columns) > 2 else None
            elif len(df.columns) >= 2:
                col_control = df.columns[0]
                col_evidence = df.columns[1]

        if col_control is None or col_evidence is None:
            raise HTTPException(status_code=400, detail="Columns for 'Control' and 'Evidence' could not be identified.")

        custom_evidence = {}
        custom_documents = {}
        matched_sls = set()
        digit_re = _re.compile(r'(\d{1,2}\.\d{1,2}(?:\.\d{1,2})?)')
        vapt_re = _re.compile(r'(vapt-\d{1,2})', _re.IGNORECASE)

        for _, row in df.iterrows():
            ctrl_val = str(row[col_control]).strip()
            ev_val = str(row[col_evidence]).strip()
            if not ctrl_val or ctrl_val == "nan" or not ev_val or ev_val == "nan":
                continue

            matched_uc = None
            match_id = digit_re.search(ctrl_val)
            match_vapt = vapt_re.search(ctrl_val)

            if match_vapt:
                target_vapt = match_vapt.group(1).upper()
                for uc in _UC_LIST:
                    if uc["use_case"].upper().startswith(target_vapt):
                        matched_uc = uc
                        break
            elif match_id:
                target_id = match_id.group(1)
                for uc in _UC_LIST:
                    uc_id = uc["use_case"].split(" ")[0]
                    if uc_id == target_id:
                        matched_uc = uc
                        break
            else:
                c_lower = ctrl_val.lower()
                for uc in _UC_LIST:
                    uc_id = uc["use_case"].split(" ")[0]
                    uc_uc = str(uc.get("use_case", "")).lower()
                    
                    if 'ntp' in c_lower and uc_id == "8.17":
                        matched_uc = uc
                        break
                    elif ('multifactor' in c_lower or 'mfa' in c_lower) and uc_id in ("5.17", "8.5"):
                        matched_uc = uc
                        break
                    elif 'pam' in c_lower and uc_id in ("5.15", "8.2", "5.18"):
                        matched_uc = uc
                        break
                    elif 'fraud' in c_lower and uc_id in ("5.1", "5.15"):
                        matched_uc = uc
                        break
                    elif ('archived' in c_lower or 'archival' in c_lower or 'logging' in c_lower) and uc_id in ("8.15", "5.33"):
                        matched_uc = uc
                        break
                    elif any(k in c_lower for k in ('cpu', 'memory', 'disk', 'utilization')) and uc_id in ("8.16", "8.6"):
                        matched_uc = uc
                        break
                    elif 'authentication' in c_lower and uc_id in ("5.17", "5.15"):
                        matched_uc = uc
                        break
                    elif c_lower in uc_uc:
                        matched_uc = uc
                        break

            if matched_uc:
                uc_key = matched_uc["use_case"]
                if uc_key in custom_evidence:
                    custom_evidence[uc_key] += f" | {ev_val}"
                else:
                    custom_evidence[uc_key] = ev_val

                if col_document is not None:
                    doc_val = str(row[col_document]).strip()
                    if doc_val and doc_val != "nan":
                        if uc_key in custom_documents:
                            if doc_val not in custom_documents[uc_key]:
                                custom_documents[uc_key] += f", {doc_val}"
                        else:
                            custom_documents[uc_key] = doc_val
                matched_sls.add(matched_uc["sl"])

        return {
            "success": True,
            "matched_sls": list(matched_sls),
            "custom_evidence": custom_evidence,
            "custom_documents": custom_documents,
            "message": f"Successfully matched {len(matched_sls)} standard compliance controls."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/deliver")
def api_deliver_report(
    session_id: str = Form(...),
    auditee_id: int = Form(...),
    username: str = Form("admin")
):
    """Delivers report session to specified auditee account."""
    db = SessionLocal()
    try:
        report = db.query(AuditReport).filter(AuditReport.session_id == session_id).first()
        if not report:
            raise HTTPException(status_code=404, detail="Session not found.")
            
        user = db.query(User).filter(User.username == username).first()
        auditor_id = user.id if user else None
        
        with force_master():
            db.add(AuditRecord(
                report_id=report.id,
                auditor_id=auditor_id,
                status="Sent to Auditee",
                comments="Report published to auditee from records dashboard"
            ))
            report.status = "Sent to Auditee"
            report.auditee_id = auditee_id
            db.commit()
            
        return {"success": True, "message": "Report successfully delivered to auditee."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@router.delete("/clear-records")
def api_clear_all_records():
    """Clears all audit reports, findings, chats, checkpoints, chunks, and logs from database."""
    db = SessionLocal()
    try:
        from src.db.database import AuditorFeedback
        with force_master():
            db.query(Finding).delete()
            db.query(AuditorFeedback).delete()
            db.query(AuditReport).delete()
            db.query(EvidenceFile).delete()
            db.query(AuditRecord).delete()
            db.query(ComplianceScore).delete()
            db.query(ChatMessage).delete()
            db.query(DocumentChunk).delete()
            db.query(AuditCheckpoint).delete()
            db.commit()
        return {"success": True, "message": "All database audit records cleared successfully."}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@router.get("/feedback/export")
def api_export_feedback():
    """Exports all AuditorFeedback records to JSON."""
    db = SessionLocal()
    try:
        from src.db.database import AuditorFeedback
        feedbacks = db.query(AuditorFeedback).all()
        data = []
        for fb in feedbacks:
            data.append({
                "control_id": fb.control_id,
                "evidence_snippet": fb.evidence_snippet,
                "corrected_status": fb.corrected_status,
                "finding": fb.finding,
                "recommendation": fb.recommendation,
                "auditor_comments": fb.auditor_comments,
                "confidence": fb.confidence,
                "hallucination_check": fb.hallucination_check
            })
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@router.post("/feedback/import")
def api_import_feedback(file: UploadFile = File(...)):
    """Imports AuditorFeedback records from uploaded JSON file."""
    db = SessionLocal()
    try:
        import json
        file_bytes = file.file.read()
        feedbacks_data = json.loads(file_bytes)
        
        from src.db.database import AuditorFeedback
        imported_count = 0
        with force_master():
            for item in feedbacks_data:
                control_id = item.get("control_id")
                evidence_snippet = item.get("evidence_snippet")
                corrected_status = item.get("corrected_status")
                finding = item.get("finding")
                
                # Prevent duplication
                dup = db.query(AuditorFeedback).filter(
                    AuditorFeedback.control_id == control_id,
                    AuditorFeedback.evidence_snippet == evidence_snippet,
                    AuditorFeedback.corrected_status == corrected_status,
                    AuditorFeedback.finding == finding
                ).first()
                if not dup:
                    db.add(AuditorFeedback(
                        control_id=control_id,
                        evidence_snippet=evidence_snippet,
                        corrected_status=corrected_status,
                        finding=finding,
                        recommendation=item.get("recommendation"),
                        auditor_comments=item.get("auditor_comments"),
                        confidence=item.get("confidence", 10),
                        hallucination_check=item.get("hallucination_check")
                    ))
                    imported_count += 1
            db.commit()
            
        return {"success": True, "message": f"Successfully imported {imported_count} feedback records."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@router.get("/chats/sessions")
def api_get_chat_sessions(role: Optional[str] = None, username: Optional[str] = None):
    """Retrieves list of active compliance sessions scoped to the logged-in user."""
    db = SessionLocal()
    try:
        sessions_dict = {}
        # 1. AuditReports — filter by user if auditee role
        if role == "auditee" and username:
            user = db.query(User).filter(User.username == username).first()
            if user:
                reports = db.query(AuditReport).filter(AuditReport.auditee_id == user.id).all()
            else:
                reports = []
        else:
            reports = db.query(AuditReport).all()
        for r in reports:
            sessions_dict[r.session_id] = {
                "session_id": r.session_id,
                "session_title": r.session_title,
                "created_at": str(r.created_at)
            }
            
        # 2. ChatMessages — scope to the requesting user only, fall back if username column missing
        try:
            if username:
                chats = db.query(ChatMessage).filter(
                    ChatMessage.username == username
                ).order_by(ChatMessage.created_at.desc()).all()
            else:
                chats = []
        except Exception:
            # Fallback: username column may not exist in older DB — query without filter
            try:
                chats = db.query(ChatMessage).order_by(ChatMessage.created_at.desc()).limit(50).all()
            except Exception:
                chats = []

        for c in chats:
            if c.session_id not in sessions_dict:
                sessions_dict[c.session_id] = {
                    "session_id": c.session_id,
                    "session_title": getattr(c, "session_title", None) or "AI Chat Session",
                    "created_at": str(c.created_at)
                }
                    
        # Sort
        sorted_sessions = list(sessions_dict.values())
        sorted_sessions.sort(key=lambda x: x["created_at"], reverse=True)
        return {"success": True, "sessions": sorted_sessions[:12]}
    except Exception as e:
        return {"success": True, "sessions": [], "error": str(e)}
    finally:
        db.close()


@router.get("/chats/history")
def api_get_chat_history(session_id: str, username: Optional[str] = None):
    """Retrieves messages for specified chat session — filtered to the requesting user."""
    db = SessionLocal()
    try:
        query = db.query(ChatMessage).filter(ChatMessage.session_id == session_id)
        if username:
            # Only show messages that belong to this user OR have no username (legacy rows)
            from sqlalchemy import or_
            query = query.filter(or_(ChatMessage.username == username, ChatMessage.username == None))
        messages = query.order_by(ChatMessage.created_at.asc()).all()
        res = []
        for m in messages:
            res.append({
                "role": m.role,
                "content": m.content,
                "created_at": str(m.created_at)
            })
        return {"success": True, "messages": res}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@router.post("/chats/clear")
def api_clear_chat_session(session_id: str = Form(...), username: Optional[str] = Form(None)):
    """Clears only the current user's messages for a session."""
    db = SessionLocal()
    try:
        with force_master():
            q = db.query(ChatMessage).filter(ChatMessage.session_id == session_id)
            if username:
                from sqlalchemy import or_
                q = q.filter(or_(ChatMessage.username == username, ChatMessage.username == None))
            q.delete(synchronize_session=False)
            db.query(AuditCheckpoint).filter(AuditCheckpoint.session_id == session_id).delete()
            db.commit()
        return {"success": True, "message": "Chat history cleared successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@router.get("/export/docx")
def api_export_docx(session_id: str):
    """Exports findings report as DOCX using template mappings."""
    db = SessionLocal()
    try:
        from fastapi.responses import StreamingResponse
        from src.db.database import Finding, AuditReport
        from src.core.report_exporter import export_docx_report
        
        report = db.query(AuditReport).filter(AuditReport.session_id == session_id).first()
        if not report:
            raise HTTPException(status_code=404, detail="Session not found.")
            
        db_findings = db.query(Finding).filter(Finding.report_id == report.id).all()
        
        findings_mapped = []
        resolved_list = []
        for f in db_findings:
            sev = f.severity or "Medium"
            sev_score = 5.0
            if "Critical" in sev or "1" in sev:
                sev_score = 9.5
            elif "High" in sev:
                sev_score = 8.0
            elif "Medium" in sev or "2" in sev:
                sev_score = 5.0
            else:
                sev_score = 2.5
                
            findings_mapped.append({
                "control_id": f.control_id,
                "control": f.control_name or f.control_id,
                "clause": "ISO 27001 Annex A",
                "finding": f.description or f.gap_detected or "",
                "description": f.description or f.gap_detected or "",
                "status": f.status or "Non-Compliant",
                "severity": f.severity or "Medium",
                "severity_score": sev_score,
                "business_impact": f.reasoning or "Compliance verification pending.",
                "recommendation": f.recommendation or "",
                "evidence_snippet": f.evidence_snippet or "",
                "evidence_quote": f.evidence_snippet or "",
                "source_files": f.source_files or ""
            })
            if f.status == "Compliant":
                resolved_list.append(f.control_id)
                
        docx_bytes = export_docx_report(
            session_title=report.framework,
            findings=findings_mapped,
            resolved_list=resolved_list,
            status=report.status or "Draft",
            comments="Lead auditor generated report"
        )
        
        return StreamingResponse(
            io.BytesIO(docx_bytes),
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": f"attachment; filename={report.framework.replace(' ', '_')}_Report.docx"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@router.get("/export/pdf")
def api_export_pdf(session_id: str):
    """Exports findings report as PDF using custom layout templates."""
    db = SessionLocal()
    try:
        from fastapi.responses import StreamingResponse
        from src.db.database import Finding, AuditReport
        from src.core.report_exporter import export_pdf_report
        
        report = db.query(AuditReport).filter(AuditReport.session_id == session_id).first()
        if not report:
            raise HTTPException(status_code=404, detail="Session not found.")
            
        db_findings = db.query(Finding).filter(Finding.report_id == report.id).all()
        
        findings_mapped = []
        resolved_list = []
        for f in db_findings:
            sev = f.severity or "Medium"
            sev_score = 0.0
            try:
                if f.evidence_found:
                    sev_score = float(f.evidence_found)
            except Exception:
                sev_score = 0.0

            if sev_score <= 0.0:
                if "Critical" in sev or "1" in sev:
                    sev_score = 9.5
                elif "High" in sev:
                    sev_score = 8.0
                elif "Medium" in sev or "2" in sev:
                    sev_score = 5.5
                else:
                    sev_score = 2.5
                
            findings_mapped.append({
                "control_id": f.control_id,
                "title": f.control_name or f.control_id,
                "finding": f.control_name or f.description or "",
                "control": f.control_name or f.control_id,
                "clause": "ISO 27001 Annex A",
                "description": f.description or f.gap_detected or "",
                "status": f.status or "Non-Compliant",
                "severity": f.severity or "Medium",
                "severity_score": sev_score,
                "target": f.source_files or "Scoped Target Systems",
                "business_impact": f.reasoning or "Compliance verification pending.",
                "recommendation": f.recommendation or "",
                "evidence_snippet": f.evidence_snippet or "",
                "evidence_quote": f.evidence_snippet or "",
                "source_files": f.source_files or ""
            })
            if f.status == "Compliant":
                resolved_list.append(f.control_id)
                
        is_vapt = report.framework in ("VAPT Framework Controls", "VAPT") or "VAPT" in (report.framework or "").upper()
        if is_vapt:
            from src.core.report_exporter import _export_vapt_pdf
            pdf_bytes = _export_vapt_pdf(
                session_title=report.framework,
                findings=findings_mapped,
                resolved_list=resolved_list,
                status=report.status or "Completed",
                comments="Lead auditor generated report"
            )
        else:
            from src.core.report_exporter import export_pdf_report
            pdf_bytes = export_pdf_report(
                session_title=report.framework,
                findings=findings_mapped,
                resolved_list=resolved_list,
                status=report.status or "Draft",
                comments="Lead auditor generated report"
            )
        
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={report.framework.replace(' ', '_')}_Report.pdf"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()
