from fastapi import APIRouter, HTTPException, Query, File, UploadFile, Request
from pydantic import BaseModel, Field
from typing import List, Optional
from src.db.database import (
    get_all_custom_controls,
    add_custom_control,
    update_custom_control,
    delete_custom_control
)
from src.ai.keyword_generator import generate_keywords
from src.api.endpoints.auth import _require_auth

router = APIRouter(prefix="/controls", tags=["Manage Controls"])

# --- Request / Response Schemas ---
class CreateControlRequest(BaseModel):
    control_id: str
    control_name: str
    category: str
    keywords: List[str] = []
    description: str = ""
    is_global: bool = True
    created_by: str = "auditor"

class UpdateControlRequest(BaseModel):
    keywords: Optional[List[str]] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None

class AutogenKeywordsRequest(BaseModel):
    name: str
    description: str = ""

# --- Endpoints ---

@router.get("")
def api_get_controls(request: Request, active_only: bool = Query(True)):
    _require_auth(request)
    try:
        controls = get_all_custom_controls(active_only=active_only)
        return {"success": True, "controls": controls}
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to load controls.")

@router.post("")
def api_create_control(request: Request, req: CreateControlRequest):
    _require_auth(request)
    if not req.control_id.strip() or not req.control_name.strip():
        raise HTTPException(status_code=400, detail="Control ID and Control Name are required.")
    try:
        new_id = add_custom_control(
            control_id=req.control_id.strip(),
            control_name=req.control_name.strip(),
            category=req.category.strip(),
            keywords=req.keywords,
            description=req.description.strip(),
            auto_generated=False,
            created_by=req.created_by.strip(),
            is_global=req.is_global
        )
        return {"success": True, "message": "Control saved successfully", "id": new_id}
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to save control.")

@router.post("/autogen-keywords")
def api_autogen_keywords(request: Request, req: AutogenKeywordsRequest):
    _require_auth(request)
    if not req.name.strip():
        raise HTTPException(status_code=400, detail="Control name is required for keyword generation.")
    try:
        keywords = generate_keywords(req.name.strip(), req.description.strip())
        return {"success": True, "keywords": keywords}
    except Exception:
        raise HTTPException(status_code=500, detail="Keyword generation failed.")

@router.put("/{db_id}")
def api_update_control(request: Request, db_id: int, req: UpdateControlRequest):
    _require_auth(request)
    try:
        success = update_custom_control(
            control_db_id=db_id,
            keywords=req.keywords,
            description=req.description,
            is_active=req.is_active
        )
        if not success:
            raise HTTPException(status_code=404, detail="Control not found in database.")
        return {"success": True, "message": "Control updated successfully"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to update control.")

@router.delete("/{db_id}")
def api_delete_control(request: Request, db_id: int, soft: bool = Query(True)):
    user = _require_auth(request)
    if user.get("role") not in ("admin", "auditor"):
        raise HTTPException(status_code=403, detail="Access denied.")
    try:
        success = delete_custom_control(control_db_id=db_id, soft=soft)
        if not success:
            raise HTTPException(status_code=404, detail="Control not found in database.")
        action_type = "deactivated" if soft else "deleted"
        return {"success": True, "message": f"Control successfully {action_type}"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to delete control.")

@router.get("/framework")
def api_get_framework_controls(request: Request):
    _require_auth(request)
    """Returns combined list of standard ISO/VAPT framework controls and custom controls."""
    try:
        from src.core.controls_data import USE_CASES
        from src.core.bg_worker import _load_custom_use_cases
        customs = _load_custom_use_cases(force=True)
        combined = []
        for uc in USE_CASES:
            combined.append({"sl": uc["sl"], "use_case": uc["use_case"], "label": uc["label"], "category": uc["category"]})
        for c in customs:
            combined.append({"sl": c["sl"], "use_case": c["use_case"], "label": c["label"], "category": c["category"]})
        return {"success": True, "controls": combined}
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to load framework controls.")

@router.post("/parse-scope-excel")
async def api_parse_scope_excel(request: Request, file: UploadFile = File(...)):
    """Parses an uploaded auditor scope Excel mapping (.xlsx/.xls) and returns mapped control SLs and custom evidence."""
    _require_auth(request)
    if not file.filename.lower().endswith(('.xlsx', '.xls')):
        raise HTTPException(status_code=400, detail="Only Excel files (.xlsx, .xls) are supported.")

        
    try:
        import os
        import tempfile
        from src.core.excel_scoping_parser import parse_excel_scoping_checklist
        from src.core.controls_data import USE_CASES
        
        contents = await file.read()
        
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as tmp:
            tmp.write(contents)
            tmp_path = tmp.name

        try:
            items = parse_excel_scoping_checklist(tmp_path)
        finally:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass


        custom_evidence = {}
        custom_documents = {}
        # BUG FIX: Use LIST not SET — two rows with same ctrl_id (e.g. two 8.17 NTP checks)
        # must each appear so progress counter and control loop both get 8 items, not 6.
        matched_sls_list = []
        import re as _re
        from src.core.excel_scoping_parser import (
            _resolve_control_by_direct_map as _kw_resolve,
            _resolve_control_by_name as _name_resolve,
        )

        def _norm(t: str) -> str:
            """Lowercase + strip punctuation for fuzzy comparisons."""
            return _re.sub(r'[^a-z0-9\s]', ' ', str(t or '').lower()).strip()

        for item in items:
            ctrl_id = item.get("control_id")
            ctrl_label = item.get("control_label")
            question = item.get("question") or item.get("control_label") or ctrl_id
            expected_ev = item.get("expected_evidence") or question or ""
            files = item.get("files") or item.get("raw_file_refs") or []
            files_str = ", ".join(files) if isinstance(files, list) else str(files)

            matched_uc = None

            # --- Pass 1: exact numeric ID match or exact use_case string match ---
            for uc in USE_CASES:
                uc_id = uc["use_case"].split(" ")[0]
                if uc_id == ctrl_id or uc["use_case"] == ctrl_label:
                    matched_uc = uc
                    break

            # --- Pass 2: strip leading numeric ID from ctrl_label and compare ---
            # Handles the case where the parser resolved via keyword/embedding and
            # ctrl_id == "UNKNOWN" but ctrl_label == "5.15 Access Control" (a valid
            # ISO label whose numeric prefix still uniquely identifies the control).
            if not matched_uc and ctrl_label and ctrl_label != "UNKNOWN":
                label_id_match = _re.match(r'^(VAPT\s*-?\s*\d+|\d{1,2}\.\d{1,2}(?:\.\d{1,2})?)', str(ctrl_label).strip(), _re.IGNORECASE)
                if label_id_match:
                    label_prefix = label_id_match.group(1).strip().upper()
                    for uc in USE_CASES:
                        uc_id = uc["use_case"].split(" ")[0].upper()
                        if uc_id == label_prefix:
                            matched_uc = uc
                            break

            # --- Pass 2.5: re-run the parser's rich keyword map on the question ---
            # The parser already ran _resolve_control_by_direct_map on resolution_text
            # but returned UNKNOWN when that text was empty or the question column was
            # detected differently from what the backend stores in item["question"].
            # Re-running here covers question-based rows like "Is MFA enabled?" or
            # "Are backups taken daily?" that carry domain keywords (mfa -> 8.5,
            # backup -> 8.13, ntp -> 8.17) that the word-overlap pass below would miss
            # because it only compares against USE_CASES label words, not audit terms.
            if not matched_uc and question:
                matched_uc = _kw_resolve(question, USE_CASES)

            # Also try _resolve_control_by_name on the question text (handles cases
            # like "Clock Synchronization" or "Backup and Recovery" as plain text).
            if not matched_uc and question:
                matched_uc = _name_resolve(question, USE_CASES)

            # --- Pass 3: word-overlap fallback on ctrl_label text ---
            # Final resort when neither ID, label-prefix, nor keyword/name pass matched
            # (e.g. a highly domain-specific or abbreviated question).
            if not matched_uc:
                search_text = _norm(" ".join(filter(None, [ctrl_label, question])))
                search_words = [w for w in search_text.split() if len(w) > 2]
                if search_words:
                    best_uc, best_score = None, 0
                    for uc in USE_CASES:
                        uc_text = _norm(uc.get("label", "") + " " + uc.get("use_case", ""))
                        uc_words = set(uc_text.split())
                        overlap = len(set(search_words) & uc_words)
                        if overlap > best_score:
                            best_score, best_uc = overlap, uc
                    min_req = 1 if len(search_words) <= 2 else 2
                    if best_score >= min_req:
                        matched_uc = best_uc

            if matched_uc:
                uc_key = matched_uc["use_case"]
                uc_id = uc_key.split(" ")[0]

                # BUG FIX: append to list so two 8.17 rows both appear
                matched_sls_list.append(int(matched_uc["sl"]))

                # BUG FIX: merge files for same ctrl_id rather than overwrite.
                # This means both NTP evidence files end up in the mapping for 8.17.
                for target_k in (uc_key, uc_id, ctrl_label):
                    if target_k:
                        if target_k not in custom_documents or not custom_documents[target_k]:
                            custom_documents[target_k] = files_str
                        elif files_str and files_str not in custom_documents[target_k]:
                            # Append additional file for same control, comma-separated
                            custom_documents[target_k] = custom_documents[target_k] + ", " + files_str
                        if expected_ev:
                            custom_evidence[target_k] = expected_ev

        custom_evidence["excel_items"] = items

        unmatched_count = len(items) - len(matched_sls_list)
        warning = None
        if len(items) > 0 and len(matched_sls_list) == 0:
            warning = (
                "No ISO controls could be matched from the Excel sheet. "
                "Please ensure the sheet has a column containing ISO control IDs (e.g. '5.15') "
                "or recognisable control names."
            )
        elif unmatched_count > 0:
            warning = f"{unmatched_count} row(s) could not be matched to a known ISO control and were skipped."

        return {
            "success": True,
            "matched_sls": matched_sls_list,        # list with duplicates — 8 items, not 6
            "custom_evidence": custom_evidence,
            "custom_documents": custom_documents,
            "total_rows": len(items),
            "warning": warning,
            "message": f"Successfully loaded {len(items)} Excel audit checklist items ({len(set(matched_sls_list))} unique ISO controls)."
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"[EXCEL SCOPE PARSE ERROR] {e}", flush=True)
        raise HTTPException(status_code=500, detail="Failed to parse Excel scope file. Please check the file format and try again.")


