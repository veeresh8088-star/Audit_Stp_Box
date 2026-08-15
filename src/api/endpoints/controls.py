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
async def api_parse_scope_excel(file: UploadFile = File(...)):
    """Parses an uploaded auditor scope Excel mapping (.xlsx/.xls) and returns mapped control SLs and custom evidence."""
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

        for item in items:
            ctrl_id = item.get("control_id")
            ctrl_label = item.get("control_label")
            question = item.get("question") or item.get("control_label") or ctrl_id
            expected_ev = item.get("expected_evidence") or question or ""
            files = item.get("files") or item.get("raw_file_refs") or []
            files_str = ", ".join(files) if isinstance(files, list) else str(files)

            matched_uc = None
            for uc in USE_CASES:
                uc_id = uc["use_case"].split(" ")[0]
                if uc_id == ctrl_id or uc["use_case"] == ctrl_label:
                    matched_uc = uc
                    break

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

        return {
            "success": True,
            "matched_sls": matched_sls_list,        # list with duplicates — 8 items, not 6
            "custom_evidence": custom_evidence,
            "custom_documents": custom_documents,
            "total_rows": len(items),
            "message": f"Successfully loaded {len(items)} Excel audit checklist items ({len(set(matched_sls_list))} unique ISO controls)."
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"[EXCEL SCOPE PARSE ERROR] {e}", flush=True)
        raise HTTPException(status_code=500, detail="Failed to parse Excel scope file. Please check the file format and try again.")


