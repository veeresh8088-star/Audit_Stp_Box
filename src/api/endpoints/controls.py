from fastapi import APIRouter, HTTPException, Query, File, UploadFile
from pydantic import BaseModel, Field
from typing import List, Optional
from src.db.database import (
    get_all_custom_controls,
    add_custom_control,
    update_custom_control,
    delete_custom_control
)
from src.ai.keyword_generator import generate_keywords

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
def api_get_controls(active_only: bool = Query(True, description="Filter for active controls only")):
    try:
        controls = get_all_custom_controls(active_only=active_only)
        return {"success": True, "controls": controls}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

@router.post("")
def api_create_control(req: CreateControlRequest):
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save control: {e}")

@router.post("/autogen-keywords")
def api_autogen_keywords(req: AutogenKeywordsRequest):
    if not req.name.strip():
        raise HTTPException(status_code=400, detail="Control name is required for keyword generation.")
    
    try:
        keywords = generate_keywords(req.name.strip(), req.description.strip())
        return {"success": True, "keywords": keywords}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI keyword generation failed: {e}")

@router.put("/{db_id}")
def api_update_control(db_id: int, req: UpdateControlRequest):
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database update failed: {e}")

@router.delete("/{db_id}")
def api_delete_control(db_id: int, soft: bool = Query(True, description="Soft delete (deactivate) or hard delete")):
    try:
        success = delete_custom_control(control_db_id=db_id, soft=soft)
        if not success:
            raise HTTPException(status_code=404, detail="Control not found in database.")
        action_type = "deactivated" if soft else "deleted"
        return {"success": True, "message": f"Control successfully {action_type}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database deletion failed: {e}")

@router.get("/framework")
def api_get_framework_controls():
    """Returns combined list of standard ISO/VAPT framework controls and custom controls."""
    try:
        from src.core.controls_data import USE_CASES
        from src.core.bg_worker import _load_custom_use_cases
        
        customs = _load_custom_use_cases(force=True)
        combined = []
        for uc in USE_CASES:
            combined.append({
                "sl": uc["sl"],
                "use_case": uc["use_case"],
                "label": uc["label"],
                "category": uc["category"]
            })
        for c in customs:
            combined.append({
                "sl": c["sl"],
                "use_case": c["use_case"],
                "label": c["label"],
                "category": c["category"]
            })
        return {"success": True, "controls": combined}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/parse-scope-excel")
async def api_parse_scope_excel(file: UploadFile = File(...)):
    """Parses an uploaded auditor scope Excel mapping (.xlsx/.xls) and returns mapped control SLs and custom evidence."""
    if not file.filename.lower().endswith(('.xlsx', '.xls')):
        raise HTTPException(status_code=400, detail="Only Excel files (.xlsx, .xls) are supported.")
        
    try:
        import io
        import re as _re
        import pandas as pd
        from src.core.controls_data import USE_CASES
        
        contents = await file.read()
        df = pd.read_excel(io.BytesIO(contents))
        
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
            raise HTTPException(status_code=400, detail="Columns for 'Control' and 'Evidence' could not be found.")

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
                for uc in USE_CASES:
                    if uc["use_case"].upper().startswith(target_vapt):
                        matched_uc = uc
                        break
            elif match_id:
                target_id = match_id.group(1)
                for uc in USE_CASES:
                    uc_id = uc["use_case"].split(" ")[0]
                    if uc_id == target_id:
                        matched_uc = uc
                        break
            else:
                c_lower = ctrl_val.lower()
                for uc in USE_CASES:
                    uc_id = uc["use_case"].split(" ")[0]
                    uc_uc = str(uc.get("use_case", "")).lower()
                    
                    if 'ntp' in c_lower:
                        if uc_id == "8.17": matched_uc = uc; break
                    elif 'multifactor' in c_lower or 'mfa' in c_lower:
                        if uc_id in ("5.17", "8.5"): matched_uc = uc; break
                    elif 'pam' in c_lower:
                        if uc_id in ("5.15", "8.2", "5.18"): matched_uc = uc; break
                    elif 'fraud' in c_lower:
                        if uc_id in ("5.1", "5.15"): matched_uc = uc; break
                    elif 'archived' in c_lower or 'archival' in c_lower or 'logging' in c_lower:
                        if uc_id in ("8.15", "5.33"): matched_uc = uc; break
                    elif any(k in c_lower for k in ('cpu', 'memory', 'disk', 'utilization')):
                        if uc_id in ("8.16", "8.6"): matched_uc = uc; break
                    elif 'authentication' in c_lower:
                        if uc_id in ("5.17", "5.15"): matched_uc = uc; break
                    elif c_lower in uc_uc:
                        matched_uc = uc; break
                        
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
                matched_sls.add(int(matched_uc["sl"]))

        return {
            "success": True,
            "matched_sls": list(matched_sls),
            "custom_evidence": custom_evidence,
            "custom_documents": custom_documents,
            "total_rows": len(df),
            "message": f"Loaded {len(df)} checklist items across {len(matched_sls)} unique controls!"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse Excel scope file: {e}")

