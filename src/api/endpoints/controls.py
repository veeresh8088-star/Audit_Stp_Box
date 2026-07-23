from fastapi import APIRouter, HTTPException, Query
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
