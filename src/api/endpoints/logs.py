from fastapi import APIRouter, HTTPException, Query
from typing import Optional
import os
from src.db.database import (
    SessionLocal, 
    SystemEvent, 
    AuditTrail, 
    purge_old_logs,
    force_master
)

router = APIRouter(prefix="/logs", tags=["Admin Logs"])

LOG_PATH = "data/audit_run_latency.log"

@router.get("/system")
def api_get_system_events(
    severity: str = Query("All", description="Filter by severity level"),
    event_type: str = Query("", description="Filter by event type substring"),
    page: int = Query(0, ge=0),
    page_size: int = Query(20, ge=1, le=100)
):
    db = SessionLocal()
    try:
        query = db.query(SystemEvent)
        if severity != "All":
            query = query.filter(SystemEvent.severity == severity)
        if event_type.strip():
            query = query.filter(SystemEvent.event_type.ilike(f"%{event_type.strip()}%"))
        
        total_count = query.count()
        rows = query.order_by(SystemEvent.created_at.desc()).offset(page * page_size).limit(page_size).all()
        
        events = []
        for r in rows:
            events.append({
                "id": r.id,
                "event_type": r.event_type,
                "actor": r.actor,
                "session_id": r.session_id,
                "framework": r.framework,
                "meta": r.meta,
                "severity": r.severity,
                "created_at": str(r.created_at)
            })
        return {
            "success": True, 
            "events": events, 
            "page": page, 
            "page_size": page_size, 
            "total_count": total_count,
            "total_pages": (total_count + page_size - 1) // page_size
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch system events: {e}")
    finally:
        db.close()

@router.get("/audit-trail")
def api_get_audit_trail(
    page: int = Query(0, ge=0),
    page_size: int = Query(20, ge=1, le=100)
):
    db = SessionLocal()
    try:
        query = db.query(AuditTrail)
        total_count = query.count()
        rows = query.order_by(AuditTrail.run_date.desc()).offset(page * page_size).limit(page_size).all()
        
        trail = []
        for r in rows:
            trail.append({
                "id": r.id,
                "audit_id": r.audit_id,
                "document_name": r.document_name,
                "standard": r.standard,
                "model_used": r.model_used,
                "run_date": str(r.run_date),
                "total_controls": r.total_controls
            })
        return {
            "success": True,
            "trail": trail,
            "page": page,
            "page_size": page_size,
            "total_count": total_count,
            "total_pages": (total_count + page_size - 1) // page_size
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch audit trail: {e}")
    finally:
        db.close()

@router.get("/developer")
def api_get_developer_logs():
    if not os.path.exists(LOG_PATH):
        return {"success": True, "logs": "", "message": "No logs recorded yet."}
    
    try:
        with open(LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
            logs = f.read()
        return {"success": True, "logs": logs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read developer log file: {e}")

@router.delete("/developer")
def api_clear_developer_logs():
    try:
        if os.path.exists(LOG_PATH):
            os.remove(LOG_PATH)
            return {"success": True, "message": "Developer log file successfully cleared."}
        return {"success": True, "message": "No log file existed to delete."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete log file: {e}")

@router.post("/purge")
def api_purge_logs(days: int = Query(90, ge=1)):
    try:
        deleted = purge_old_logs(days=days)
        return {"success": True, "message": f"Successfully purged {deleted} events older than {days} days."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to purge logs: {e}")
