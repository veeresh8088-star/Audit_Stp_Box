"""
redis_metrics.py
─────────────────────────────────────────────────────────────────────────────
Redis Live Metrics Helper for AICyberAuditBox Admin Dashboard.

Stores per-session and global telemetry in Redis so the
"Live Server Metrics (Redis Stream)" KPI panel is truly real-time.

Key schema
──────────
  session:{sid}:tokens        INCRBY    total tokens for this session
  session:{sid}:prompt_tokens INCRBY
  session:{sid}:comp_tokens   INCRBY
  session:{sid}:latency_sec   INCRBYFLOAT  cumulative latency seconds
  session:{sid}:files         SET       file count (integer)
  session:{sid}:file_mb       SET       total file size MB (float string)
  session:{sid}:controls      INCRBY    controls evaluated count
  session:{sid}:errors        INCRBY    error/warning count
  session:{sid}:auditor       SET       auditor username
  session:{sid}:status        SET       "running" | "done" | "error"
  session:{sid}:started_at    SET       ISO timestamp
  session:{sid}:updated_at    SET       ISO timestamp (updated on each write)

  global:tokens               INCRBY    grand total tokens across all sessions
  global:latency_sec          INCRBYFLOAT
  global:files                INCRBY
  global:errors               INCRBY
  global:active_sessions      SET       JSON list of active session ids

TTL: each session key expires after 24 hours automatically.
Falls back silently to no-op if Redis is not reachable.
"""

import os
import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

SESSION_TTL = 86400   # 24 hours

_redis_client = None
_redis_available = False


def _get_redis():
    """Lazy-init Redis client with dual-port fallback (6380 / 6379) and auto-reconnect."""
    global _redis_client, _redis_available
    if _redis_client is not None and _redis_available:
        try:
            _redis_client.ping()
            return _redis_client
        except Exception:
            _redis_available = False
            _redis_client = None

    try:
        import redis
        urls_to_try = [
            os.environ.get("REDIS_URL", "redis://127.0.0.1:6380/0"),
            "redis://127.0.0.1:6379/0",
            "redis://127.0.0.1:6380/0"
        ]
        seen = set()
        urls = [u for u in urls_to_try if not (u in seen or seen.add(u))]

        for url in urls:
            try:
                client = redis.from_url(url, decode_responses=True, protocol=2, socket_timeout=1, socket_connect_timeout=1)
                client.ping()
                _redis_client = client
                _redis_available = True
                logger.info(f"[Redis] Connected to {url}")
                return _redis_client
            except Exception:
                continue
    except Exception as e:
        logger.warning(f"[Redis] Import or connection check failed: {e}")

    _redis_available = False
    _redis_client = None
    return None



def _ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def session_start(session_id: str, auditor: str = "SYSTEM", files_count: int = 0, file_mb: float = 0.0):
    """
    Called when an audit session starts.
    Registers the session as 'running' in Redis and adds it to global:active_sessions.
    """
    r = _get_redis()
    if not r:
        return
    try:
        pipe = r.pipeline()
        prefix = f"session:{session_id}"
        pipe.set(f"{prefix}:auditor",    auditor)
        pipe.set(f"{prefix}:status",     "running")
        pipe.set(f"{prefix}:started_at", _ts())
        pipe.set(f"{prefix}:updated_at", _ts())
        pipe.set(f"{prefix}:files",      str(files_count))
        pipe.set(f"{prefix}:file_mb",    str(round(file_mb, 3)))
        pipe.set(f"{prefix}:tokens",     "0")
        pipe.set(f"{prefix}:prompt_tokens", "0")
        pipe.set(f"{prefix}:comp_tokens",   "0")
        pipe.set(f"{prefix}:latency_sec",   "0")
        pipe.set(f"{prefix}:controls",      "0")
        pipe.set(f"{prefix}:errors",        "0")
        for key in [
            f"{prefix}:auditor", f"{prefix}:status", f"{prefix}:started_at",
            f"{prefix}:updated_at", f"{prefix}:files", f"{prefix}:file_mb",
            f"{prefix}:tokens", f"{prefix}:prompt_tokens", f"{prefix}:comp_tokens",
            f"{prefix}:latency_sec", f"{prefix}:controls", f"{prefix}:errors",
        ]:
            pipe.expire(key, SESSION_TTL)

        raw = r.get("global:active_sessions") or "[]"
        try:
            active = json.loads(raw)
        except Exception:
            active = []
        if session_id not in active:
            active.append(session_id)
        pipe.set("global:active_sessions", json.dumps(active))
        pipe.expire("global:active_sessions", SESSION_TTL)
        pipe.incrby("global:files", files_count)
        pipe.expire("global:files", SESSION_TTL)
        pipe.execute()
    except Exception as e:
        logger.warning(f"[Redis] session_start failed: {e}")


def push_control_metrics(session_id: str, prompt_tokens: int, comp_tokens: int, latency_sec: float):
    """
    Called after EACH control is evaluated in bg_worker.py.
    Atomically increments per-session AND global Redis counters.
    """
    r = _get_redis()
    if not r:
        return
    try:
        total_tokens = prompt_tokens + comp_tokens
        pipe = r.pipeline()
        prefix = f"session:{session_id}"
        pipe.incrby(f"{prefix}:tokens",        total_tokens)
        pipe.incrby(f"{prefix}:prompt_tokens", prompt_tokens)
        pipe.incrby(f"{prefix}:comp_tokens",   comp_tokens)
        pipe.incrbyfloat(f"{prefix}:latency_sec", latency_sec)
        pipe.incrby(f"{prefix}:controls", 1)
        pipe.set(f"{prefix}:updated_at", _ts())
        for key in [
            f"{prefix}:tokens", f"{prefix}:prompt_tokens", f"{prefix}:comp_tokens",
            f"{prefix}:latency_sec", f"{prefix}:controls", f"{prefix}:updated_at",
        ]:
            pipe.expire(key, SESSION_TTL)
        pipe.incrby("global:tokens", total_tokens)
        pipe.incrbyfloat("global:latency_sec", latency_sec)
        pipe.expire("global:tokens", SESSION_TTL)
        pipe.expire("global:latency_sec", SESSION_TTL)
        pipe.execute()
    except Exception as e:
        logger.warning(f"[Redis] push_control_metrics failed: {e}")


def push_error(session_id: str):
    """Increment error counter for this session and globally."""
    r = _get_redis()
    if not r:
        return
    try:
        pipe = r.pipeline()
        pipe.incrby(f"session:{session_id}:errors", 1)
        pipe.expire(f"session:{session_id}:errors", SESSION_TTL)
        pipe.incrby("global:errors", 1)
        pipe.expire("global:errors", SESSION_TTL)
        pipe.execute()
    except Exception as e:
        logger.warning(f"[Redis] push_error failed: {e}")


def session_done(session_id: str, status: str = "done"):
    """Mark session as done/error. Moves from active_sessions to completed_sessions.
    Keeps completed sessions visible in admin for SESSION_TTL seconds."""
    r = _get_redis()
    if not r:
        return
    try:
        pipe = r.pipeline()
        pipe.set(f"session:{session_id}:status",     status)
        pipe.set(f"session:{session_id}:updated_at", _ts())
        pipe.expire(f"session:{session_id}:status",     SESSION_TTL)
        pipe.expire(f"session:{session_id}:updated_at", SESSION_TTL)

        # Move from active -> completed (do NOT delete — admin must still see it)
        raw_active = r.get("global:active_sessions") or "[]"
        try:
            active = json.loads(raw_active)
        except Exception:
            active = []
        active = [s for s in active if s != session_id]  # remove from active
        pipe.set("global:active_sessions", json.dumps(active))
        pipe.expire("global:active_sessions", SESSION_TTL)

        # Add to completed_sessions list so admin can still display them
        raw_done = r.get("global:completed_sessions") or "[]"
        try:
            done_list = json.loads(raw_done)
        except Exception:
            done_list = []
        if session_id not in done_list:
            done_list.append(session_id)
        # Keep only the last 50 completed sessions
        done_list = done_list[-50:]
        pipe.set("global:completed_sessions", json.dumps(done_list))
        pipe.expire("global:completed_sessions", SESSION_TTL)
        pipe.execute()
    except Exception as e:
        logger.warning(f"[Redis] session_done failed: {e}")


def get_live_metrics() -> dict:
    """
    Read all live metrics from Redis for the Admin Dashboard KPI panel.
    Returns a dict with global totals and per-session active session details.
    Falls back to empty/zero values if Redis is not available.
    """
    r = _get_redis()
    if not r:
        return {
            "redis_available": False,
            "global_tokens": 0,
            "global_latency_sec": 0.0,
            "global_files": 0,
            "global_errors": 0,
            "active_sessions": [],
        }
    try:
        global_tokens  = int(r.get("global:tokens") or 0)
        global_latency = float(r.get("global:latency_sec") or 0.0)
        global_files   = int(r.get("global:files") or 0)
        global_errors  = int(r.get("global:errors") or 0)

        raw_active = r.get("global:active_sessions") or "[]"
        try:
            active_ids = json.loads(raw_active)
        except Exception:
            active_ids = []

        # ── Build session rows: active first, then completed ──────────────────
        sessions = []
        seen_sids = set()

        def _build_session_row(sid):
            if sid in seen_sids:
                return None
            seen_sids.add(sid)
            status     = r.get(f"session:{sid}:status") or "unknown"
            auditor    = r.get(f"session:{sid}:auditor") or "SYSTEM"
            tokens     = int(r.get(f"session:{sid}:tokens") or 0)
            latency    = float(r.get(f"session:{sid}:latency_sec") or 0.0)
            files      = int(r.get(f"session:{sid}:files") or 0)
            file_mb    = float(r.get(f"session:{sid}:file_mb") or 0.0)
            controls   = int(r.get(f"session:{sid}:controls") or 0)
            errors     = int(r.get(f"session:{sid}:errors") or 0)
            updated_at = r.get(f"session:{sid}:updated_at") or ""
            started_at = r.get(f"session:{sid}:started_at") or ""
            mins = int(latency // 60); secs = round(latency % 60, 1)
            lat_str = f"{mins}m {secs}s" if mins > 0 else f"0m {secs}s"
            return {
                "session_id":  sid,
                "auditor":     auditor,
                "status":      status,
                "tokens":      tokens,
                "latency_sec": round(latency, 1),
                "latency_str": lat_str,
                "files":       files,
                "file_mb":     round(file_mb, 2),
                "controls":    controls,
                "errors":      errors,
                "updated_at":  updated_at,
                "started_at":  started_at,
            }

        # Active sessions first
        for sid in active_ids:
            row = _build_session_row(sid)
            if row:
                sessions.append(row)

        # Completed sessions (most recent last 50, reversed so newest first)
        raw_done = r.get("global:completed_sessions") or "[]"
        try:
            done_ids = list(reversed(json.loads(raw_done)))
        except Exception:
            done_ids = []
        for sid in done_ids:
            row = _build_session_row(sid)
            if row:
                sessions.append(row)

        # Sort: running first, then done by updated_at descending
        def _sort_key(s):
            order = 0 if s["status"] == "running" else (1 if s["status"] == "done" else 2)
            return (order, s.get("updated_at", ""))
        sessions.sort(key=_sort_key)

        g_mins = int(global_latency // 60); g_secs = round(global_latency % 60, 1)
        g_lat_str = f"{g_mins}m {g_secs}s" if g_mins > 0 else f"0m {g_secs}s"
        total_controls = sum(s["controls"] for s in sessions) or 1
        avg_lat = global_latency / max(1, total_controls)
        avg_mins = int(avg_lat // 60); avg_secs = round(avg_lat % 60, 1)
        avg_lat_str = f"{avg_mins}m {avg_secs}s" if avg_mins > 0 else f"0m {avg_secs}s"

        return {
            "redis_available": True,
            "global_tokens":              global_tokens,
            "global_latency_sec":         round(global_latency, 1),
            "global_latency_str":         g_lat_str,
            "avg_latency_per_ctrl_str":   avg_lat_str,
            "global_files":               global_files,
            "global_errors":              global_errors,
            "active_sessions":            sessions,
        }
    except Exception as e:
        logger.warning(f"[Redis] get_live_metrics failed: {e}")
        return {
            "redis_available": False,
            "global_tokens": 0,
            "global_latency_sec": 0.0,
            "global_files": 0,
            "global_errors": 0,
            "active_sessions": [],
        }
