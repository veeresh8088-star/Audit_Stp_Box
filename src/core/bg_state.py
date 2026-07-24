import threading

def _get_bg_store():
    if not hasattr(_get_bg_store, "_instance"):
        _get_bg_store._instance = {
            "results": {},
            "running": set(),
            "progress": {},
            "lock": threading.Lock(),
            "summaries": {}
        }
    return _get_bg_store._instance

_bg_store = _get_bg_store()
_bg_results = _bg_store["results"]
_bg_running = _bg_store["running"]
_bg_lock = _bg_store["lock"]

# Stop flags: bg_key -> True means "please stop this scan"
_bg_stop_flags: dict = {}
