import os
import sys
import time
import threading
from contextlib import contextmanager

class LLMPortPoolManager:
    """Enterprise LLM Worker Port Pool & Control-Level Mutex Lock Manager.
    
    Manages pre-warmed LLM worker ports (e.g., 11434, 11435) with per-port mutex locking.
    Provides sub-millisecond (< 1ms) control-level lock release for high-concurrency auditing.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(LLMPortPoolManager, cls).__new__(cls)
                cls._instance._initialize()
            return cls._instance

    def _initialize(self):
        self._pool_lock = threading.Lock()
        self._rr_index = 0
        
        # Determine ports based on environment or hardware CPU count
        hosts_env = os.environ.get("LLM_HOSTS", "").strip()
        if hosts_env:
            raw_ports = [h.strip() for h in hosts_env.split(",") if h.strip()]
            self.ports = []
            for p in raw_ports:
                if p.isdigit():
                    self.ports.append(f"http://127.0.0.1:{p}")
                elif not p.startswith("http"):
                    self.ports.append(f"http://{p}")
                else:
                    self.ports.append(p)
        else:
            # Default completion port is 11434 (11435 is dedicated for embeddings)
            embed_host = os.environ.get("EMBEDDING_HOST", "11435")
            self.ports = ["http://127.0.0.1:11434"]
                
        # Per-port mutex locks to guarantee 0 prompt collisions on any single port
        self.port_locks = {port: threading.Lock() for port in self.ports}
        print(f"[PORT POOL INITIALIZED] Configured {len(self.ports)} LLM worker ports: {self.ports}", flush=True)

    @contextmanager
    def acquire_control_slot(self, session_id=None, timeout=None):
        """Context manager leasing a port mutex lock for 1 control query.
        
        Yields:
            str: Leased port URL (e.g. 'http://127.0.0.1:11434')
        """
        if timeout is None or timeout in (1800, 600):
            try:
                from src.core.redis_metrics import get_live_metrics
                m = get_live_metrics()
                if m.get("redis_available"):
                    active_cnt = max(1, len(m.get("active_sessions", [])))
                else:
                    from src.core.bg_state import _bg_running
                    active_cnt = max(1, len(_bg_running))
                timeout = max(600, active_cnt * 180)
            except Exception:
                timeout = 600

        start_ts = time.time()
        leased_port = None
        
        # Round-Robin port selection
        with self._pool_lock:
            leased_port = self.ports[self._rr_index % len(self.ports)]
            self._rr_index += 1
            
        port_lock = self.port_locks[leased_port]
        acquired = port_lock.acquire(timeout=timeout)
        if not acquired:
            raise TimeoutError(f"Failed to acquire port lock on {leased_port} within {timeout}s for session {session_id}")
            
        t_acquire = (time.time() - start_ts) * 1000
        print(f"[PORT LEASED] Session '{session_id or 'Unknown'}' leased {leased_port} (Lock acquired in {t_acquire:.2f}ms)", flush=True)
        
        try:
            yield leased_port
        finally:
            rel_start = time.time()
            port_lock.release()
            t_release = (time.time() - rel_start) * 1000
            print(f"[PORT RELEASED] Session '{session_id or 'Unknown'}' released {leased_port} (Sub-ms release: {t_release:.3f}ms)", flush=True)

# Singleton global instance
port_pool_manager = LLMPortPoolManager()
