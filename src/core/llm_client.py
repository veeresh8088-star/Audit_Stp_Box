import os
import threading
import requests
import json
from src.core.port_pool import port_pool_manager

def in_docker():
    return os.path.exists('/.dockerenv')


# ── Round-Robin Load Balancer ─────────────────────────────────────────────────
# When LLM_HOSTS env var is set (e.g. "11434,11436"), requests are distributed
# across all configured LLM instances in a thread-safe round-robin fashion.
# Falls back to single OLLAMA_HOST when LLM_HOSTS is not set.
_rr_lock = threading.Lock()
_rr_index = 0

def _get_next_llm_host():
    """Returns the next LLM host URL in round-robin order."""
    global _rr_index
    hosts_env = os.environ.get("LLM_HOSTS", "").strip()
    if not hosts_env:
        # Single instance mode — use OLLAMA_HOST as before
        return os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").strip()
    # Multi-instance mode — parse comma-separated ports or full URLs
    raw_hosts = [h.strip() for h in hosts_env.split(",") if h.strip()]
    hosts = []
    for h in raw_hosts:
        if h.isdigit():
            hosts.append(f"http://127.0.0.1:{h}")
        elif not h.startswith("http"):
            hosts.append(f"http://{h}")
        else:
            hosts.append(h)
    with _rr_lock:
        host = hosts[_rr_index % len(hosts)]
        _rr_index += 1
    return host

def get_llm_backend():
    """Returns llama.cpp as the sole, dedicated inference engine."""
    return "llama.cpp"

def _resolve_host(url=None, default_port=11434):
    """Resolves host URL."""
    if url is None:
        url = _get_next_llm_host() if default_port == 11434 else f"http://127.0.0.1:{default_port}"
    if url and not url.startswith("http://") and not url.startswith("https://"):
        url = f"http://{url}" if ":" in url else f"http://{url}:{default_port}"
    return url

def _ensure_llama_server_running(port=11434):
    """Auto-detects if llama-server.exe on port 11434 (LLM) or 11435 (Embedding) is offline,
    and automatically spawns it in the background so the platform self-heals."""
    import socket, subprocess, sys, time
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.5)
    try:
        s.connect(("127.0.0.1", port))
        s.close()
        return True # Port is active & healthy!
    except Exception:
        pass
    finally:
        s.close()

    print(f"[AUTO-START LLM] llama-server port {port} is offline. Auto-launching process...", flush=True)
    
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    llama_exe = None
    candidates = [
        r"C:\Users\HP\Downloads\llama,,ccppp mode\llama-server.exe",
        os.path.join(base_dir, "llama-server.exe"),
        r"C:\Users\veeresh988V\Desktop\llama\llama-server.exe"
    ]
    for c in candidates:
        if os.path.exists(c):
            llama_exe = c
            break
            
    if not llama_exe:
        print(f"[AUTO-START LLM] Could not locate llama-server.exe in candidates.", flush=True)
        return False

    if port == 11434:
        model_path = os.path.join(base_dir, "google_gemma-4-E4B-it-Q4_K_M.gguf")
        cmd = [llama_exe, "--port", "11434", "-m", model_path, "-c", "4096", "-np", "2", "-t", "4"]
    else:
        model_path = os.path.join(base_dir, "nomic-embed-text-v1.5.f16.gguf")
        cmd = [llama_exe, "--port", "11435", "-m", model_path, "-t", "4", "--embedding"]

    try:
        creation_flag = subprocess.CREATE_NEW_CONSOLE if sys.platform == "win32" else 0
        subprocess.Popen(cmd, creationflags=creation_flag)
        # Wait up to 25 seconds for model to load into RAM and accept HTTP requests
        for _ in range(25):
            time.sleep(1.0)
            try:
                r_check = requests.get(f"http://127.0.0.1:{port}/health", timeout=1.5)
                if r_check.status_code == 200:
                    print(f"[AUTO-START LLM] Successfully launched llama-server on port {port}!", flush=True)
                    return True
            except Exception:
                pass
        print(f"[AUTO-START LLM] Server process started on port {port}, warming up...", flush=True)
        return True
    except Exception as e:
        print(f"[AUTO-START LLM] Auto-start error on port {port}: {e}", flush=True)
    return False

def query_llm(prompt, model, format=None, num_ctx=16384, temperature=0.0, num_thread=None, timeout=None, stop=None, session_id=None, token_stats=None):
    """Sends a non-streaming prompt completion request exclusively to llama-server.exe."""
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

    with port_pool_manager.acquire_control_slot(session_id=session_id, timeout=timeout) as host:
        if "gemma" in model.lower():
            prompt = f"<start_of_turn>user\n{prompt}<end_of_turn>\n<start_of_turn>model\n"
        url = f"{host}/completion"
        stop_tokens = stop or ["<end_of_turn>", "<eos>", "<|im_end|>", "</s>", "</audit_finding>", "</gap_analysis>", "</vapt_finding>", "</finding>", "```"]

        def _complete(n_predict):
            payload = {
                "prompt": prompt,
                "temperature": temperature,
                "stream": False,
                "n_predict": n_predict,
                "stop": stop_tokens
            }
            if format == "json":
                payload["response_format"] = {"type": "json_object"}
            try:
                r = requests.post(url, json=payload, timeout=timeout)
                if r.status_code != 200:
                    try:
                        from src.core.bg_worker import log_system_event
                        log_system_event("LLM_HTTP_ERROR", "ERROR", f"LLM server returned HTTP {r.status_code}: {r.text[:200]}", session_id=session_id)
                    except Exception: pass
                    raise Exception(f"llama-server.exe error: HTTP {r.status_code} - {r.text}")
                return r.json()
            except (requests.exceptions.ConnectionError, requests.exceptions.RequestException) as _conn_err:
                print(f"[LLM CLIENT] Connection error to {url}: {_conn_err}. Attempting auto-start...", flush=True)
                if _ensure_llama_server_running(11434):
                    r = requests.post(url, json=payload, timeout=timeout)
                    if r.status_code == 200:
                        return r.json()
                raise Exception(f"llama-server.exe connection error on {url}: {_conn_err}")
            except requests.exceptions.Timeout as _to_err:
                try:
                    from src.core.bg_worker import log_system_event
                    log_system_event("LLM_REQUEST_TIMEOUT", "ERROR", f"LLM HTTP request timed out after {timeout}s", session_id=session_id)
                except Exception: pass
                raise

        result = _complete(1536)
        if result.get("stop_type") == "limit":
            # Response was cut off before it finished — retry once with a much larger
            # budget instead of silently returning (and downstream, failing to parse) a
            # truncated answer.
            result = _complete(4096)

        if token_stats is not None:
            # Real counts from the server itself, not a character-count estimate.
            token_stats["prompt_tokens"] = result.get("tokens_evaluated", 0)
            token_stats["completion_tokens"] = result.get("tokens_predicted", 0)

        return result.get("content", "").strip()

def query_llm_stream(prompt, model, num_ctx=16384, temperature=0.0, num_thread=None, session_id=None):
    """Generates streaming tokens from the dedicated llama-server.exe engine.
    Shares the same port_pool_manager slots as query_llm() instead of an independent,
    uncoordinated round-robin — otherwise a streaming and non-streaming call could
    collide on the same in-use slot."""
    with port_pool_manager.acquire_control_slot(session_id=session_id) as host:
        if "gemma" in model.lower():
            prompt = f"<start_of_turn>user\n{prompt}<end_of_turn>\n<start_of_turn>model\n"
        url = f"{host}/completion"
        payload = {
            "prompt": prompt,
            "temperature": temperature,
            "stream": True,
        }
        r = requests.post(url, json=payload, stream=True, timeout=300)
        if r.status_code != 200:
            raise Exception(f"llama-server.exe streaming error: HTTP {r.status_code} - {r.text}")

        for line in r.iter_lines():
            if line:
                decoded = line.decode("utf-8").strip()
                if decoded.startswith("data: "):
                    try:
                        data_json = json.loads(decoded[6:])
                        yield data_json.get("content", "")
                    except Exception:
                        pass

def get_embedding(text, model="nomic-embed-text"):
    """Fetches text embedding vector exclusively from the llama-server.exe embedding endpoint."""
    if not text or not str(text).strip():
        return None

    # Truncate text to 4000 chars to avoid overloading embedding server context
    text_sample = str(text)[:4000]

    host_env = os.environ.get("EMBEDDING_HOST") or os.environ.get("OLLAMA_HOST")
    host = _resolve_host(host_env, default_port=11435)
    embed_timeout = int(os.environ.get("EMBEDDING_TIMEOUT", "60"))

    # Query native llama-server /embedding endpoint
    url = f"{host}/embedding"
    try:
        r = requests.post(url, json={"content": text_sample}, timeout=embed_timeout)
        if r.status_code == 200:
            res_data = r.json()
            if isinstance(res_data, list):
                if res_data and isinstance(res_data[0], list):
                    return res_data[0]
                elif res_data and isinstance(res_data[0], dict):
                    return res_data[0].get("embedding") or res_data[0]
                return res_data
            elif isinstance(res_data, dict):
                emb = res_data.get("embedding")
                if emb:
                    return emb
    except Exception as e_emb:
        if not in_docker():
            print(f"[EMBEDDING RETRY] Connection error on {url}: {e_emb}. Attempting auto-start on 11435...", flush=True)
            _ensure_llama_server_running(11435)


    # Fallback to OpenAI-compatible /v1/embeddings on llama-server.exe
    try:
        url_v1 = f"{host}/v1/embeddings"
        r = requests.post(url_v1, json={"input": text_sample, "model": model}, timeout=embed_timeout)
        if r.status_code == 200:
            data = r.json().get("data")
            if data and isinstance(data, list) and len(data) > 0:
                return data[0].get("embedding")
    except Exception as e:
        print(f"[LLM CLIENT ERROR] Failed to query llama-server.exe embeddings: {e}")
    return None

