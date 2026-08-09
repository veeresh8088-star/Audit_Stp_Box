import os
import threading
import requests
import json
from src.core.port_pool import port_pool_manager

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
    """Resolves host URL. Round-robin (LLM_HOSTS) only applies to the standard completion
    port — callers asking for a different port (e.g. the embedding server) get that port
    directly instead of silently landing on the completion server."""
    if url is None:
        url = _get_next_llm_host() if default_port == 11434 else f"http://127.0.0.1:{default_port}"
    if url and not url.startswith("http://") and not url.startswith("https://"):
        url = f"http://{url}" if ":" in url else f"http://{url}:{default_port}"
    return url

def query_llm(prompt, model, format=None, num_ctx=4096, temperature=0.0, num_thread=None, timeout=None, stop=None, session_id=None, token_stats=None):
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
            r = requests.post(url, json=payload, timeout=timeout)
            if r.status_code != 200:
                raise Exception(f"llama-server.exe error: HTTP {r.status_code} - {r.text}")
            return r.json()

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

def query_llm_stream(prompt, model, num_ctx=4096, temperature=0.0, num_thread=None, session_id=None):
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
            emb = r.json().get("embedding")
            if emb:
                return emb
    except Exception:
        pass

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

