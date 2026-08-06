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
    """Reads LLM_BACKEND env var or auto-detects llama.cpp vs Ollama by probing port 11434."""
    env = os.environ.get("LLM_BACKEND", "").strip().lower()
    if env:
        return env
    # Auto-detect: probe llama.cpp vs Ollama endpoints on 11434
    try:
        host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").strip()
        if not host.startswith("http"):
            host = f"http://{host}"
        r = requests.get(f"{host}/props", timeout=1)
        if r.status_code == 200 and "default_generation_settings" in r.text:
            return "llama.cpp"
    except Exception:
        pass
    return "ollama"

def _resolve_host(url=None, default_port=11434):
    """Resolves host URL. Uses round-robin when LLM_HOSTS is configured."""
    if url is None:
        url = _get_next_llm_host()
    if url and not url.startswith("http://") and not url.startswith("https://"):
        url = f"http://{url}" if ":" in url else f"http://{url}:{default_port}"
    return url

def query_llm(prompt, model, format=None, num_ctx=4096, temperature=0.0, num_thread=None, timeout=1800, stop=None, session_id=None):
    """Sends a non-streaming prompt completion request through port_pool_manager per-port lock."""
    backend = get_llm_backend()
    
    with port_pool_manager.acquire_control_slot(session_id=session_id, timeout=timeout) as host:
        if backend in ("llama.cpp", "llamacpp"):
            if "gemma" in model.lower():
                prompt = f"<start_of_turn>user\n{prompt}<end_of_turn>\n<start_of_turn>model\n"
            url = f"{host}/completion"
            payload = {
                "prompt": prompt,
                "temperature": temperature,
                "stream": False,
                "n_predict": 1024,
                "stop": stop or ["<end_of_turn>", "<eos>", "<|im_end|>", "</s>", "</audit_finding>", "</gap_analysis>", "</vapt_finding>", "</finding>", "```"]
            }
            if format == "json":
                payload["response_format"] = {"type": "json_object"}
                
            r = requests.post(url, json=payload, timeout=timeout)
            if r.status_code == 200:
                return r.json().get("content", "").strip()
            else:
                raise Exception(f"llama.cpp server error: {r.status_code} - {r.text}")
        else:
            # Default: Ollama
            url = f"{host}/api/generate"
            options_dict = {
                "temperature": temperature,
                "num_ctx": num_ctx,
                "num_predict": 1024 if format == "json" else 2048
            }
            if num_thread is not None:
                options_dict["num_thread"] = num_thread
            if stop:
                options_dict["stop"] = stop
                
            payload = {
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": options_dict,
                "keep_alive": "15m"
            }
            if format:
                payload["format"] = format
                
            r = requests.post(url, json=payload, timeout=timeout)
            if r.status_code == 200:
                return r.json().get("response", "").strip()
            elif r.status_code == 404:
                # Fallback check for llama.cpp server running on same host
                l_url = f"{host}/completion"
                l_prompt = f"<start_of_turn>user\n{prompt}<end_of_turn>\n<start_of_turn>model\n" if "gemma" in model.lower() else prompt
                l_payload = {
                    "prompt": l_prompt,
                    "temperature": temperature,
                    "stream": False,
                    "n_predict": 1024,
                    "stop": stop or ["<end_of_turn>", "<eos>", "<|im_end|>", "</s>", "</audit_finding>", "</gap_analysis>", "</vapt_finding>", "</finding>", "```"]
                }
                l_r = requests.post(l_url, json=l_payload, timeout=timeout)
                if l_r.status_code == 200:
                    return l_r.json().get("content", "").strip()
                raise Exception(f"Ollama server error: 404 - Model '{model}' not found or endpoint invalid")
            else:
                raise Exception(f"Ollama server error: {r.status_code} - {r.text}")

def query_llm_stream(prompt, model, num_ctx=4096, temperature=0.0, num_thread=None):
    """Generates streaming tokens from the LLM backend."""
    backend = get_llm_backend()
    host = _resolve_host()
    
    if backend in ("llama.cpp", "llamacpp"):
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
            raise Exception(f"llama.cpp server error: {r.status_code} - {r.text}")
            
        for line in r.iter_lines():
            if line:
                decoded = line.decode("utf-8").strip()
                if decoded.startswith("data: "):
                    try:
                        data_json = json.loads(decoded[6:])
                        yield data_json.get("content", "")
                    except Exception:
                        pass
    else:
        # Default: Ollama
        url = f"{host}/api/generate"
        options_dict = {
            "temperature": temperature,
            "num_ctx": num_ctx
        }
        if num_thread is not None:
            options_dict["num_thread"] = num_thread

        payload = {
            "model": model,
            "prompt": prompt,
            "stream": True,
            "options": options_dict,
            "keep_alive": "15m"
        }
        r = requests.post(url, json=payload, stream=True, timeout=300)
        if r.status_code != 200:
            raise Exception(f"Ollama server error: {r.status_code} - {r.text}")
            
        for line in r.iter_lines():
            if line:
                chunk = json.loads(line)
                yield chunk.get("response", "")

def get_embedding(text, model="nomic-embed-text"):
    """Fetches text embedding vector from the configured embedding backend."""
    if not text or not str(text).strip():
        return None

    # Truncate text to 4000 chars to avoid overloading embedding server context
    text_sample = str(text)[:4000]

    backend = os.environ.get("EMBEDDING_BACKEND", get_llm_backend()).lower()
    
    # Resolving hosting ports (Ollama on 11434, llama.cpp embedding server default on 11435)
    default_port = 11435 if backend in ("llama.cpp", "llamacpp") else 11434
    host_env = os.environ.get("EMBEDDING_HOST") or os.environ.get("OLLAMA_HOST")
    host = _resolve_host(host_env, default_port)
    
    embed_timeout = int(os.environ.get("EMBEDDING_TIMEOUT", "60"))
    if backend in ("llama.cpp", "llamacpp"):
        # native llama.cpp /embedding endpoint
        url = f"{host}/embedding"
        try:
            r = requests.post(url, json={"content": text_sample}, timeout=embed_timeout)
            if r.status_code == 200:
                emb = r.json().get("embedding")
                if emb:
                    return emb
        except Exception:
            # Fallback to OpenAI-compatible /v1/embeddings
            try:
                url_v1 = f"{host}/v1/embeddings"
                r = requests.post(url_v1, json={"input": text_sample, "model": model}, timeout=embed_timeout)
                if r.status_code == 200:
                    data = r.json().get("data")
                    if data and isinstance(data, list) and len(data) > 0:
                        return data[0].get("embedding")
            except Exception as e:
                print(f"[LLM CLIENT ERROR] Failed to query llama.cpp embeddings: {e}")
    else:
        # Default Ollama
        url = f"{host}/api/embeddings"
        try:
            r = requests.post(url, json={"model": model, "prompt": text_sample}, timeout=embed_timeout)
            if r.status_code == 200:
                return r.json().get("embedding")
        except Exception as e:
            print(f"[LLM CLIENT ERROR] Failed to query Ollama embeddings: {e}")
    return None
