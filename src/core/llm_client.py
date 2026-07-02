import os
import requests
import json

def get_llm_backend():
    """Reads LLM_BACKEND env var. Returns 'ollama' or 'llama.cpp'."""
    return os.environ.get("LLM_BACKEND", "ollama").strip().lower()

def _resolve_host(url=None, default_port=11434):
    """Resolves host URL, prepending http:// and appending default port if missing."""
    if url is None:
        url = os.environ.get("OLLAMA_HOST", f"http://127.0.0.1:{default_port}").strip()
    if url and not url.startswith("http://") and not url.startswith("https://"):
        url = f"http://{url}" if ":" in url else f"http://{url}:{default_port}"
    return url

def query_llm(prompt, model, format=None, num_ctx=4096, temperature=0.0, num_thread=4, timeout=900):
    """Sends a non-streaming prompt completion request to the configured LLM backend."""
    backend = get_llm_backend()
    host = _resolve_host()
    
    if backend in ("llama.cpp", "llamacpp"):
        url = f"{host}/completion"
        payload = {
            "prompt": prompt,
            "temperature": temperature,
            "stream": False,
            "n_predict": 1024 if format == "json" else 2048,
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
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_ctx": num_ctx,
                "num_thread": num_thread
            },
            "keep_alive": "15m"
        }
        if format:
            payload["format"] = format
            
        r = requests.post(url, json=payload, timeout=timeout)
        if r.status_code == 200:
            return r.json().get("response", "").strip()
        else:
            raise Exception(f"Ollama server error: {r.status_code} - {r.text}")

def query_llm_stream(prompt, model, num_ctx=4096, temperature=0.0, num_thread=4):
    """Generates streaming tokens from the LLM backend."""
    backend = get_llm_backend()
    host = _resolve_host()
    
    if backend in ("llama.cpp", "llamacpp"):
        url = f"{host}/completion"
        payload = {
            "prompt": prompt,
            "temperature": temperature,
            "stream": True,
        }
        r = requests.post(url, json=payload, stream=True, timeout=90)
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
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": True,
            "options": {
                "temperature": temperature,
                "num_ctx": num_ctx,
                "num_thread": num_thread
            },
            "keep_alive": "15m"
        }
        r = requests.post(url, json=payload, stream=True, timeout=90)
        if r.status_code != 200:
            raise Exception(f"Ollama server error: {r.status_code} - {r.text}")
            
        for line in r.iter_lines():
            if line:
                chunk = json.loads(line)
                yield chunk.get("response", "")

def get_embedding(text, model="nomic-embed-text"):
    """Fetches text embedding vector from the configured embedding backend."""
    backend = os.environ.get("EMBEDDING_BACKEND", get_llm_backend()).lower()
    
    # Resolving hosting ports (Ollama on 11434, llama.cpp embedding server default on 11435)
    default_port = 11435 if backend in ("llama.cpp", "llamacpp") else 11434
    host_env = os.environ.get("EMBEDDING_HOST") or os.environ.get("OLLAMA_HOST")
    host = _resolve_host(host_env, default_port)
    
    if backend in ("llama.cpp", "llamacpp"):
        # native llama.cpp /embedding endpoint
        url = f"{host}/embedding"
        try:
            r = requests.post(url, json={"content": text}, timeout=60)
            if r.status_code == 200:
                return r.json().get("embedding")
        except Exception:
            # Fallback to OpenAI-compatible /v1/embeddings
            try:
                url_v1 = f"{host}/v1/embeddings"
                r = requests.post(url_v1, json={"input": text, "model": model}, timeout=60)
                if r.status_code == 200:
                    return r.json().get("data")[0].get("embedding")
            except Exception as e:
                print(f"[LLM CLIENT ERROR] Failed to query llama.cpp embeddings: {e}")
    else:
        # Default Ollama
        url = f"{host}/api/embeddings"
        try:
            r = requests.post(url, json={"model": model, "prompt": text}, timeout=15)
            if r.status_code == 200:
                return r.json().get("embedding")
        except Exception as e:
            print(f"[LLM CLIENT ERROR] Failed to query Ollama embeddings: {e}")
    return None
