# -*- coding: utf-8 -*-
"""
Retrieval Module
Contains document chunk cache, save_document_chunks, and context retrieval logic.
Decoupled from app.py to prevent circular dependencies.
"""

import os
import re
import json
import requests
import hashlib
import concurrent.futures
from src.db.database import SessionLocal, DocumentChunk, force_master

# Global cache for chunks ingested during upload processing
_ingested_chunks_cache = {}

import pickle
CACHE_FILE = os.path.join(os.path.dirname(__file__), ".embeddings_cache.pkl")
_chunk_embeddings_cache = {}
if os.path.exists(CACHE_FILE):
    try:
        with open(CACHE_FILE, "rb") as f:
            _chunk_embeddings_cache = pickle.load(f)
        print(f"[EMBEDDING CACHE] Loaded {len(_chunk_embeddings_cache)} persistent embeddings from cache.", flush=True)
    except Exception as e:
        print(f"[EMBEDDING CACHE] Warning: failed to load persistent cache: {e}", flush=True)

# ── Native vector engine (sqlite-vec or pgvector) ────────────────────────────
# Lazy-initialised on first retrieval call to allow DB to boot first.
_native_vec_engine = None
_native_vec_lock = concurrent.futures.ThreadPoolExecutor.__new__

def _get_native_vec_engine():
    """Lazy-initialises and returns the best available native vector engine."""
    global _native_vec_engine
    if _native_vec_engine is None:
        try:
            from src.db.database import engine_master
            if engine_master is not None and engine_master.dialect.name == "postgresql":
                _native_vec_engine = _init_pgvector(engine_master)
            else:
                _native_vec_engine = _init_sqlite_vec()
        except Exception as e:
            print(f"[VEC SEARCH] Engine init failed ({e}); using Python cosine.", flush=True)
            _native_vec_engine = "python"  # sentinel: use Python fallback
    return _native_vec_engine

def _init_sqlite_vec():
    """Initialises sqlite-vec shadow table next to the active SQLite file."""
    try:
        import sqlite_vec, sqlite3, struct
        from src.db.database import engine_master
        if engine_master is None:
            return "python"
        db_url = str(engine_master.url)
        db_path = db_url.replace("sqlite:///", "").replace("sqlite://", "")
        if not os.path.exists(db_path):
            return "python"
        # timeout=0: fail instantly on lock (no waiting), WAL mode for concurrent reads
        conn = sqlite3.connect(db_path, check_same_thread=False, timeout=0)
        conn.execute("PRAGMA journal_mode=WAL")  # WAL: multiple readers + 1 writer simultaneously
        conn.enable_load_extension(True)
        sqlite_vec.load(conn)
        conn.enable_load_extension(False)
        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS vec_chunks
            USING vec0(chunk_id INTEGER PRIMARY KEY, embedding FLOAT[768])
        """)
        conn.commit()
        conn.close()
        print(f"[VEC SEARCH] sqlite-vec native engine ready (db: {db_path}).", flush=True)
        return {"type": "sqlite-vec", "db_path": db_path}
    except ImportError:
        print("[VEC SEARCH] sqlite-vec not installed; using Python cosine.", flush=True)
        return "python"
    except Exception as e:
        print(f"[VEC SEARCH] sqlite-vec init failed ({e}); using Python cosine.", flush=True)
        return "python"

def _init_pgvector(pg_engine):
    """Initialises pgvector extension and HNSW index on PostgreSQL."""
    try:
        from sqlalchemy import text
        with pg_engine.begin() as conn:
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS pg_vec_chunks (
                    chunk_id INTEGER PRIMARY KEY,
                    embedding vector(768)
                )"""))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_pg_vec_hnsw
                ON pg_vec_chunks USING hnsw (embedding vector_cosine_ops)
                WITH (m=16, ef_construction=64)"""))
        print("[VEC SEARCH] pgvector HNSW engine ready.", flush=True)
        return {"type": "pgvector", "engine": pg_engine}
    except Exception as e:
        print(f"[VEC SEARCH] pgvector init failed ({e}); using Python cosine.", flush=True)
        return "python"

def _vec_store_embedding(chunk_db_id, vector, engine):
    """Store a single embedding in the native vector engine."""
    if engine is None or engine == "python" or vector is None:
        return
    try:
        if engine.get("type") == "sqlite-vec":
            import sqlite_vec, sqlite3, struct
            packed = struct.pack(f"{len(vector)}f", *vector)
            # timeout=0: if DB is locked by another user, skip instantly (no waiting)
            conn = sqlite3.connect(engine["db_path"], check_same_thread=False, timeout=0)
            conn.enable_load_extension(True)
            sqlite_vec.load(conn)
            conn.enable_load_extension(False)
            conn.execute("INSERT OR REPLACE INTO vec_chunks(chunk_id, embedding) VALUES (?, ?)",
                         (chunk_db_id, packed))
            conn.commit()
            conn.close()
        elif engine.get("type") == "pgvector":
            from sqlalchemy import text
            vec_str = "[" + ",".join(str(v) for v in vector) + "]"
            with engine["engine"].begin() as conn:
                conn.execute(text("""
                    INSERT INTO pg_vec_chunks (chunk_id, embedding) VALUES (:cid, :emb::vector)
                    ON CONFLICT (chunk_id) DO UPDATE SET embedding = EXCLUDED.embedding
                """), {"cid": chunk_db_id, "emb": vec_str})
    except Exception:
        pass  # Never crash audit on vector storage failure — next run will retry

def _vec_native_search(query_vector, filenames, top_k, engine):
    """Perform KNN search using native engine. Returns {chunk_db_id: similarity}."""
    if engine is None or engine == "python" or query_vector is None:
        return {}
    try:
        if engine.get("type") == "sqlite-vec":
            import sqlite_vec, sqlite3, struct
            packed_q = struct.pack(f"{len(query_vector)}f", *query_vector)
            # timeout=0: if DB is locked, fail instantly — never wait — Python cosine takes over
            conn = sqlite3.connect(engine["db_path"], check_same_thread=False, timeout=0)
            conn.enable_load_extension(True)
            sqlite_vec.load(conn)
            conn.enable_load_extension(False)
            if filenames:
                placeholders = ",".join(["?"]*len(filenames))
                sql = (f"SELECT vc.chunk_id, vc.distance FROM vec_chunks vc "
                       f"JOIN document_chunks dc ON dc.id=vc.chunk_id "
                       f"WHERE dc.filename IN ({placeholders}) "
                       f"AND vc.embedding MATCH ? AND K=? ORDER BY vc.distance")
                rows = conn.execute(sql, [*filenames, packed_q, top_k*4]).fetchall()
            else:
                rows = conn.execute(
                    "SELECT chunk_id, distance FROM vec_chunks WHERE embedding MATCH ? AND K=? ORDER BY distance",
                    [packed_q, top_k*4]).fetchall()
            conn.close()
            return {r[0]: max(0.0, 1.0-(r[1]/2.0)) for r in rows}
        elif engine.get("type") == "pgvector":
            from sqlalchemy import text
            vec_str = "[" + ",".join(str(v) for v in query_vector) + "]"
            if filenames:
                sql = text("SELECT pvc.chunk_id, 1-(pvc.embedding <=> :vec_str::vector) AS sim "
                           "FROM pg_vec_chunks pvc JOIN document_chunks dc ON dc.id=pvc.chunk_id "
                           "WHERE dc.filename = ANY(:fn_list) ORDER BY sim DESC LIMIT :top_k_val")
                params = {"vec_str": vec_str, "fn_list": list(filenames), "top_k_val": top_k * 4}
            else:
                sql = text("SELECT chunk_id, 1-(embedding <=> :vec_str::vector) AS sim "
                           "FROM pg_vec_chunks ORDER BY sim DESC LIMIT :top_k_val")
                params = {"vec_str": vec_str, "top_k_val": top_k * 4}
            with engine["engine"].begin() as conn:
                rows = conn.execute(sql, params).fetchall()
            return {r[0]: float(r[1]) for r in rows}
    except Exception as e:
        print(f"[VEC SEARCH] Native search error ({e}); falling back to Python cosine.", flush=True)
    return {}

# Cross-Encoder lazy-loading variables
_RERANKER_MODEL = None
_RERANKER_ACTIVE_MODE = None

def get_reranker(mode="quick"):
    """Lazy-loads and caches the selected Cross-Encoder model.
    Toggles loaded models dynamically to prevent excessive RAM usage.
    """
    global _RERANKER_MODEL, _RERANKER_ACTIVE_MODE
    
    # Map friendly modes to Hugging Face models
    model_name = "cross-encoder/ms-marco-MiniLM-L-6-v2" if mode == "quick" else "BAAI/bge-reranker-base"
    
    if _RERANKER_MODEL is None or _RERANKER_ACTIVE_MODE != mode:
        # If another model is active, unload it first to protect RAM
        if _RERANKER_MODEL is not None:
            print(f"[RERANKER] Unloading active model '{_RERANKER_ACTIVE_MODE}' to free memory...", flush=True)
            _RERANKER_MODEL = None
            import gc
            gc.collect()
            
        try:
            from sentence_transformers import CrossEncoder
            print(f"[RERANKER] Loading model '{model_name}' (Mode: {mode.upper()}). First run will download file...", flush=True)
            _RERANKER_MODEL = CrossEncoder(model_name, max_length=512)
            _RERANKER_ACTIVE_MODE = mode
            print(f"[RERANKER] Model '{model_name}' loaded successfully.", flush=True)
        except Exception as e:
            print(f"[RERANKER ERROR] Failed to load CrossEncoder model '{model_name}': {e}", flush=True)
            
    return _RERANKER_MODEL

# Configurable defaults for retrieval
DEFAULT_TOP_K = {
    "pdf": 12,
    "docx": 12,
    "txt": 12,
    "xlsx": 12,
    "csv": 12,
    "pptx": 12,
    "image": 12
}



def load_top_k_config():
    config_path = os.path.join("config", "retrieval_config.json")
    config = dict(DEFAULT_TOP_K)
    
    if not os.path.exists(config_path):
        try:
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            with open(config_path, "w") as cf:
                json.dump(DEFAULT_TOP_K, cf, indent=4)
        except Exception as e:
            print(f"[CONFIG ERROR] Failed to write default retrieval_config.json: {e}")
            
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as cf:
                file_config = json.load(cf)
                for k, v in file_config.items():
                    if k in config and isinstance(v, int):
                        config[k] = v
            print(f"[CONFIG] Loaded custom TOP_K overrides: {file_config}")
        except Exception as e:
            print(f"[CONFIG ERROR] Failed to load retrieval_config.json: {e}")
            
    return config

def save_document_chunks(filename, text):
    """Splits a document text into overlapping paragraph windows (> 40 chars), prepends parent section headers, and writes to ShaktiDB."""
    session = SessionLocal()
    try:
        with force_master():
            # Delete existing chunks for this file to prevent duplicates
            session.query(DocumentChunk).filter(DocumentChunk.filename == filename).delete()

            # Purge this filename's cached embeddings too. The cache is keyed by
            # (filename, chunk_index), not content -- if a file gets re-uploaded with
            # revised content under the same name, stale (filename, index) keys would
            # otherwise survive and get silently reused for the new chunk text, since
            # the embedding step only computes a fresh vector when the key is missing.
            stale_keys = [k for k in _chunk_embeddings_cache if k[0] == filename]
            if stale_keys:
                for k in stale_keys:
                    del _chunk_embeddings_cache[k]
                try:
                    with open(CACHE_FILE, "wb") as f:
                        pickle.dump(_chunk_embeddings_cache, f)
                except Exception as e:
                    print(f"[EMBEDDING CACHE] Warning: failed to persist cache after purge: {e}", flush=True)
                print(f"[EMBEDDING CACHE] Purged {len(stale_keys)} stale embedding(s) for re-uploaded file '{filename}'.", flush=True)

            cached_chunks = _ingested_chunks_cache.get(filename)
            if cached_chunks:
                chunks_saved = 0
                for idx, (p_content, metadata) in enumerate(cached_chunks):
                    # Split custom chunk content (Parent) into child sentences
                    sentences = []
                    raw_s = re.split(r'(?<=[.!?])\s+', p_content)
                    for s in raw_s:
                        s_strip = s.strip()
                        if len(s_strip.split()) >= 4:
                            sentences.append(s_strip)
                    if not sentences:
                        sentences = [p_content]
                        
                    for s_idx, sentence in enumerate(sentences):
                        child_metadata = dict(metadata)
                        child_metadata["parent_context"] = p_content
                        child_metadata["sentence_index"] = s_idx
                        
                        # Prepend context to the sentence vector to maintain scoping context
                        child_content = sentence
                        if metadata.get("section_heading"):
                            child_content = f"[{metadata['section_heading']}] {child_content}"
                        elif metadata.get("slide_title"):
                            child_content = f"[{metadata['slide_title']}] {child_content}"
                        elif metadata.get("sheet_name"):
                            child_content = f"[{metadata['sheet_name']}] {child_content}"
                            
                        chunk_id = hashlib.md5(f"{filename}_{idx}_{s_idx}_{child_content}".encode('utf-8')).hexdigest()[:8]
                        child_metadata["chunk_id"] = f"chunk_{chunk_id}"
                        
                        db_chunk = DocumentChunk(
                            filename=filename,
                            chunk_index=chunks_saved,
                            content=child_content,
                            metadata_json=json.dumps(child_metadata),
                            source_file=child_metadata.get("source_file"),
                            source_type=child_metadata.get("source_type"),
                            chunk_id=child_metadata.get("chunk_id")
                        )
                        session.add(db_chunk)
                        chunks_saved += 1
                session.commit()
                print(f"[RAG] Successfully stored {chunks_saved} pointwise parent-child custom cached chunks for '{filename}' in database.")
                return

            # Fallback split into double newlines chunks (paragraphs)
            # Minimum 8 words (more reliable than 40 chars for ISO policy text)
            MAX_CHUNK_CHARS = 2000  # raised from 1200 to prevent silent truncation of document sections
            raw_paragraphs = [p.strip() for p in text.split('\n\n') if len(p.strip().split()) >= 8]
            
            # Prevent silent truncation: if any paragraph is longer than 800 characters,
            # split it by single newlines so it fits cleanly in sliding windows.
            paragraphs = []
            for rp in raw_paragraphs:
                if len(rp) > 800:
                    sub_paras = [sp.strip() for sp in rp.split('\n') if len(sp.strip().split()) >= 4]
                    paragraphs.extend(sub_paras)
                else:
                    paragraphs.append(rp)
            
            # Fallback to single newline paragraphs if double newline yields no results,
            # or if the split resulted in too few, very long blocks (often happens with pdfplumber text).
            if not paragraphs or len(paragraphs) <= 5 or (len(paragraphs) > 0 and sum(len(p) for p in paragraphs) / len(paragraphs) > 1200):
                lines = text.split('\n')
                paragraphs = []
                cur = []
                SECTION_START = re.compile(r'^(?:\d+\.\d+|\d+\.\d+\.\d+|\d+\.)\b|^\s*[●○\-\*]\s')
                for l in lines:
                    val = l.strip()
                    if not val:
                        continue
                    is_new = False
                    if cur:
                        if SECTION_START.match(val):
                            is_new = True
                        else:
                            last_line = cur[-1]
                            if last_line and last_line[-1] in ('.', '?', '!', '"', '”'):
                                if not last_line.endswith("i.e.") and not last_line.endswith("e.g.") and not last_line.endswith("approx."):
                                    if val[0].isupper() or val[0].isdigit():
                                        is_new = True
                    if is_new and cur:
                        paragraphs.append(" ".join(cur))
                        cur = []
                    cur.append(val)
                if cur:
                    paragraphs.append(" ".join(cur))
                paragraphs = [p for p in paragraphs if len(p.split()) >= 8]
                
            HEADER_REGEX = re.compile(
                r'^\s*(?:Clause\s+|Section\s+)?(\d+(?:\.\d+)*)\b', 
                re.IGNORECASE
            )
            
            current_section = ""
            section_aware_paras = []
            for p in paragraphs:
                p_str = p.strip()
                match = HEADER_REGEX.match(p_str)
                if match and len(p_str) < 120:
                    current_section = p_str
                section_aware_paras.append((current_section, p_str))
                
            # Store sliding windows of 3 paragraphs, stride = 1
            window_size = 3
            stride = 1
            chunks_saved = 0
            for idx in range(0, len(section_aware_paras), stride):
                window_data = section_aware_paras[idx : idx + window_size]
                if not window_data:
                    break
                
                # Retrieve the most specific/recent section header for the window
                window_section = ""
                for sec, _ in window_data:
                    if sec:
                        window_section = sec
                        
                window_paras = [p for _, p in window_data]
                p_text = "\n\n".join(window_paras)
                # Keep raw parent context without section wrapper in metadata if we want it clean
                p_parent = p_text
                if window_section:
                    p_text = f"[{window_section}]\n{p_text}"
                # Hard cap: split oversized chunks (e.g. dense PDF pages) at sentence boundaries
                if len(p_text) > MAX_CHUNK_CHARS:
                    # Find the last sentence boundary before the cap
                    cut = p_text.rfind('.', 0, MAX_CHUNK_CHARS)
                    if cut == -1:
                        cut = MAX_CHUNK_CHARS
                    p_text = p_text[:cut + 1].strip()
                    p_parent = p_text

                # Split parent context into child sentences
                sentences = []
                raw_s = re.split(r'(?<=[.!?])\s+', p_text)
                for s in raw_s:
                    s_strip = s.strip()
                    if len(s_strip.split()) >= 4:
                        sentences.append(s_strip)
                if not sentences:
                    sentences = [p_text]

                for s_idx, sentence in enumerate(sentences):
                    _, ext = os.path.splitext(filename.lower())
                    SUPPORTED_TYPES_LOCAL = {
                        ".pdf": "pdf",   ".docx": "docx", ".doc": "docx",
                        ".txt": "txt",   ".xlsx": "xlsx",  ".xls": "xlsx",
                        ".csv": "csv",   ".pptx": "pptx",  ".ppt": "pptx",
                        ".html": "html", ".htm": "html",
                        ".png": "image", ".jpg": "image",   ".jpeg": "image"
                    }
                    src_type = SUPPORTED_TYPES_LOCAL.get(ext, ext.lstrip(".") if ext else "txt")
                    
                    child_metadata = {
                        "source_file": filename,
                        "source_type": src_type,
                        "section_heading": window_section,
                        "parent_context": p_parent,
                        "sentence_index": s_idx,
                        "chunk_id": f"chunk_fallback_{idx}_{s_idx}"
                    }
                    
                    child_content = sentence
                    # If the split sentence doesn't have the section prefix, add it to help vector retrieval
                    if window_section and not sentence.startswith('['):
                        child_content = f"[{window_section}] {sentence}"
                        
                    chunk = DocumentChunk(
                        filename=filename,
                        chunk_index=chunks_saved,
                        content=child_content,
                        metadata_json=json.dumps(child_metadata),
                        source_file=child_metadata.get("source_file"),
                        source_type=child_metadata.get("source_type"),
                        chunk_id=child_metadata.get("chunk_id")
                    )
                    session.add(chunk)
                    chunks_saved += 1
                
            session.commit()
            print(f"[RAG] Successfully stored {chunks_saved} fallback overlapping chunks for '{filename}' in database.")
    except Exception as e:
        session.rollback()
        print(f"[RAG ERROR] Failed to save document chunks for '{filename}': {e}")
    finally:
        _ingested_chunks_cache.pop(filename, None)
        session.close()

def _get_ollama_embedding(text, model="nomic-embed-text", url=None):
    try:
        from src.core.llm_client import get_embedding
        return get_embedding(text, model=model)
    except Exception as e:
        print(f"[HYBRID RAG WARNING] Failed to get embedding for text: {e}")
    return None

def _cosine_similarity(v1, v2):
    dot_product = sum(x * y for x, y in zip(v1, v2))
    norm_v1 = sum(x * x for x in v1) ** 0.5
    norm_v2 = sum(x * x for x in v2) ** 0.5
    if norm_v1 == 0 or norm_v2 == 0:
        return 0.0
    return dot_product / (norm_v1 * norm_v2)

def _retrieve_rag_context(context, controls_batch, file_names_list, llm_model, KEYWORD_SYNONYMS):
    """Production RAG retrieval engine.
    Phase 3: Multi-document evidence aggregation — searches ALL uploaded files simultaneously.
    Phase 4: Pipeline: keyword scoring -> exact dedup -> Jaccard near-dedup -> diversity -> rank.
    Phase 5: Token-budget accumulation: TARGET=4000 tokens, HARD_MAX=5000 tokens.
    Phase 8: Returns retrieved_chunk_metas for evidence source provenance.
    """
    # Token budget: dynamically configurable via env vars (defaults: 3000 / 5000 tokens)
    TARGET_CONTEXT_TOKENS = int(os.environ.get("TARGET_CONTEXT_TOKENS", "3000"))
    HARD_MAX_CONTEXT_TOKENS = int(os.environ.get("HARD_MAX_CONTEXT_TOKENS", "5000"))

    # Smart Vector Chunking for ALL documents (no bypass).
    # All documents go through: Parent-Child Sentence Windows →
    # Hybrid Keyword+Vector Scoring → Cross-Encoder Reranking.
    # Fallback to full text at line ~671 if chunking yields nothing.
    print(f"[RAG SMART CHUNK] Document text is {len(context)} chars. Routing through full Smart Vector Chunking pipeline.", flush=True)

    # 1. Ensure chunks exist for ALL uploaded files
    chunks_count = 0
    session = SessionLocal()
    try:
        chunks_count = session.query(DocumentChunk).filter(DocumentChunk.filename.in_(file_names_list)).count()
    except Exception as db_verify_err:
        print(f"[RAG WARNING] Failed to verify chunks count: {db_verify_err}")
    finally:
        session.close()

    if chunks_count == 0:
        print(f"[RAG] No chunks found for {file_names_list}. Ingesting on-the-fly...")
        primary_file = file_names_list[0] if file_names_list else "default_document.pdf"
        try:
            save_document_chunks(primary_file, context)
        except Exception as ingest_err:
            print(f"[RAG WARNING] Failed to ingest chunks: {ingest_err}")

    # 2. Load ALL chunks from ALL uploaded files
    session = SessionLocal()
    db_chunks = []
    try:
        db_chunks = session.query(DocumentChunk).filter(DocumentChunk.filename.in_(file_names_list)).all()
    except Exception as db_query_err:
        print(f"[RAG WARNING] Database query failed: {db_query_err}")
    finally:
        session.close()

    SUPPORTED_TYPES_LOCAL = {
        ".pdf": "pdf",   ".docx": "docx", ".doc": "docx",
        ".txt": "txt",   ".xlsx": "xlsx",  ".xls": "xlsx",
        ".csv": "csv",   ".pptx": "pptx",  ".ppt": "pptx",
        ".html": "html", ".htm": "html",
        ".png": "image", ".jpg": "image",   ".jpeg": "image"
    }
    type_counts = {}
    for fname in file_names_list:
        _, ext = os.path.splitext(fname.lower())
        ftype = SUPPORTED_TYPES_LOCAL.get(ext, "pdf")
        type_counts[ftype] = type_counts.get(ftype, 0) + 1
    file_type = max(type_counts, key=type_counts.get) if type_counts else "pdf"

    top_k_config = load_top_k_config()
    configured_top_k = top_k_config.get(file_type, 15)


    # Fallback: paragraph split from raw context if DB empty
    paragraphs = []
    if not db_chunks:
        paragraphs = [p.strip() for p in context.split('\n\n') if p.strip()]
        if not paragraphs:
            paragraphs = [context]

    # Keyword synonyms expansion
    expanded_terms = set()
    for c in controls_batch:
        raw_words = set(re.findall(r'\b[a-zA-Z0-9_\-]{3,}\b', c['control'].lower()))
        raw_words.update(re.findall(r'\b[a-zA-Z0-9_\-]{3,}\b', c.get('label', '').lower()))
        for w in raw_words:
            expanded_terms.add(w)
            if w in KEYWORD_SYNONYMS:
                for syn in KEYWORD_SYNONYMS[w]:
                    expanded_terms.add(syn.lower())

    # Build weighted keyword dictionary
    batch_keywords = {}
    for c in controls_batch:
        c_keywords = c.get('keywords', {})
        if not c_keywords:
            c_keywords = {}
            for w in re.findall(r'\b[a-zA-Z0-9_\-]{3,}\b', c['control'].lower()):
                c_keywords[w] = 2.0
            for w in re.findall(r'\b[a-zA-Z0-9_\-]{3,}\b', c.get('label', '').lower()):
                c_keywords[w] = 1.0
            for syn_w in list(c_keywords.keys()):
                if syn_w in KEYWORD_SYNONYMS:
                    for s in KEYWORD_SYNONYMS[syn_w]:
                        if s not in c_keywords:
                            c_keywords[s] = 1.5
        for kw, weight in c_keywords.items():
            batch_keywords[kw] = max(batch_keywords.get(kw, 0), weight)

    # Step 2: Score ALL chunks
    scored_chunks = []
    if db_chunks:
        for chunk in db_chunks:
            p_lower = chunk.content.lower()
            score = 0
            for kw, weight in batch_keywords.items():
                count = len(re.findall(r'\b' + re.escape(kw) + r'\b', p_lower))
                if count > 0:
                    score += count * weight
            src_fname = chunk.filename
            if chunk.metadata_json:
                try:
                    meta = json.loads(chunk.metadata_json)
                    if "source_file" in meta:
                        src_fname = meta["source_file"]
                except Exception:
                    pass
            scored_chunks.append((score, chunk.content, chunk.chunk_index, src_fname, chunk))
    else:
        for idx, p in enumerate(paragraphs):
            p_lower = p.lower()
            score = 0
            for kw, weight in batch_keywords.items():
                count = len(re.findall(r'\b' + re.escape(kw) + r'\b', p_lower))
                if count > 0:
                    score += count * weight
            scored_chunks.append((score, p, idx, "fallback", None))

    unique_src_files = list({sc[3] for sc in scored_chunks if sc[3] != "fallback"})
    num_files = len(unique_src_files)


    # [HYBRID SEARCH] Compute Local Embeddings
    query_text = " ".join([f"{c['control']} {c['label']} {c.get('expected', '')}" for c in controls_batch])
    query_vector = _get_ollama_embedding(query_text)
    
    vector_similarities = {}
    if query_vector is not None:
        embeddings_store = _chunk_embeddings_cache
            
        chunks_to_embed = []
        for sc in scored_chunks:
            chunk_key = (sc[3], sc[2])
            if chunk_key not in embeddings_store:
                chunks_to_embed.append((chunk_key, sc[1]))
                
        if chunks_to_embed:
            def embed_worker(item):
                key, content = item
                vector = _get_ollama_embedding(content)
                return key, vector
                
            from src.core.llm_client import get_llm_backend
            backend = os.environ.get("EMBEDDING_BACKEND", get_llm_backend()).lower()
            max_embed_workers = 2 if backend in ("llama.cpp", "llamacpp") else 4
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_embed_workers) as executor:
                embed_results = list(executor.map(embed_worker, chunks_to_embed))

            # Store in pickle cache AND native vector engine
            _native_engine = _get_native_vec_engine()
            for key, vector in embed_results:
                if vector is not None:
                    embeddings_store[key] = vector
            
            # Build chunk_db_id → key map to store in native engine
            # key = (filename, chunk_index); we need the DB row id for sqlite-vec
            if _native_engine != "python" and _native_engine is not None:
                try:
                    session_tmp = SessionLocal()
                    for (fname, cidx), vector in zip(
                        [item[0] for item in chunks_to_embed],
                        [r[1] for r in embed_results]
                    ):
                        if vector is None:
                            continue
                        row = session_tmp.query(DocumentChunk).filter(
                            DocumentChunk.filename == fname,
                            DocumentChunk.chunk_index == cidx
                        ).first()
                        if row:
                            _vec_store_embedding(row.id, vector, _native_engine)
                    session_tmp.close()
                except Exception as _vse:
                    pass  # Never crash audit on vec store failure
            
            try:
                with open(CACHE_FILE, "wb") as f:
                    pickle.dump(embeddings_store, f)
            except Exception as e:
                print(f"[EMBEDDING CACHE] Warning: failed to save persistent cache: {e}", flush=True)

        # ── Vector similarity: native engine first, Python cosine fallback ────
        _native_engine = _get_native_vec_engine()
        native_sims = _vec_native_search(query_vector, file_names_list, 40, _native_engine)

        if native_sims:
            # Map native chunk_db_id results back to (filename, chunk_index) keys
            try:
                session_tmp = SessionLocal()
                ids_to_fetch = list(native_sims.keys())
                rows = session_tmp.query(DocumentChunk).filter(
                    DocumentChunk.id.in_(ids_to_fetch)
                ).all()
                for row in rows:
                    chunk_key = (row.filename, row.chunk_index)
                    vector_similarities[chunk_key] = native_sims[row.id]
                session_tmp.close()
                print(f"[VEC SEARCH] Native {_native_engine.get('type','?')} returned {len(native_sims)} chunk similarities.", flush=True)
            except Exception as map_e:
                print(f"[VEC SEARCH] Native result mapping failed ({map_e}); using Python cosine.", flush=True)
                native_sims = {}

        if not native_sims:
            # Python cosine fallback (always accurate)
            for sc in scored_chunks:
                chunk_key = (sc[3], sc[2])
                c_vec = embeddings_store.get(chunk_key)
                if c_vec is not None:
                    sim = _cosine_similarity(query_vector, c_vec)
                    vector_similarities[chunk_key] = max(0.0, float(sim))

    # Merge Keyword & Vector Scores
    max_kw_score = max([sc[0] for sc in scored_chunks]) if scored_chunks else 0.0
    hybrid_scored_chunks = []
    for sc in scored_chunks:
        kw_score = sc[0]
        chunk_key = (sc[3], sc[2])
        vec_sim = vector_similarities.get(chunk_key, 0.0)
        
        norm_kw = (kw_score / max_kw_score) if max_kw_score > 0 else 0.0
        
        if query_vector is not None:
            hybrid_score = 0.4 * norm_kw + 0.6 * vec_sim
        else:
            hybrid_score = kw_score
            
        hybrid_scored_chunks.append((hybrid_score, sc[1], sc[2], sc[3], sc[4]))

    scored_chunks = hybrid_scored_chunks
    scored_chunks.sort(key=lambda x: x[0], reverse=True)
    matching_chunks = [c for c in scored_chunks if c[0] > 0.05]
    raw_retrieved = matching_chunks[:40] if matching_chunks else scored_chunks[:20]

    # Exact Duplicate Removal
    unique_raw = []
    seen_contents = set()
    for item in raw_retrieved:
        norm_content = item[1].strip()
        if norm_content not in seen_contents:
            seen_contents.add(norm_content)
            unique_raw.append(item)

    # Near-Duplicate Removal (Jaccard)
    def _jaccard(t1, t2):
        w1 = set(re.findall(r'\b\w+\b', t1.lower()))
        w2 = set(re.findall(r'\b\w+\b', t2.lower()))
        if not w1 and not w2:
            return 1.0
        return len(w1 & w2) / len(w1 | w2)

    SIMILARITY_THRESHOLD = 0.97
    deduplicated = []
    for item in unique_raw:
        is_dup = False
        for existing in deduplicated:
            if _jaccard(item[1], existing[1]) >= SIMILARITY_THRESHOLD:
                is_dup = True
                break
        if not is_dup:
            deduplicated.append(item)

    deduplicated.sort(key=lambda x: x[0], reverse=True)
    
    # ── Cross-Encoder Reranking ──────────────────────────────────────────────
    rerank_mode = os.environ.get("RAG_RERANK_MODE", "quick").strip().lower()
    reranker = get_reranker(rerank_mode)
    
    if reranker is not None and deduplicated:
        candidates = deduplicated[:20]
        try:
            pairs = [(query_text, item[1]) for item in candidates]
            rerank_scores = reranker.predict(pairs)
            
            reranked_candidates = []
            for i, item in enumerate(candidates):
                h_score = item[0]
                r_score = float(rerank_scores[i])
                final_score = 0.3 * h_score + 0.7 * r_score
                reranked_candidates.append((final_score, item[1], item[2], item[3], item[4]))
                
            reranked_candidates.sort(key=lambda x: x[0], reverse=True)
            deduplicated = reranked_candidates + deduplicated[20:]
            print(f"[RERANK SUCCESS] Reranked {len(candidates)} candidate chunks using mode '{rerank_mode.upper()}'.", flush=True)
        except Exception as re_err:
            print(f"[RERANK WARNING] Reranking failed: {re_err}", flush=True)

    total_available_chunks = len(db_chunks) if db_chunks else len(paragraphs)

    # Evidence Diversity Enforcement
    # NOTE: only relevant when a control's search spans multiple files (Manual/AI
    # scoping) -- Excel-locked scoping restricts file_names_list to one file per
    # control upstream, so unique_src_files is never >1 there and this never fires.
    # DIVERSITY_MIN_SCORE gates which files are worth force-including: 0.05 was too
    # low (hybrid_score is roughly 0-1) and let near-zero-relevance chunks from
    # completely unrelated files get injected into every control's context, diluting
    # the limited token budget with noise. 0.15 still catches genuinely tangential
    # matches while dropping near-random ones.
    DIVERSITY_MIN_SCORE = 0.15
    if len(unique_src_files) > 1 and deduplicated:
        top_window = deduplicated[:max(configured_top_k, 5)]
        files_in_top = {item[3] for item in top_window}
        missing_files = set(unique_src_files) - files_in_top
        for missing_fname in missing_files:
            best_for_file = None
            for candidate in scored_chunks:
                already_in = any(candidate[1].strip() == d[1].strip() for d in deduplicated)
                if candidate[3] == missing_fname and candidate[0] > DIVERSITY_MIN_SCORE and not already_in:
                    best_for_file = candidate
                    break
            if best_for_file:
                insert_at = min(configured_top_k, len(deduplicated))
                deduplicated.insert(insert_at, best_for_file)
                print(f"[RAG DIVERSITY] Injected chunk from '{missing_fname}' for multi-document evidence.")

    deduplicated = deduplicated[:configured_top_k]

    # Token Budget Accumulation. No absolute relevance-score cutoff: the cross-encoder
    # reranker's scores are raw unbounded logits (commonly negative), not a 0-1 scale, so
    # a fixed threshold rejects almost everything regardless of actual relevance. The
    # reranker's ordering (already sorted best-first above) is what determines quality;
    # the token budget below is the real, meaningful stopping condition.
    selected_chunks = []
    current_tokens = 0
    for item in deduplicated:
        chunk_tokens = len(item[1]) // 4
        if current_tokens + chunk_tokens > HARD_MAX_CONTEXT_TOKENS:
            break
        selected_chunks.append(item)
        current_tokens += chunk_tokens
        if current_tokens >= TARGET_CONTEXT_TOKENS:
            break

    actual_top_k = len(selected_chunks)
    files_in_selected = list({item[3] for item in selected_chunks})

    print(
        f"[RAG LOG] file_type={file_type} | docs={len(file_names_list)} | "
        f"total_chunks={total_available_chunks} | selected={actual_top_k} | "
        f"token_estimate={current_tokens} | files_in_evidence={files_in_selected}"
    )

    # Chronological sort within each file
    file_order = {fname: idx for idx, fname in enumerate(file_names_list)}
    final_sorted = sorted(
        selected_chunks,
        key=lambda x: (file_order.get(x[3], 999), x[2])
    )

    # Collect chunk metadata
    retrieved_chunk_metas = []
    for _, content, index, src_file, chunk_obj in final_sorted:
        if chunk_obj is not None and chunk_obj.metadata_json:
            try:
                meta = json.loads(chunk_obj.metadata_json)
                retrieved_chunk_metas.append(meta)
            except Exception:
                retrieved_chunk_metas.append({"source_file": src_file})
        else:
            retrieved_chunk_metas.append({"source_file": src_file})

    # Build condensed context (Parent-Child Sentence Window Expansion)
    condensed_context = ""
    added_paragraphs = set()
    for _, child_content, _, _, chunk_obj in final_sorted:
        # Retrieve parent paragraph if available in metadata, else fallback to child sentence
        parent_context = child_content
        if chunk_obj is not None and chunk_obj.metadata_json:
            try:
                meta = json.loads(chunk_obj.metadata_json)
                if "parent_context" in meta:
                    parent_context = meta["parent_context"]
            except Exception:
                pass
                
        paras = [para.strip() for para in parent_context.split('\n\n') if para.strip()]
        chunk_unique_text = []
        for para in paras:
            para_body = para
            if para.startswith('[') and ']' in para:
                lines = para.split('\n', 1)
                if len(lines) > 1:
                    para_body = lines[1]
            para_norm = " ".join(para_body.lower().split())
            if para_norm not in added_paragraphs:
                chunk_unique_text.append(para)
                added_paragraphs.add(para_norm)
        if chunk_unique_text:
            condensed_context += "\n\n".join(chunk_unique_text) + "\n\n"

    if not condensed_context.strip():
        condensed_context = context[:4000 if "3b" in llm_model.lower() else 6000]

    return condensed_context, actual_top_k, retrieved_chunk_metas
