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
_chunk_embeddings_cache = {}

# Configurable defaults for retrieval
DEFAULT_TOP_K = {
    "pdf": 12,
    "docx": 12,
    "txt": 12,
    "xlsx": 8,
    "csv": 8,
    "pptx": 10,
    "image": 8
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
            
            cached_chunks = _ingested_chunks_cache.get(filename)
            if cached_chunks:
                chunks_saved = 0
                for idx, (content, metadata) in enumerate(cached_chunks):
                    # Generate a stable chunk_id
                    chunk_id = hashlib.md5(f"{filename}_{idx}_{content}".encode('utf-8')).hexdigest()[:8]
                    metadata["chunk_id"] = f"chunk_{chunk_id}"
                    
                    db_chunk = DocumentChunk(
                        filename=filename,
                        chunk_index=idx,
                        content=content,
                        metadata_json=json.dumps(metadata),
                        source_file=metadata.get("source_file"),
                        source_type=metadata.get("source_type"),
                        chunk_id=metadata.get("chunk_id")
                    )
                    session.add(db_chunk)
                    chunks_saved += 1
                session.commit()
                print(f"[RAG] Successfully stored {chunks_saved} custom cached chunks with metadata for '{filename}' in database.")
                return

            # Fallback split into double newlines chunks (paragraphs)
            paragraphs = [p.strip() for p in text.split('\n\n') if len(p.strip()) > 40]
            
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
                paragraphs = [p for p in paragraphs if len(p) > 40]
                
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
                if window_section:
                    p_text = f"[{window_section}]\n{p_text}"
                    
                _, ext = os.path.splitext(filename.lower())
                SUPPORTED_TYPES_LOCAL = {
                    ".pdf": "pdf",   ".docx": "docx", ".doc": "docx",
                    ".txt": "txt",   ".xlsx": "xlsx",  ".xls": "xlsx",
                    ".csv": "csv",   ".pptx": "pptx",  ".ppt": "pptx",
                    ".png": "image", ".jpg": "image",   ".jpeg": "image"
                }
                src_type = SUPPORTED_TYPES_LOCAL.get(ext, ext.lstrip(".") if ext else "txt")
                metadata = {
                    "source_file": filename,
                    "source_type": src_type,
                    "section_heading": window_section,
                    "chunk_id": f"chunk_fallback_{idx}"
                }
                
                chunk = DocumentChunk(
                    filename=filename,
                    chunk_index=idx,
                    content=p_text,
                    metadata_json=json.dumps(metadata),
                    source_file=metadata.get("source_file"),
                    source_type=metadata.get("source_type"),
                    chunk_id=metadata.get("chunk_id")
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

def _get_ollama_embedding(text, model="nomic-embed-text", url="http://127.0.0.1:11434"):
    try:
        r = requests.post(
            f"{url}/api/embeddings",
            json={"model": model, "prompt": text},
            timeout=15
        )
        if r.status_code == 200:
            return r.json().get("embedding")
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

def _retrieve_rag_context(context, controls_batch, file_names_list, ollama_model, KEYWORD_SYNONYMS):
    """Production RAG retrieval engine.
    Phase 3: Multi-document evidence aggregation — searches ALL uploaded files simultaneously.
    Phase 4: Pipeline: keyword scoring -> exact dedup -> Jaccard near-dedup -> diversity -> rank.
    Phase 5: Token-budget accumulation: TARGET=4000 tokens, HARD_MAX=5000 tokens.
    Phase 8: Returns retrieved_chunk_metas for evidence source provenance.
    """
    TARGET_CONTEXT_TOKENS = 1500
    HARD_MAX_CONTEXT_TOKENS = 2000

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
        ".png": "image", ".jpg": "image",   ".jpeg": "image"
    }
    type_counts = {}
    for fname in file_names_list:
        _, ext = os.path.splitext(fname.lower())
        ftype = SUPPORTED_TYPES_LOCAL.get(ext, "pdf")
        type_counts[ftype] = type_counts.get(ftype, 0) + 1
    file_type = max(type_counts, key=type_counts.get) if type_counts else "pdf"

    top_k_config = load_top_k_config()
    configured_top_k = top_k_config.get(file_type, 8)

    # Fallback: paragraph split from raw context if DB empty
    paragraphs = []
    if not db_chunks:
        paragraphs = [p.strip() for p in context.split('\n\n') if len(p.strip()) > 40]
        if not paragraphs:
            paragraphs = [p.strip() for p in context.split('\n') if len(p.strip()) > 40]

    stop_words = {
        "this", "that", "with", "from", "your", "have", "will", "must",
        "should", "ensure", "under", "these", "against", "about", "their", "where"
    }

    # Step 1: Build merged keyword set from all controls in batch
    batch_keywords = {}
    for c in controls_batch:
        c_keywords = {}
        main_text = f"{c['control']} {c['label']} {c.get('expected', '')}".lower()
        main_words = re.findall(r'\b[a-z0-9_]{2,}\b', main_text)
        for w in main_words:
            if w not in stop_words:
                c_keywords[w] = max(c_keywords.get(w, 0), 3)
        inst_text = f"{c.get('prompt_hint', '')}".lower()
        inst_words = re.findall(r'\b[a-z0-9_]{2,}\b', inst_text)
        for w in inst_words:
            if w not in stop_words:
                c_keywords[w] = max(c_keywords.get(w, 0), 2)
        for kw in list(c_keywords.keys()):
            if "access control" in main_text or "access control" in inst_text:
                for s in KEYWORD_SYNONYMS.get("access control", []):
                    if s not in c_keywords:
                        c_keywords[s] = 1.5
            for base, syns in KEYWORD_SYNONYMS.items():
                if kw == base or kw in syns:
                    if base not in c_keywords:
                        c_keywords[base] = 1.5
                    for s in syns:
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
    if num_files > 1:
        TARGET_CONTEXT_TOKENS = min(4000, 1500 + (num_files * 400))
        HARD_MAX_CONTEXT_TOKENS = min(5000, 2000 + (num_files * 500))

    # [HYBRID SEARCH] Compute Local Embeddings
    query_text = " ".join([f"{c['control']} {c['label']} {c.get('expected', '')}" for c in controls_batch])
    query_vector = _get_ollama_embedding(query_text)
    
    vector_similarities = {}
    if query_vector is not None:
        # Check global cache safely without triggering thread-safety errors
        embeddings_store = _chunk_embeddings_cache
            
        chunks_to_embed = []
        for sc in scored_chunks:
            chunk_key = (sc[3], sc[2])
            if chunk_key not in embeddings_store:
                chunks_to_embed.append((chunk_key, sc[1]))
                
        if chunks_to_embed:
            status_text = None
            try:
                import streamlit as st
                status_text = st.empty()
                status_text.info(f"⏳ Processing local semantic embeddings for {len(chunks_to_embed)} document sections...")
            except Exception:
                pass
                
            def embed_worker(item):
                key, content = item
                vector = _get_ollama_embedding(content)
                return key, vector
                
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                results = list(executor.map(embed_worker, chunks_to_embed))
                
            for key, vector in results:
                if vector is not None:
                    embeddings_store[key] = vector
            if status_text is not None:
                try:
                    status_text.empty()
                except Exception:
                    pass
            
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
            # 40% Keyword score + 60% Vector Semantic score
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
    total_available_chunks = len(db_chunks) if db_chunks else len(paragraphs)

    # Evidence Diversity Enforcement
    if len(unique_src_files) > 1 and deduplicated:
        top_window = deduplicated[:max(configured_top_k, 5)]
        files_in_top = {item[3] for item in top_window}
        missing_files = set(unique_src_files) - files_in_top
        for missing_fname in missing_files:
            best_for_file = None
            for candidate in scored_chunks:
                already_in = any(candidate[1].strip() == d[1].strip() for d in deduplicated)
                if candidate[3] == missing_fname and candidate[0] > 0.05 and not already_in:
                    best_for_file = candidate
                    break
            if best_for_file:
                insert_at = min(configured_top_k, len(deduplicated))
                deduplicated.insert(insert_at, best_for_file)
                print(f"[RAG DIVERSITY] Injected chunk from '{missing_fname}' for multi-document evidence.")

    # Token Budget Accumulation
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

    # Build condensed context
    condensed_context = ""
    added_paragraphs = set()
    for _, p_content, _, _, _ in final_sorted:
        paras = [para.strip() for para in p_content.split('\n\n') if para.strip()]
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
        condensed_context = context[:4000 if "3b" in ollama_model.lower() else 6000]

    return condensed_context, actual_top_k, retrieved_chunk_metas
