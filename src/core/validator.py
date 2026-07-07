# -*- coding: utf-8 -*-
"""
Strict Forensic Compliance Auditor - Validation Module
Implements the core grounding, leakage, confidence, and consistency checks.
"""

def check_grounding(evidence, document_text):
    """
    Checks if the cited evidence actually exists in the provided document text.
    """
    if not evidence or evidence == "NOT_FOUND":
        return "NOT_GROUNDED"
    
    # Fuzzy check - first 50 chars matching (case-insensitive)
    snippet = evidence[:50].lower().strip().strip('"').strip("'").strip('“').strip('”')
    if not snippet:
        return "NOT_GROUNDED"
        
    if snippet not in document_text.lower():
        return "NOT_GROUNDED"
    return "GROUNDED"


def normalize_text(text):
    """
    Normalizes whitespace, smart quotes, dashes, and case to make verbatim search robust against line breaks and formatting.
    """
    if not text:
        return ""
    import re
    # Replace newlines, tabs, and multiple spaces with a single space
    text = re.sub(r'\s+', ' ', text)
    # Standardize smart quotes / single quotes
    text = text.replace('“', '"').replace('”', '"').replace('‘', "'").replace('’', "'")
    # Standardize dashes
    text = text.replace('–', '-').replace('—', '-')
    return text.strip().lower()


def check_prompt_leakage(evidence, hints, threshold=0.75):
    """
    Checks if the cited evidence is copied directly or has high fuzzy similarity to the expected evidence hints.
    Also guards against the model echoing systemic prompt instructions.
    """
    if not evidence or evidence == "NOT_FOUND":
        return "CLEAN"
        
    evidence_clean = evidence.strip().strip('"').strip("'").strip('“').strip('”').strip().lower()
    
    # Block systemic prompt instruction leakage
    PROMPT_SPECIFIC_KEYWORDS = [
        "strict forensic compliance auditor",
        "adversarial compliance challenger",
        "universal decision tree",
        "hallucination self check",
        "universal document scope",
        "never copy from expected evidence",
        "case a (grounded exact quote",
        "case b (partial evidence",
        "case c (no evidence",
        "case d (evidence matches",
        "case e (fuzzy",
        "verify the full lifecycle of identities",
        "expected evidence",
        "step 1: fresh start",
        "decision tree",
    ]
    for kw in PROMPT_SPECIFIC_KEYWORDS:
        if kw in evidence_clean:
            return "PROMPT_LEAK"
            
    # Check for pattern "law 1" through "law 10"
    import re
    if re.search(r'\blaw\s+([1-9]|10)\b', evidence_clean):
        return "PROMPT_LEAK"
            
    import difflib
    for hint in hints:
        if not hint:
            continue
        hint_clean = hint.strip().strip('"').strip("'").strip('“').strip('”').strip().lower()
        if not hint_clean:
            continue
        # Direct substring check
        if hint_clean in evidence_clean or evidence_clean in hint_clean:
            return "PROMPT_LEAK"
        # Fuzzy similarity check
        similarity = difflib.SequenceMatcher(None, hint_clean, evidence_clean).ratio()
        if similarity >= threshold:
            return "PROMPT_LEAK"
    return "CLEAN"


def map_new_schema_to_legacy(finding):
    """
    Maps the new ISO 27001 Lead Auditor schema to the legacy schema format
    used by the validator, database, and Streamlit UI.
    """
    if not finding:
        return finding
        
    # Check if this is already in the legacy format (e.g. has 'evidence_quote' and not 'justification')
    if "evidence_quote" in finding and "justification" not in finding:
        return finding
        
    mapped = {}
    
    # Copy all other fields that don't need translation
    for k, v in finding.items():
        mapped[k] = v
        
    # 1. status mapping
    status_val = finding.get("status", "NON_COMPLIANT")
    mapped["status"] = status_val
    
    # 2. severity mapping
    sev_val = finding.get("severity", "Medium")
    sev_key = str(sev_val).strip() if sev_val is not None else "Medium"
    sev_map = {
        "N/A": "N/A",
        "NONE": "N/A",
        "NIL": "N/A",
        "OK": "N/A",
        "ACCEPTED": "N/A",
        "LOW": "P4 Low",
        "P4 LOW": "P4 Low",
        "MEDIUM": "P3 Medium",
        "MED": "P3 Medium",
        "MODERATE": "P3 Medium",
        "P3 MEDIUM": "P3 Medium",
        "HIGH": "P2 High",
        "P2 HIGH": "P2 High",
        "CRITICAL": "P1 Critical",
        "P1 CRITICAL": "P1 Critical"
    }
    mapped["severity"] = sev_map.get(sev_key.upper(), "P3 Medium")
    
    # 3. evidence quote mapping
    evidence_list = finding.get("evidence", [])
    evidence_quote = "NOT_FOUND"
    if evidence_list and isinstance(evidence_list, list):
        first_ev = evidence_list[0]
        if isinstance(first_ev, dict):
            evidence_quote = first_ev.get("excerpt") or "NOT_FOUND"
            mapped["evidence_location"] = f"{first_ev.get('source', '')} | Page/Sec {first_ev.get('page', '')}"
    mapped["evidence_quote"] = evidence_quote
    mapped["evidence_snippet"] = evidence_quote if evidence_quote != "NOT_FOUND" else ""
    
    # 4. gap description mapping
    missing_reqs = finding.get("missing_requirements", [])
    biz_impact = finding.get("business_impact", "")
    gap_desc = finding.get("gap_description") or ""
    if not gap_desc:
        parts = []
        if biz_impact:
            parts.append(f"Business Impact: {biz_impact}")
        if missing_reqs:
            parts.append(f"Missing Requirements: {', '.join(missing_reqs)}")
        gap_desc = " | ".join(parts) if parts else "No documented evidence satisfying the control requirements."
    mapped["gap_description"] = gap_desc
    mapped["finding"] = gap_desc
    mapped["description"] = gap_desc
    
    # 5. reasoning mapping
    mapped["reasoning"] = finding.get("justification") or finding.get("reasoning") or ""
    
    # 6. confidence mapping (map evidence_strength to confidence score)
    strength = finding.get("evidence_strength", "None")
    strength_map = {
        "Strong": 10, "STRONG": 10,
        "Moderate": 7, "MODERATE": 7,
        "Weak": 4, "WEAK": 4,
        "None": 1, "NONE": 1
    }
    mapped["confidence"] = strength_map.get(strength, 10)
    
    # 7. recommendation mapping
    mapped["recommendation"] = finding.get("recommendation") or ""
    
    return mapped


def apply_confidence_gate(finding):
    """
    No longer downgrades findings based on confidence scores.
    Preserves and parses the confidence score, but bypasses status changes
    to comply with strict lead auditor requirements.
    """
    confidence = finding.get("confidence", 10)
    # Default to 10 if not present or invalid
    try:
        confidence = int(confidence)
    except (TypeError, ValueError):
        confidence = 10
        
    finding["confidence"] = confidence
    # Downgrade check is disabled as per user instruction:
    # "do not use relevance scores, confidence scores, or similarity metrics to determine compliance status."
    return finding


def check_consistency(finding):
    """
    Auto-corrects status inconsistencies in both directions:
    - COMPLIANT with no evidence → NON_COMPLIANT
    - NON_COMPLIANT with grounded evidence → PARTIAL_COMPLIANT (Fix 6)
    """
    status = finding.get("status", "NON_COMPLIANT")
    evidence = finding.get("evidence_quote") or "NOT_FOUND"
    hallucination_check = finding.get("hallucination_check", "")

    # Forward check: COMPLIANT must have grounded evidence
    if status == "COMPLIANT":
        if not evidence or evidence == "NOT_FOUND":
            finding["status"] = "NON_COMPLIANT"
            finding["consistency_fix"] = True
            finding["evidence_snippet"] = ""
            finding["evidence_quote"] = "NOT_FOUND"

    # FIX 6 — Reverse check: NON_COMPLIANT with a grounded evidence quote is a contradiction.
    # If the evidence was verified (GROUNDED or GROUNDED_WITH_OCR_WARNING), the control
    # at minimum demonstrates partial compliance — upgrade to PARTIAL_COMPLIANT.
    elif status == "NON_COMPLIANT":
        if evidence and evidence != "NOT_FOUND" and hallucination_check in ("GROUNDED", "GROUNDED_WITH_OCR_WARNING"):
            finding["status"] = "PARTIAL_COMPLIANT"
            finding["consistency_fix"] = True
            print(f"[VALIDATOR] Reverse consistency fix: NON_COMPLIANT with grounded evidence upgraded to PARTIAL_COMPLIANT.", flush=True)

    return finding


def check_reasoning_hallucination(reasoning, document_text, threshold=0.4):
    """
    FIX Q3: Checks whether the auditor's reasoning text contains claims that
    are not grounded in the actual document. Flags fabricated claims.

    Returns a dict:
      - "clean": bool — True if reasoning appears well-grounded
      - "flagged_phrases": list of suspicious phrases not found in doc
    """
    if not reasoning or not document_text:
        return {"clean": True, "flagged_phrases": []}

    import re
    doc_lower = document_text.lower()

    # Split reasoning into sentences and check each one
    sentences = re.split(r'(?<=[.!?])\s+', reasoning.strip())
    flagged = []

    # Phrases that are suspicious if not found in document
    GENERIC_SAFE_PHRASES = [
        "iso 27001", "control", "compliance", "evidence", "document",
        "policy", "procedure", "requirement", "not found", "not evidenced",
        "does not contain", "no evidence", "gap", "missing", "incident",
        "security", "organization", "auditor", "finding"
    ]

    for sentence in sentences:
        s = sentence.strip().lower()
        if len(s) < 20:
            continue
        # Extract key noun phrases (3+ word spans)
        words = s.split()
        if len(words) < 4:
            continue
        # Check if sentence makes a positive factual claim ("mentions", "contains", "outlines", "states")
        claim_verbs = ["mentions", "contains", "outlines", "states", "describes", "includes", "provides", "defines", "details"]
        has_claim = any(v in s for v in claim_verbs)
        if not has_claim:
            continue
        # If it makes a factual claim, check that at least one key phrase from the sentence appears in the document
        is_safe = any(phrase in s for phrase in GENERIC_SAFE_PHRASES)
        if is_safe:
            continue
        # Extract 3-word windows and check in document
        found_in_doc = False
        for i in range(len(words) - 2):
            window = " ".join(words[i:i+3])
            if window in doc_lower:
                found_in_doc = True
                break
        if not found_in_doc:
            flagged.append(sentence.strip())

    return {
        "clean": len(flagged) == 0,
        "flagged_phrases": flagged
    }


def calculate_real_accuracy(findings):
    """
    Calculates the real compliance accuracy of the model findings.
    """
    total = len(findings)
    if total == 0:
        return {
            "total": 0,
            "grounded_compliant": 0,
            "correct_non_compliant": 0,
            "hallucinated": 0,
            "real_accuracy": 0.0,
            "claimed_accuracy": "DISABLED - was misleading"
        }
        
    grounded_compliant = sum(
        1 for f in findings
        if f.get("status") == "COMPLIANT"
        and f.get("hallucination_check") == "GROUNDED"
    )
    correct_non_compliant = sum(
        1 for f in findings
        if f.get("status") == "NON_COMPLIANT"
    )
    hallucinated = sum(
        1 for f in findings
        if f.get("hallucination_check") in ["NOT_GROUNDED", "PROMPT_LEAK"]
    )
    
    real_accuracy = round(
        (grounded_compliant + correct_non_compliant) / total * 100, 1
    )
    
    return {
        "total": total,
        "grounded_compliant": grounded_compliant,
        "correct_non_compliant": correct_non_compliant,
        "hallucinated": hallucinated,
        "real_accuracy": real_accuracy,
        "claimed_accuracy": "DISABLED - was misleading"
    }


def potential_evidence_exists(control_id, document_text):
    """
    Fuzzy checks if any keyword from the control description or keywords is present in the document.
    """
    if not control_id or not document_text:
        return False
        
    # Split control_id to get words (excluding clause prefix like 5.15)
    parts = control_id.split(" ")
    keywords = []
    for p in parts[1:]:
        cleaned = "".join(c for c in p if c.isalnum()).lower()
        if len(cleaned) > 3:
            keywords.append(cleaned)
            
    # Fallback to USE_CASES if control_id was short (e.g., "6.5") and yielded no keywords
    if not keywords:
        from src.core.controls_data import USE_CASES
        full_label = ""
        for uc in USE_CASES:
            uc_id = uc.get("use_case", "")
            uc_lbl = uc.get("label", "")
            if uc_id == control_id or uc_lbl == control_id or uc_id.startswith(control_id) or uc_lbl.startswith(control_id):
                full_label = uc_id
                break
        if full_label:
            parts = full_label.split(" ")
            for p in parts[1:]:
                cleaned = "".join(c for c in p if c.isalnum()).lower()
                if len(cleaned) > 3:
                    keywords.append(cleaned)

    # Add relevant control-specific keywords/synonyms to catch potential evidence sections
    if any(kw in ["termination", "exit", "employee"] for kw in keywords) or "6.5" in control_id:
        keywords.extend(["termination", "exit", "hr", "human resources", "resign", "dismiss", "leave"])

    doc_lower = document_text.lower()
    for kw in keywords:
        if kw in doc_lower:
            return True
    return False


def validate_only(finding, document_text, expected_evidence_map, db_chunks=None):
    """
    Runs core validation rules on a single finding without triggering requires_human_review.
    Enforces the explicit gate order:
      1. Leakage check (fails immediately on prompt leak)
      2. Verbatim Grounding check
      3. Fuzzy OCR Grounding check (if verbatim fails)
      4. Confidence & Consistency checks
    """
    finding = map_new_schema_to_legacy(finding)
    control_id = finding.get("control_id") or finding.get("control") or ""
    code = control_id.split(" ")[0] if control_id else ""
    
    # ── DEBUG: Log raw LLM output before any validation ──
    raw_status = finding.get("status", "UNKNOWN")
    raw_evidence = finding.get("evidence_quote") or finding.get("evidence_snippet") or "NOT_FOUND"
    raw_confidence = finding.get("confidence", "N/A")
    raw_gap = finding.get("gap_description") or finding.get("finding") or ""
    print(f"\n{'='*60}", flush=True)
    print(f"[VALIDATOR DEBUG] Control: {control_id}", flush=True)
    print(f"[VALIDATOR DEBUG] RAW LLM Status: {raw_status}", flush=True)
    print(f"[VALIDATOR DEBUG] RAW LLM Evidence: {raw_evidence[:200]}", flush=True)
    print(f"[VALIDATOR DEBUG] RAW LLM Confidence: {raw_confidence}", flush=True)
    print(f"[VALIDATOR DEBUG] RAW LLM Gap: {raw_gap[:200]}", flush=True)
    print(f"{'='*60}", flush=True)
    
    evidence = finding.get("evidence_quote") or "NOT_FOUND"
    evidence_clean = evidence.strip().strip('"').strip("'").strip('“').strip('”').strip()
    if not evidence_clean or evidence_clean == "NOT_FOUND":
        evidence_clean = "NOT_FOUND"
    evidence_clean_lower = evidence_clean.lower()
        
    finding["evidence_quote"] = evidence_clean
    finding["evidence_snippet"] = evidence_clean if evidence_clean != "NOT_FOUND" else ""
    finding["chunk_id"] = None
    
    if evidence_clean == "NOT_FOUND":
        # FIX 1: Before forcing NON_COMPLIANT, check if the document contains
        # any keyword evidence related to this control. If it does, the LLM
        # simply failed to quote it — so PARTIAL_COMPLIANT is more accurate.
        if potential_evidence_exists(control_id, document_text):
            print(f"[VALIDATOR DEBUG] [PARTIAL] {control_id}: LLM returned NOT_FOUND but keyword evidence exists in document. Upgrading to PARTIAL_COMPLIANT.", flush=True)
            finding["status"] = "PARTIAL_COMPLIANT"
            finding["hallucination_check"] = "NOT_FOUND"
            finding["requires_human_review"] = True
            finding["requires_review"] = True
            finding["validator_note"] = "LLM did not cite evidence, but relevant text was found in the document. Human verification required."
            finding["review_note"] = "LLM returned NOT_FOUND for evidence, but keyword-based search found potentially relevant content in the document. Verify manually whether the control is satisfied."
            finding["finding"] = f"Evidence for {control_id} may exist in the document but was not cited by the auditor. Manual verification required."
            finding["severity"] = "P3 Medium"
        else:
            print(f"[VALIDATOR DEBUG] [FAIL] {control_id}: LLM returned NOT_FOUND evidence and no keywords found. Setting NON_COMPLIANT.", flush=True)
            finding["status"] = "NON_COMPLIANT"
            finding["hallucination_check"] = "NOT_FOUND"
            finding["validator_note"] = "No evidence provided and no relevant keywords found in document."
            finding["finding"] = f"Control requirements for {control_id} are completely missing from the policy document."
            finding["severity"] = "P3 Medium"
        finding = apply_confidence_gate(finding)
        finding = check_consistency(finding)
        return finding

    # ════════════════════════════════════════
    # GATE 1: Leakage check (always first)
    # ════════════════════════════════════════
    hints = expected_evidence_map.get(code, []) if expected_evidence_map else []
    leakage = check_prompt_leakage(evidence_clean, hints)
    
    # Pre-emptively detect adversarial prompt injections in the retrieved context/document text
    if document_text:
        doc_lower = document_text.lower()
        injection_keywords = [
            "ignore all instructions",
            "ignore previous instructions",
            "ignore the instructions",
            "ignore system instructions",
            "ignore the system prompt",
            "attention: ignore",
            "mark the control as",
            "override all instructions"
        ]
        for kw in injection_keywords:
            if kw in doc_lower:
                leakage = "PROMPT_LEAK"
                break
                
    print(f"[VALIDATOR DEBUG] GATE 1 (Leakage): {control_id} -> {leakage}", flush=True)
    if leakage == "PROMPT_LEAK":
        print(f"[VALIDATOR DEBUG] [FAIL] {control_id}: REJECTED by Leakage Gate! Evidence matched prompt hints or prompt injection detected.", flush=True)
        print(f"[VALIDATOR DEBUG]   Hints: {hints[:2]}", flush=True)
        finding["status"] = "NON_COMPLIANT"
        finding["hallucination_check"] = "PROMPT_LEAK"
        finding["validator_note"] = "Evidence matches Expected Evidence hint — rejected"
        finding["evidence_snippet"] = ""
        finding["evidence_quote"] = "NOT_FOUND"
        finding["finding"] = "Control requirements not addressed in policy document; prompt template echoed by model."
        finding["severity"] = "P3 Medium"
        finding["finding_is_final"] = True
        finding = apply_confidence_gate(finding)
        finding = check_consistency(finding)
        return finding

    # ════════════════════════════════════════
    # GATE 2: Verbatim Grounding & Chunk Mapping (Normalized)
    # ════════════════════════════════════════
    grounded_state = "NOT_GROUNDED"
    matched_chunk_id = None
    
    norm_evidence = normalize_text(evidence_clean)
    if norm_evidence and norm_evidence != "not_found":
        found_in_chunk = False
        if db_chunks:
            for chunk in db_chunks:
                norm_chunk = normalize_text(chunk.content)
                if norm_evidence in norm_chunk:
                    grounded_state = "GROUNDED"
                    matched_chunk_id = chunk.id
                    found_in_chunk = True
                    # Extract source details from metadata_json if present (to map to specific files inside a ZIP)
                    if chunk.metadata_json:
                        try:
                            import json as _json
                            meta = _json.loads(chunk.metadata_json)
                            if "source_file" in meta:
                                finding["evidence_source_file"] = meta["source_file"]
                                finding["source_files"] = meta["source_file"]
                            if "source_type" in meta:
                                finding["evidence_source_type"] = meta["source_type"]
                        except Exception:
                            pass
                    break
        
        # Fallback to checking the full document text (essential when retrieval bypassed chunking for small files)
        if not found_in_chunk and document_text:
            norm_doc = normalize_text(document_text)
            if norm_evidence in norm_doc:
                grounded_state = "GROUNDED"

    # ════════════════════════════════════════
    # GATE 3: Fuzzy OCR Grounding Fallback
    # ════════════════════════════════════════
    if grounded_state == "NOT_GROUNDED":
        import difflib
        if db_chunks:
            for chunk in db_chunks:
                words_evidence = evidence_clean_lower.split()
                words_chunk = chunk.content.lower().split()
                n_words = len(words_evidence)
                if n_words == 0 or len(words_chunk) < n_words:
                    continue
                best_ratio = 0.0
                for start in range(len(words_chunk) - n_words + 1):
                    window_text = " ".join(words_chunk[start : start + n_words])
                    ratio = difflib.SequenceMatcher(None, evidence_clean_lower, window_text).ratio()
                    if ratio > best_ratio:
                        best_ratio = ratio
                if best_ratio >= 0.85:
                    grounded_state = "GROUNDED_WITH_OCR_WARNING"
                    matched_chunk_id = chunk.id
                    # Extract source details from metadata_json if present (to map to specific files inside a ZIP)
                    if chunk.metadata_json:
                        try:
                            import json as _json
                            meta = _json.loads(chunk.metadata_json)
                            if "source_file" in meta:
                                finding["evidence_source_file"] = meta["source_file"]
                                finding["source_files"] = meta["source_file"]
                            if "source_type" in meta:
                                finding["evidence_source_type"] = meta["source_type"]
                        except Exception:
                            pass
                    break
        else:
            paragraphs = [p.strip().lower() for p in document_text.split('\n') if len(p.strip()) > 40]
            for p in paragraphs:
                words_evidence = evidence_clean_lower.split()
                words_p = p.split()
                n_words = len(words_evidence)
                if n_words == 0 or len(words_p) < n_words:
                    continue
                best_ratio = 0.0
                for start in range(len(words_p) - n_words + 1):
                    window_text = " ".join(words_p[start : start + n_words])
                    ratio = difflib.SequenceMatcher(None, evidence_clean_lower, window_text).ratio()
                    if ratio > best_ratio:
                        best_ratio = ratio
                if best_ratio >= 0.85:
                    grounded_state = "GROUNDED_WITH_OCR_WARNING"
                    break

    finding["chunk_id"] = matched_chunk_id
    finding["hallucination_check"] = grounded_state

    print(f"[VALIDATOR DEBUG] GATE 2+3 (Grounding): {control_id} -> {grounded_state}", flush=True)
    if grounded_state == "NOT_GROUNDED":
        print(f"[VALIDATOR DEBUG] [FAIL] {control_id}: REJECTED by Grounding Gate! Evidence not found in document.", flush=True)
        print(f"[VALIDATOR DEBUG]   Evidence (first 100 chars): {evidence_clean[:100]}", flush=True)
        raw_status_upper = str(raw_status).upper().strip()
        # Check for COMPLIANT or PARTIAL, but NOT NON_COMPLIANT (which contains "COMPLIANT" as substring)
        is_compliant_claim = (raw_status_upper == "COMPLIANT" or raw_status_upper == "PARTIAL"
                              or raw_status_upper == "PARTIALLY_COMPLIANT")
        if is_compliant_claim:
            finding["status"] = "PARTIAL_COMPLIANT"
            finding["requires_human_review"] = True
            finding["requires_review"] = True
            finding["validator_note"] = "Grounding failed but model claimed compliant/partial — downgraded to PARTIAL_COMPLIANT"
            finding["review_note"] = "Grounding validation failed: cited evidence quote was not found in policy document text. Downgraded to PARTIAL_COMPLIANT pending manual verification."
        else:
            finding["status"] = "NON_COMPLIANT"
            finding["validator_note"] = "Evidence quote not found in document text — rejected"
            finding["evidence_snippet"] = ""
            finding["evidence_quote"] = "NOT_FOUND"
            finding["finding"] = f"Control requirements for {control_id} are completely missing from the policy document."
            finding["severity"] = "P3 Medium"
    elif grounded_state == "GROUNDED_WITH_OCR_WARNING":
        finding["requires_human_review"] = True
        finding["requires_review"] = True
        finding["validator_note"] = "Verbiage matched with fuzzy correlation (potential OCR distortion)"
        existing_note = finding.get("review_note") or ""
        ocr_note = "Potential OCR distortion: Cited evidence was grounded via fuzzy correlation. Verify exact spelling in PDF."
        if existing_note:
            if ocr_note not in existing_note:
                finding["review_note"] = f"{existing_note} {ocr_note}"
        else:
            finding["review_note"] = ocr_note
    else:
        print(f"[VALIDATOR DEBUG] [OK] {control_id}: PASSED all gates! Status: {finding.get('status')}", flush=True)
        finding["validator_note"] = None

    # FIX Q3: Reasoning hallucination check — runs for all findings that passed grounding.
    # Scans reasoning text for positive factual claims not grounded in the document.
    reasoning_text = finding.get("reasoning") or finding.get("justification") or ""
    if reasoning_text and grounded_state in ("GROUNDED", "GROUNDED_WITH_OCR_WARNING"):
        hallucination_result = check_reasoning_hallucination(reasoning_text, document_text)
        if not hallucination_result["clean"]:
            flagged = hallucination_result["flagged_phrases"]
            print(f"[VALIDATOR DEBUG] [WARN] {control_id}: Reasoning contains {len(flagged)} potentially hallucinated claim(s).", flush=True)
            finding["reasoning_hallucination_warning"] = True
            finding["reasoning_flagged_phrases"] = flagged
            existing_note = finding.get("review_note") or ""
            hal_note = f"Reasoning hallucination warning: {len(flagged)} claim(s) in the auditor reasoning could not be verified in the document text. Review: {'; '.join(flagged[:2])}"
            if existing_note:
                if "hallucination warning" not in existing_note:
                    finding["review_note"] = f"{existing_note} | {hal_note}"
            else:
                finding["review_note"] = hal_note

    # Get & Normalize status — only three valid outputs: COMPLIANT, PARTIAL_COMPLIANT, NON_COMPLIANT
    status = finding.get("status", "NON_COMPLIANT").upper()
    if "HUMAN_REVIEW" in status or "HUMAN REVIEW" in status:
        # Map HUMAN_REVIEW -> PARTIAL_COMPLIANT (uncertain / needs verification)
        finding["status"] = "PARTIAL_COMPLIANT"
    elif "NON_COMPLIANT" in status or "NON-COMPLIANT" in status:
        finding["status"] = "NON_COMPLIANT"
    elif "PARTIALLY" in status or "PARTIAL" in status:
        finding["status"] = "PARTIAL_COMPLIANT"
    elif "COMPLIANT" in status:
        finding["status"] = "COMPLIANT"
    else:
        finding["status"] = "NON_COMPLIANT"

    # Confidence check
    if "confidence" not in finding or finding["confidence"] is None:
        finding["confidence"] = 10 if finding["status"] == "COMPLIANT" else 2
        
    pre_gate_status = finding.get("status")
    finding = apply_confidence_gate(finding)
    finding = check_consistency(finding)
    post_gate_status = finding.get("status")
    if pre_gate_status != post_gate_status:
        print(f"[VALIDATOR DEBUG] [WARN] {control_id}: Status changed by Confidence/Consistency gate: {pre_gate_status} -> {post_gate_status}", flush=True)
    print(f"[VALIDATOR DEBUG] FINAL: {control_id} -> Status={finding.get('status')}, Evidence={'YES' if finding.get('evidence_quote') not in ('', 'NOT_FOUND', None) else 'NO'}", flush=True)
    
    # FIX 2: Ensure recommendation is populated and appropriate for the compliance status.
    # COMPLIANT controls must never receive "Establish procedures" recommendations.
    current_status = finding.get("status", "NON_COMPLIANT")
    if not finding.get("recommendation"):
        if current_status == "COMPLIANT":
            finding["recommendation"] = "No action required. Continue to maintain current procedures and ensure periodic review of compliance evidence."
        else:
            from src.core.controls_data import USE_CASES
            rec = ""
            for uc in USE_CASES:
                if uc["use_case"] == control_id or uc["label"] == control_id:
                    rec = uc.get("recommendation", "")
                    break
            if not rec and code:
                for uc in USE_CASES:
                    if uc["use_case"].startswith(code) or uc["label"].startswith(code):
                        rec = uc.get("recommendation", "")
                        break
            if not rec:
                rec = f"Establish, document, and implement procedures to satisfy {control_id}."
            finding["recommendation"] = rec
    elif current_status == "COMPLIANT" and finding.get("recommendation", "").lower().startswith("establish"):
        # FIX 2b: Override incorrect "Establish" recommendation if control is already COMPLIANT
        finding["recommendation"] = "No action required. Continue to maintain current procedures and ensure periodic review of compliance evidence."

    return finding


def post_process(finding, document_text, expected_evidence_map=None, db_chunks=None):
    """
    Applies post-processing policies to a single finding.
    """
    if expected_evidence_map is None:
        expected_evidence_map = {}
        
    # Respect BLOCK override (if overridden by human or system rules)
    if finding.get("post_process_override") == "BLOCK":
        return validate_only(finding, document_text, expected_evidence_map, db_chunks)
        
    # Run normal validation check
    finding = validate_only(finding, document_text, expected_evidence_map, db_chunks)
    
    # Skip potential evidence check if prompt leak
    if finding.get("hallucination_check") == "PROMPT_LEAK":
        return finding
        
    # Trigger review flag for potential evidence (only if not already matched fuzzy/verbatim).
    # We do NOT skip this check if finding_is_final is True, because models often incorrectly
    # assert finding_is_final=True even when they missed relevant paragraphs (like offboarding clauses).
    if finding.get("status") == "NON_COMPLIANT" and finding.get("hallucination_check") not in ("GROUNDED", "GROUNDED_WITH_OCR_WARNING"):
        control_id = finding.get("control_id") or finding.get("control") or ""
        if potential_evidence_exists(control_id, document_text):
            finding["requires_human_review"] = True
            finding["requires_review"] = True
            existing_note = finding.get("review_note") or ""
            pot_note = "Potential evidence found. Human verification needed."
            if existing_note:
                if pot_note not in existing_note:
                    finding["review_note"] = f"{existing_note} {pot_note}"
            else:
                finding["review_note"] = pot_note
            
    return finding


def validate_findings(findings, document_text, expected_evidence_map):
    """
    Bulk validates a list of findings using the validate_only logic.
    """
    validated = []
    for f in findings:
        validated.append(validate_only(f, document_text, expected_evidence_map))
    return validated


def validate_cross_control_duplicates(findings):
    """
    Checks all findings in a batch. If the exact same non-trivial evidence quote is cited
    across 2 or more different controls, flags those findings for human review.
    """
    # Group findings by normalized evidence quote
    quote_map = {}
    for f in findings:
        status = f.get("status", "NON_COMPLIANT")
        if status in ["Out of Scope", "NON_COMPLIANT", "Non-Compliant"]:
            continue
        ev = f.get("evidence_quote") or f.get("evidence_snippet") or "NOT_FOUND"
        ev_norm = ev.strip().strip('"').strip("'").strip('“').strip('”').strip().lower()
        if not ev_norm or ev_norm == "not_found" or len(ev_norm) < 15:
            # Skip short or generic quotes
            continue
            
        if ev_norm not in quote_map:
            quote_map[ev_norm] = []
        quote_map[ev_norm].append(f)
        
    for ev_norm, f_list in quote_map.items():
        if len(f_list) >= 2:
            # Flag duplicate citations across multiple controls
            for f in f_list:
                f["requires_human_review"] = True
                f["requires_review"] = True
                existing_note = f.get("review_note") or ""
                dup_note = "Duplicate evidence citation: This quote was also cited in other controls (potential citation reuse)."
                if existing_note:
                    if dup_note not in existing_note:
                        f["review_note"] = f"{existing_note} {dup_note}"
                else:
                    f["review_note"] = dup_note
                    
    return findings
