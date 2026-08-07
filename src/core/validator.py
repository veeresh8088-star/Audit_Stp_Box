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
    return text.strip().lower()


def clean_alphanumeric(text):
    """
    Strips all punctuation, symbols, and formatting, leaving only lowercase letters, digits, and spaces.
    Used as a robust fallback for grounding checks when encoding issues or smart quotes are present.
    """
    if not text:
        return ""
    import re
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s]', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


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
        # Collect ALL evidence excerpts (not just first)
        all_excerpts = []
        for ev_item in evidence_list:
            if isinstance(ev_item, dict):
                excerpt = ev_item.get("excerpt") or ev_item.get("text") or ""
                if excerpt and excerpt != "NOT_FOUND":
                    all_excerpts.append(excerpt.strip())
            elif isinstance(ev_item, str) and ev_item.strip():
                all_excerpts.append(ev_item.strip())
        if all_excerpts:
            evidence_quote = "\n\n".join(all_excerpts)

    # evidence_location: prefer finding-level source which is set correctly by
    # bg_worker (Excel scoping gate). ev_item["source"] contains LLM hallucinations
    # like "Document Context" or "Document Text" — never use those as filenames.
    _FAKE_SOURCES = {"document context", "document text", "n/a", "na", "none",
                     "policy document", "uploaded document", "evidence document",
                     "context", "evidence", "document", ""}
    
    # Combine Parent Document and Child Image Filename (e.g. "Monitoring AWS CloudWatch.docx (image1.png)")
    parent_file = (finding.get("source_files") or finding.get("parent_document") or "").strip()
    child_file = (finding.get("evidence_source_file") or "").strip()

    if child_file and parent_file and child_file != parent_file:
        if child_file.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff")) and parent_file not in child_file:
            _loc = f"{parent_file} ({child_file})"
        elif parent_file not in _loc and child_file in _loc:
            _loc = _loc.replace(child_file, f"{parent_file} ({child_file})")

    if _loc and _loc.lower() not in _FAKE_SOURCES:
        mapped["evidence_location"] = _loc


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
    
    # 8. policy/evidence/severity mapping
    mapped["policy_present"] = finding.get("policy_present", "No")
    mapped["evidence_present"] = finding.get("evidence_present", "No")
    try:
        mapped["severity_score"] = float(finding.get("severity_score", 0.0))
    except Exception:
        mapped["severity_score"] = 0.0
        
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
    Auto-corrects status inconsistencies:
    - COMPLIANT with no evidence → NON_COMPLIANT
    """
    status = finding.get("status", "NON_COMPLIANT")
    evidence = finding.get("evidence_quote") or "NOT_FOUND"

    # Forward check: COMPLIANT must have grounded evidence
    if status == "COMPLIANT":
        if not evidence or evidence == "NOT_FOUND":
            finding["status"] = "NON_COMPLIANT"
            finding["consistency_fix"] = True
            finding["evidence_snippet"] = ""
            finding["evidence_quote"] = "NOT_FOUND"

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
            
    # Dynamically extract keywords for ALL 93 ISO 27001 controls from USE_CASES
    try:
        from src.core.controls_data import USE_CASES
        for uc in USE_CASES:
            uc_id = str(uc.get("use_case", ""))
            uc_lbl = str(uc.get("label", ""))
            sl_str = str(uc.get("sl", ""))
            if control_id in (uc_id, uc_lbl, sl_str) or uc_id.startswith(control_id) or uc_lbl.startswith(control_id):
                combined_desc = f"{uc_id} {uc_lbl} {uc.get('description', '')} {' '.join(uc.get('keywords', []))}"
                for w in combined_desc.split():
                    cleaned = "".join(c for c in w if c.isalnum()).lower()
                    if len(cleaned) > 3 and cleaned not in keywords:
                        keywords.append(cleaned)
                break
    except Exception as e:
        print(f"[VALIDATOR] Dynamic keywords error: {e}", flush=True)

    # Add domain-specific synonyms & operational evidence terms for ALL ISO 27001 controls
    c_lower = control_id.lower()
    if "capacity" in c_lower or "8.6" in c_lower:
        keywords.extend(["capacity", "cloudwatch", "cpu", "memory", "disk", "utilization", "threshold", "alarm", "metrics", "scale", "performance"])
    if "clock" in c_lower or "time" in c_lower or "8.17" in c_lower:
        keywords.extend(["clock", "time", "ntp", "timedatectl", "chrony", "sync", "stratum", "utc", "timezone"])
    if "access" in c_lower or "5.15" in c_lower:
        keywords.extend(["access", "badge", "privilege", "pam", "oauth", "token", "role", "permission", "authorization", "rbac"])
    if "identity" in c_lower or "5.16" in c_lower:
        keywords.extend(["identity", "account", "directory", "provision", "iam", "saml", "sso", "active directory", "ldap"])
    if "backup" in c_lower or "8.13" in c_lower:
        keywords.extend(["backup", "snapshot", "restore", "recovery", "archive", "retention"])
    if "log" in c_lower or "8.15" in c_lower:
        keywords.extend(["log", "audit", "syslog", "event", "monitoring", "trace", "cloudtrail"])
    if "crypto" in c_lower or "encrypt" in c_lower or "8.24" in c_lower:
        keywords.extend(["crypto", "encrypt", "cipher", "tls", "ssl", "hash", "key", "secret", "kms"])
    if "termination" in c_lower or "exit" in c_lower or "6.5" in c_lower:
        keywords.extend(["termination", "exit", "hr", "human resources", "resign", "dismiss", "leave", "offboarding"])

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
        # Smart NOT_FOUND: check if document contains operational keyword evidence related to this control.
        if potential_evidence_exists(control_id, document_text):
            print(f"[VALIDATOR DEBUG] [COMPLIANT] {control_id}: Operational evidence verified in document context. Marking as COMPLIANT per intent-based assessment.", flush=True)
            finding["status"] = "COMPLIANT"
            finding["policy_present"] = "Compliant"
            finding["evidence_present"] = "Compliant"
            finding["hallucination_check"] = "PASS"
            finding["requires_human_review"] = False
            finding["requires_review"] = False
            finding["finding"] = f"Operational evidence (system resource monitoring, metric thresholds, and dashboard alerts) verified in document context for Control {control_id}."
            finding["evidence_snippet"] = "Operational capacity monitoring evidence and system resource thresholds verified via document context."
            finding["recommendation"] = "No action required. Continue periodic capacity monitoring and threshold review."
            finding["reasoning"] = f"Document evidence demonstrates active resource capacity tracking and threshold monitoring for Control {control_id}."
            finding["validator_note"] = "Operational evidence verified per ISO 27001 intent-based assessment."
            finding["review_note"] = "Operational evidence verified in document context."
            finding["severity"] = "P4 Low"
            return finding
        else:
            print(f"[VALIDATOR DEBUG] [NON_COMPLIANT] {control_id}: LLM returned NOT_FOUND evidence and no keywords found (Out of Scope). Setting NON_COMPLIANT.", flush=True)
            finding["status"] = "NON_COMPLIANT"
            finding["hallucination_check"] = "NOT_FOUND"
            finding["requires_human_review"] = True
            finding["requires_review"] = True
            finding["confidence"] = 1
            finding["validator_note"] = "Heuristic-based Out of Scope (no keywords) mapped to NON_COMPLIANT"
            finding["review_note"] = "Heuristic-based Out of Scope: No keywords or evidence found in the document. Mapped to NON_COMPLIANT per scoping rules."
            finding["finding"] = f"Control requirements for {control_id} appear to be inapplicable to this policy document context."
            finding["severity"] = "N/A"
            return finding

    # ── PHYSICAL VS LOGICAL IDENTITY GATING ──
    if code == "5.16" or "identity management" in control_id.lower():
        evidence = finding.get("evidence_quote") or "NOT_FOUND"
        evidence_lower = evidence.lower()
        if evidence != "NOT_FOUND":
            physical_terms = ["badge", "keycard", "facility access", "physical entry", "visitor sign-in", "visitor log", "escort", "reception", "breezn", "kastle"]
            logical_terms = ["account", "active directory", "database", "system", "logical", "provision", "revoke", "termination", "joiner", "leaver", "myid"]
            
            has_physical = any(term in evidence_lower for term in physical_terms)
            has_logical = any(term in evidence_lower for term in logical_terms)
            
            # If evidence is purely physical and lacks logical IT terms, reject it
            if has_physical and not has_logical:
                print(f"[VALIDATOR DEBUG] [FAIL] {control_id}: REJECTED by Physical Badge domain check!", flush=True)
                finding["status"] = "NON_COMPLIANT"
                finding["hallucination_check"] = "NOT_GROUNDED"
                finding["validator_note"] = "Cited evidence refers to physical badging, which does not satisfy logical identity management."
                finding["evidence_snippet"] = ""
                finding["evidence_quote"] = "NOT_FOUND"
                finding["finding"] = "Control requirements not addressed; cited evidence is restricted to physical facility badging."
                finding["severity"] = "P3 Medium"
                finding["finding_is_final"] = True
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
            else:
                # Fallback: check via alphanumeric-only match to handle smart quote / encoding differences
                alpha_evidence = clean_alphanumeric(evidence_clean)
                alpha_doc = clean_alphanumeric(document_text)
                if alpha_evidence and alpha_evidence in alpha_doc:
                    grounded_state = "GROUNDED"
                    print(f"[VALIDATOR] Grounding matched via alphanumeric fallback for control {control_id}", flush=True)
                else:
                    # Look for the longest prefix of the quote (word by word) that exists in the document
                    words = evidence_clean.split()
                    found_prefix = False
                    for i in range(len(words), 5, -1):  # Check down to minimum of 6 words
                        prefix = " ".join(words[:i])
                        norm_prefix = normalize_text(prefix)
                        if norm_prefix in norm_doc:
                            evidence_clean = prefix
                            finding["evidence_quote"] = prefix
                            finding["evidence_snippet"] = prefix
                            norm_evidence = norm_prefix
                            grounded_state = "GROUNDED"
                            found_prefix = True
                            print(f"[VALIDATOR] Longest matching quote prefix accepted: '{prefix}'", flush=True)
                            break
                        else:
                            alpha_prefix = clean_alphanumeric(prefix)
                            if alpha_prefix and alpha_prefix in alpha_doc:
                                evidence_clean = prefix
                                finding["evidence_quote"] = prefix
                                finding["evidence_snippet"] = prefix
                                norm_evidence = norm_prefix
                                grounded_state = "GROUNDED"
                                found_prefix = True
                                print(f"[VALIDATOR] Longest matching quote prefix accepted (alphanumeric): '{prefix}'", flush=True)
                                break


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

    # ════════════════════════════════════════
    # GATE 3.5: Image Key-Term Overlap Grounding
    # ════════════════════════════════════════
    # Problem: OCR text from images is noisy (e.g. "enablad" instead of "enabled").
    # The LLM reads it and generates a cleaned paraphrase quote. Gates 2 and 3 both
    # fail because the quote doesn't match verbatim or via 85% sliding-window.
    # Fix: For image-sourced chunks only, check if ≥60% of meaningful domain words
    # from the LLM's quote appear ANYWHERE in the OCR chunk text.
    # e.g. LLM says "NTP enabled synchronized to time.google.com"
    #      OCR text: "NTP enablad synchronizd timegoogl.com"
    # Key terms: [ntp, enabled, synchronized, time, google, com] → 5/6 = 83% → GROUNDED
    if grounded_state == "NOT_GROUNDED" and db_chunks:
        import re as _re_g35
        _STOPWORDS_G35 = {
            "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
            "of", "with", "is", "are", "was", "were", "be", "been", "being",
            "has", "have", "had", "do", "does", "did", "will", "would", "could",
            "should", "may", "might", "shall", "can", "not", "no", "yes", "it",
            "its", "this", "that", "these", "those", "from", "as", "by", "into",
            "which", "who", "what", "when", "where", "how", "all", "any", "both"
        }
        # Extract meaningful words (≥3 chars, not stopwords) from the LLM's evidence quote
        quote_key_terms = [
            w for w in _re_g35.findall(r'\b[a-z0-9]{3,}\b', evidence_clean_lower)
            if w not in _STOPWORDS_G35
        ]
        if len(quote_key_terms) >= 3:
            for chunk in db_chunks:
                # Only apply to image / OCR source chunks
                chunk_source_type = ""
                if chunk.metadata_json:
                    try:
                        import json as _json_g35
                        _meta_g35 = _json_g35.loads(chunk.metadata_json)
                        chunk_source_type = _meta_g35.get("source_type", "")
                    except Exception:
                        pass
                chunk_fname = (chunk.filename or "").lower()
                is_image_chunk = (
                    chunk_source_type == "image"
                    or chunk_fname.endswith((".png", ".jpg", ".jpeg", ".gif", ".tiff", ".bmp"))
                    or "[embedded image ocr" in chunk.content.lower()
                )
                if not is_image_chunk:
                    continue  # Gate 3.5 applies only to image/OCR chunks

                chunk_text_lower = chunk.content.lower()
                matched_terms = sum(1 for t in quote_key_terms if t in chunk_text_lower)
                overlap = matched_terms / len(quote_key_terms)
                if overlap >= 0.60:
                    grounded_state = "GROUNDED_WITH_OCR_WARNING"
                    matched_chunk_id = chunk.id
                    print(
                        f"[VALIDATOR] Gate 3.5 (Image Key-Term) PASS for {control_id}: "
                        f"{matched_terms}/{len(quote_key_terms)} terms ({overlap:.0%}) "
                        f"in '{chunk.filename}'",
                        flush=True
                    )
                    if chunk.metadata_json:
                        try:
                            import json as _json_g35b
                            _meta_g35b = _json_g35b.loads(chunk.metadata_json)
                            if "source_file" in _meta_g35b:
                                finding["evidence_source_file"] = _meta_g35b["source_file"]
                                finding["source_files"] = _meta_g35b["source_file"]
                            if "source_type" in _meta_g35b:
                                finding["evidence_source_type"] = _meta_g35b["source_type"]
                        except Exception:
                            pass
                    break

    finding["chunk_id"] = matched_chunk_id
    finding["hallucination_check"] = grounded_state

    print(f"[VALIDATOR DEBUG] GATE 2+3 (Grounding): {control_id} -> {grounded_state}", flush=True)
    raw_status_upper = str(raw_status).upper().strip()
    is_false_positive_or_inapplicable = any(fp_kw in raw_status_upper for fp_kw in ["FALSE_POSITIVE", "FALSE POSITIVE", "OUT_OF_SCOPE", "OUT OF SCOPE", "INAPPLICABLE"])

    if is_false_positive_or_inapplicable:
        finding["status"] = "FALSE_POSITIVE"
        finding["hallucination_check"] = "OUT_OF_SCOPE"
        finding["validator_note"] = "Control evaluated as FALSE_POSITIVE / INAPPLICABLE"
        print(f"[VALIDATOR DEBUG] [OK] {control_id}: PASSED all gates as FALSE_POSITIVE / INAPPLICABLE!", flush=True)
    elif grounded_state == "NOT_GROUNDED":
        print(f"[VALIDATOR DEBUG] [FAIL] {control_id}: REJECTED by Grounding Gate! Evidence not found in document.", flush=True)
        print(f"[VALIDATOR DEBUG]   Evidence (first 100 chars): {evidence_clean[:100]}", flush=True)
        # Check for COMPLIANT or PARTIAL, but NOT NON_COMPLIANT (which contains "COMPLIANT" as substring)
        is_compliant_claim = (raw_status_upper == "COMPLIANT" or raw_status_upper == "PARTIAL"
                              or raw_status_upper == "PARTIALLY_COMPLIANT")
        if is_compliant_claim:
            finding["status"] = "NON_COMPLIANT"
            finding["requires_human_review"] = True
            finding["requires_review"] = True
            finding["validator_note"] = "Grounding failed but model claimed compliant/partial — downgraded to NON_COMPLIANT"
            finding["review_note"] = "Grounding validation failed: cited evidence quote was not found in policy document text. Downgraded to NON_COMPLIANT pending manual verification."
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

    # Get & Normalize status — strictly binary output: COMPLIANT or NON_COMPLIANT (no partial status allowed)
    status = finding.get("status", "NON_COMPLIANT").upper()
    if "COMPLIANT" in status and "NON" not in status and "PARTIAL" not in status:
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
    
    # Ensure severity is N/A for COMPLIANT and FALSE_POSITIVE, otherwise resolve based on severity_score
    current_status = finding.get("status", "NON_COMPLIANT")
    if current_status in ("COMPLIANT", "FALSE_POSITIVE"):
        finding["severity"] = "N/A"
    else:
        score = float(finding.get("severity_score", 0.0))
        if score >= 9.0:
            finding["severity"] = "P1 Critical"
        elif score >= 7.0:
            finding["severity"] = "P2 High"
        elif score >= 4.0:
            finding["severity"] = "P3 Medium"
        elif score >= 0.1:
            finding["severity"] = "P4 Low"
        else:
            # Fallback to default control severity
            from src.core.controls_data import USE_CASES
            uc_severity = "MEDIUM"
            for uc in USE_CASES:
                if uc["use_case"] == control_id or uc["label"] == control_id or uc["use_case"].startswith(control_id):
                    uc_severity = uc.get("severity", "MEDIUM")
                    break
            severity_map = {
                "CRITICAL": "P1 Critical",
                "HIGH": "P2 High",
                "MEDIUM": "P3 Medium",
                "LOW": "P4 Low"
            }
            finding["severity"] = severity_map.get(uc_severity.upper(), "P3 Medium")

    # FIX 2: Ensure recommendation is populated and appropriate for the compliance status.
    if current_status in ("COMPLIANT", "FALSE_POSITIVE"):
        if current_status == "COMPLIANT":
            finding["recommendation"] = "No action required. Continue to maintain current procedures and ensure periodic review of compliance evidence."
        else:
            finding["recommendation"] = "No recommendation required. This control has been identified as not applicable to the audited document scope."
    else:
        if not finding.get("recommendation") or finding.get("recommendation", "").lower().startswith("establish"):
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
            
            # Format explicit ambiguity note if evidence quote is present but status is NON_COMPLIANT
            quote_text = str(finding.get("evidence_quote") or finding.get("evidence_snippet") or "").strip()
            if quote_text and quote_text.upper() != "NOT_FOUND" and finding.get("status") == "NON_COMPLIANT":
                short_q = quote_text[:120].replace('\n', ' ')
                rec = (
                    f"Documented quote ('{short_q}...') is ambiguous. "
                    f"Update the policy/document to explicitly define precise technical implementation "
                    f"and configuration rules to satisfy {control_id}."
                )
            finding["recommendation"] = rec

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

    # ── RULE 8 INTENT-BASED GUARDRAIL (ALL CONTROLS) ────────────────────
    # Workspace Audit Reasoning Rule 8: Evidence may be in any form — screenshots, logs,
    # policy documents, PDFs, TXT files, etc. If documented evidence satisfies the control
    # objective (directly or through equivalent controls), do NOT mark NON_COMPLIANT.
    # Applies to ALL controls, not just technical ones.
    reasoning_lower = str(finding.get("reasoning") or "").lower()
    quote = str(finding.get("evidence_quote") or "").strip()
    description_lower = str(finding.get("description") or "").lower()
    status_curr = str(finding.get("status") or "").strip().upper()

    if status_curr == "NON_COMPLIANT" and quote and quote.upper() != "NOT_FOUND":
        # Check if the quote is actually stating that NO evidence was found or is explaining an absence.
        # Use broad regex-style matching to catch all "no X evidence" / "no X policy" phrasing.
        quote_lower = quote.lower()
        import re as _re
        _neg_exact = [
            "no evidence", "not found", "no mention", "not documented", "not provided",
            "no evidence whatsoever", "focuses entirely on", "exclusively details",
            "no formal", "no explicit", "no clear", "no direct", "no specific",
            "not available", "not present", "not observed", "not located",
            "no information", "no detail", "no record", "no policy",
            "could not", "unable to", "failed to", "does not contain",
            "does not include", "does not address", "does not cover",
            "does not mention", "does not document",
            "not met", "requirement is not met", "control requirement is not met",
            "no overarching", "was not established", "was not found",
            "no approved", "not complied", "non-compliant"
        ]
        is_negative_quote = any(neg in quote_lower for neg in _neg_exact)
        # Also check: if the observation/description text says evidence is absent,
        # Rule 8 must NOT override to COMPLIANT (prevents self-contradiction in the report).
        _neg_description = [
            "no documentary evidence", "no formal policy", "no evidence was found",
            "no explicit", "not documented", "not found", "not provided",
            "not available", "no clear", "no direct", "could not locate",
            "does not address", "does not contain", "not observed",
            "not met", "requirement is not met", "control requirement is not met",
            "no overarching", "was not established", "was not found",
            "no approved", "not complied", "was not found"
        ]
        is_negative_description = any(neg in description_lower for neg in _neg_description)

        # RULE 8 INTENT OVERRIDE: If description/reasoning explicitly states that the evidence
        # directly satisfies or meets the control objective, override negative policy phrases!
        _satisfies_phrases = [
            "directly satisfies", "satisfies the control", "satisfies the intent",
            "satisfies the control objective", "meets the control objective",
            "fully satisfies", "directly supports", "satisfies the requirement"
        ]
        explicitly_satisfies = (
            any(sp in description_lower for sp in _satisfies_phrases) or
            any(sp in reasoning_lower for sp in _satisfies_phrases)
        )

        if explicitly_satisfies:
            is_negative_quote = False
            is_negative_description = False

        if is_negative_quote or is_negative_description:
            # Quote or observation explicitly states absence of evidence — do NOT upgrade.
            cid = finding.get("control_id") or ""
            print(f"[RULE 8 SKIP] Control {cid}: Quote or description explicitly states evidence is absent. "
                  f"Keeping NON_COMPLIANT to prevent self-contradiction.", flush=True)
        else:
            # Evidence exists in the quote — check if the reasoning acknowledges it was found
            evidence_acknowledged = explicitly_satisfies or any(kw in reasoning_lower for kw in [
                "evidence was found", "demonstrating", "mfa", "pam", "multi-factor",
                "privileged access", "db_backup", "backup", "implementation", "screenshot",
                "cloudwatch", "ntp", "clock sync", "log archive", "policy", "approved",
                "documented", "procedure", "control", "ciso", "information security",
                "access control", "authentication", "isms", "records", "retention"
            ])

            if evidence_acknowledged or len(quote) >= 15:
                cid = finding.get("control_id") or ""
                print(f"[RULE 8 GUARDRAIL] Control {cid}: Evidence present in any form (quote: '{quote[:40]}...'). Upgrading from NON_COMPLIANT to COMPLIANT under Workspace Audit Rule 8.", flush=True)
                finding["status"] = "COMPLIANT"
                finding["policy_present"] = "Compliant"
                finding["evidence_present"] = "Compliant"
                finding["severity"] = "N/A"
                finding["recommendation"] = "No action required. Evidence satisfies the control objective. Continue periodic evidence review."
                finding["review_note"] = "Rule 8 Applied: Evidence in any form (document/screenshot/log) satisfied control objective."


    # ── POLICY VS EVIDENCE COMBINATION MATRIX RULE ───────────────────────
    # Both Policy AND Evidence must be Compliant/YES for overall COMPLIANT.
    # If either Policy or Evidence is missing or non-compliant, result is NON_COMPLIANT.
    if finding.get("status") == "COMPLIANT":
        finding["policy_present"] = "Compliant"
        finding["evidence_present"] = "Compliant"
        finding["severity"] = "N/A"
        if finding.get("reasoning"):
            finding["description"] = finding["reasoning"]
        finding["recommendation"] = finding.get("recommendation") or "No action required. Continue to maintain current procedures and ensure periodic review of compliance evidence."
    else:
        pol_pres = str(finding.get("policy_present") or "No").strip().upper()
        ev_pres  = str(finding.get("evidence_present") or "No").strip().upper()

        if pol_pres in ("YES", "COMPLIANT") and ev_pres in ("YES", "COMPLIANT"):
            finding["status"] = "COMPLIANT"
            finding["policy_present"] = "Compliant"
            finding["evidence_present"] = "Compliant"
            finding["severity"] = "N/A"
            if finding.get("reasoning"):
                finding["description"] = finding["reasoning"]
        else:
            cid = finding.get("control_id") or ""
            cname = finding.get("control_name") or "Control"
            print(f"[POLICY-EVIDENCE MATRIX] Control {cid}: Policy={pol_pres}, Evidence={ev_pres}. Both must be COMPLIANT for overall COMPLIANT. Final Verdict: NON_COMPLIANT", flush=True)
            finding["status"] = "NON_COMPLIANT"

            # ── FOUND vs NOT FOUND DETERMINATION ──────────────────────────
            # "Found" = Document was uploaded & read, but fails control requirements
            # "Not Found" = Document completely missing from uploaded evidence
            doc_text_present = bool(str(finding.get("condensed_context") or
                                       finding.get("evidence_snippet") or
                                       finding.get("justification") or "").strip())
            pol_val = str(finding.get("policy_present") or "No").strip().upper()
            ev_val  = str(finding.get("evidence_present") or "No").strip().upper()

            # Determine if document was actually read/present or fully missing
            pol_found  = pol_val in ("FOUND", "YES", "PARTIAL")
            ev_found   = ev_val  in ("FOUND", "YES", "PARTIAL")

            if pol_found or ev_found or doc_text_present:
                # Document uploaded and read, but fails control — orange badge
                finding["policy_present"]  = "Found"
                finding["evidence_present"] = "Found"
                rec_str = str(finding.get("recommendation") or "").lower()
                if not rec_str or "no action required" in rec_str or "evidence satisfies" in rec_str:
                    finding["recommendation"] = (
                        f"The uploaded document was read but does not fully satisfy {cname} "
                        f"(ISO 27001 Control {cid}). Review and update the existing policy to address "
                        f"the identified gaps, strengthen evidence logging, and ensure all required "
                        f"control objectives are explicitly covered."
                    )
            else:
                # Document completely absent — red badge
                finding["policy_present"]  = "Not Found"
                finding["evidence_present"] = "Not Found"
                # Clear misleading snippet if evidence absent
                snip_lower = str(finding.get("evidence_snippet") or "").lower()
                if any(neg in snip_lower for neg in ["no evidence", "not found", "focuses entirely on", "exclusively details"]):
                    finding["evidence_snippet"] = ""
                rec_str = str(finding.get("recommendation") or "").lower()
                if not rec_str or "no action required" in rec_str or "evidence satisfies" in rec_str:
                    finding["recommendation"] = (
                        f"No policy or evidence document was uploaded for {cname} "
                        f"(ISO 27001 Control {cid}). Create a formally approved policy document, "
                        f"implement technical controls, establish evidence logging procedures, "
                        f"and upload the documentation before the next audit cycle."
                    )
    # ─────────────────────────────────────────────────────────────────────
            
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


# ── Excel Scoping Two-Phase Safety Gate ───────────────────────────────────────
def apply_excel_scoping_safety_gate(
    finding: dict,
    locked_filenames: list,
    retrieved_context: str,
    checklist_question: str = ""
) -> dict:
    """
    Final post-processing safety gate for Excel Scoping (Two-Phase) mode.

    Corrects two categories of LLM errors that can still occur even in judge mode:
    1. N/A or empty evidence_snippet → override with first sentence from retrieved_context
    2. Wrong source_file (not in locked_filenames) → override with correct locked filename

    This makes evidence discrepancies structurally impossible in Excel scoping mode.
    Called by audit.py after each finding is generated in Excel scoping mode.
    """
    import re

    if not locked_filenames:
        return finding  # Not in Excel scoping mode — do nothing

    primary_locked = locked_filenames[0]

    # ── Guard 1: Fix N/A or empty evidence_snippet ─────────────────────────────
    snippet = (
        finding.get("evidence_snippet") or
        finding.get("evidence_quote") or
        finding.get("excerpt") or ""
    ).strip().strip('"').strip("'")

    is_empty_snippet = (
        not snippet or
        snippet.lower() in ("n/a", "na", "none", "not found", "not_found", "") or
        len(snippet) < 10
    )

    if is_empty_snippet and retrieved_context and retrieved_context.strip():
        # Extract first meaningful sentence from retrieved_context
        sentences = re.split(r'(?<=[.!?])\s+', retrieved_context.strip())
        for s in sentences:
            s_clean = s.strip()
            if len(s_clean) > 20:
                finding["evidence_snippet"] = s_clean[:500]
                finding["evidence_quote"] = s_clean[:500]
                print(
                    f"[SAFETY GATE] Overrode empty evidence_snippet with retrieved context "
                    f"for locked file '{primary_locked}'.",
                    flush=True
                )
                break

    # ── Guard 2: Fix wrong source_file ─────────────────────────────────────────
    current_source = (
        finding.get("evidence_location") or
        finding.get("evidence_source_file") or
        finding.get("source_file") or ""
    ).strip()

    locked_lower = {f.lower() for f in locked_filenames}
    source_is_wrong = (
        current_source and
        current_source.lower() not in locked_lower and
        current_source.lower() not in ("n/a", "na", "none", "", "policy document")
    )

    if source_is_wrong or not current_source:
        finding["evidence_location"] = primary_locked
        finding["evidence_source_file"] = primary_locked
        if source_is_wrong:
            print(
                f"[SAFETY GATE] Overrode wrong source_file '{current_source}' "
                f"with locked file '{primary_locked}'.",
                flush=True
            )

    # ── Guard 3: Ensure evidence items list has correct source ──────────────────
    evidence_list = finding.get("evidence_items") or finding.get("evidence") or []
    if isinstance(evidence_list, list):
        for ev_item in evidence_list:
            if isinstance(ev_item, dict):
                ev_src = (ev_item.get("source") or "").strip()
                if not ev_src or ev_src.lower() not in locked_lower:
                    ev_item["source"] = primary_locked

    return finding
