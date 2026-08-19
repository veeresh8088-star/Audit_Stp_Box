# -*- coding: utf-8 -*-
"""
Strict Forensic Compliance Auditor - Validation Module
Implements the core grounding, leakage, confidence, and consistency checks.
"""
import re
import difflib
import json

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


def expand_to_complete_sentence(prefix: str, source_text: str, max_chars: int = 450) -> str:
    """
    Expands a verified quote prefix anchor into the full, authentic sentence/clause directly from the source text.
    Prevents chopped quotes ending mid-sentence (e.g. '...when entering a', '...i.e. BreezN or').
    """
    if not prefix or not source_text:
        return prefix
    prefix_clean = prefix.strip()
    if len(prefix_clean) < 8:
        return prefix_clean

    import re
    # Try finding exact, case-insensitive, or whitespace-normalized match in source_text
    idx = source_text.find(prefix_clean)
    if idx == -1:
        idx = source_text.lower().find(prefix_clean.lower())

    if idx == -1:
        # Try finding using the first 4 words of the prefix
        words = prefix_clean.split()
        if len(words) >= 4:
            first_few = " ".join(words[:4])
            idx = source_text.lower().find(first_few.lower())
            if idx == -1:
                clean_first = clean_alphanumeric(first_few)
                clean_src = clean_alphanumeric(source_text)
                if clean_first and clean_first in clean_src:
                    for w in words[:2]:
                        p = source_text.lower().find(w.lower())
                        if p != -1:
                            idx = p
                            break

    if idx != -1:
        remainder = source_text[idx:]
        pref_len = len(prefix_clean)

        # Look forward in remainder beyond prefix length up to max_chars
        search_region = remainder[pref_len:min(len(remainder), pref_len + max_chars)]

        # Search for sentence boundary: period/question/exclamation followed by space/newline,
        # or double newline (paragraph break), or bullet boundary
        m = re.search(r'(?<!\b[A-Za-z])(?<!\bi\.e)(?<!\be\.g)(?<!\bvs)\.[\s\n\r"”\']|\n\n|\r\n\r\n|\n(?=[0-9]+\.[0-9]+)|\Z', search_region)
        if m:
            end_pos = pref_len + m.end()
            completed = remainder[:end_pos].strip()
            completed = completed.rstrip(' "\'\n\r')
            if completed and not completed.endswith(('.', '!', '?', '"', '”', "'", '’', ')')):
                completed = completed + "."
            if len(completed) >= len(prefix_clean):
                return completed

    return prefix_clean


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
            
    if isinstance(hints, str):
        hints = [hints]
    elif not isinstance(hints, (list, tuple, set)):
        hints = []

    import difflib
    for hint in hints:
        if not hint or not isinstance(hint, str):
            continue
        hint_clean = hint.strip().strip('"').strip("'").strip('“').strip('”').strip().lower()
        if not hint_clean or len(hint_clean) < 15:
            continue
        # Direct substring check for meaningful hint phrases
        if hint_clean in evidence_clean:
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
    
    _loc = (
        finding.get("evidence_source_file") or
        finding.get("source_files") or
        finding.get("evidence_location") or ""
    ).strip()

    # Combine Parent Document and Child Image Filename (e.g. "Monitoring AWS CloudWatch.docx (image1.png)")
    parent_file = (finding.get("source_files") or finding.get("parent_document") or "").strip()
    child_file = (finding.get("evidence_source_file") or "").strip()

    if child_file and parent_file and child_file != parent_file:
        if child_file.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff")) and parent_file not in child_file:
            _loc = f"{parent_file} ({child_file})"
        elif _loc and parent_file not in _loc and child_file in _loc:
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
    print(f"[VALIDATOR DEBUG] RAW LLM Evidence: {raw_evidence}", flush=True)
    print(f"[VALIDATOR DEBUG] RAW LLM Confidence: {raw_confidence}", flush=True)
    print(f"[VALIDATOR DEBUG] RAW LLM Gap: {raw_gap}", flush=True)
    print(f"{'='*60}", flush=True)
    
    raw_status_upper = str(raw_status).upper().strip()
    is_false_positive_or_inapplicable = any(fp_kw in raw_status_upper for fp_kw in ["FALSE_POSITIVE", "FALSE POSITIVE", "OUT_OF_SCOPE", "OUT OF SCOPE", "INAPPLICABLE"])

    if is_false_positive_or_inapplicable:
        finding["status"] = "FALSE_POSITIVE"
        finding["hallucination_check"] = "OUT_OF_SCOPE"
        finding["validator_note"] = "Control evaluated as FALSE_POSITIVE / INAPPLICABLE"
        finding["severity"] = "N/A"
        finding["recommendation"] = "No recommendation required. This control has been identified as not applicable to the agreed audit scope."
        print(f"[VALIDATOR DEBUG] [OK] {control_id}: PASSED all gates as FALSE_POSITIVE / INAPPLICABLE!", flush=True)
        return check_consistency(apply_confidence_gate(finding))

    evidence = finding.get("evidence_quote") or "NOT_FOUND"
    evidence_clean = evidence.strip().strip('"').strip("'").strip('“').strip('”').strip()
    if not evidence_clean or evidence_clean == "NOT_FOUND":
        evidence_clean = "NOT_FOUND"
    evidence_clean_lower = evidence_clean.lower()
        
    finding["evidence_quote"] = evidence_clean
    finding["evidence_snippet"] = evidence_clean if evidence_clean != "NOT_FOUND" else ""
    finding["chunk_id"] = None

    if evidence_clean == "NOT_FOUND":
        # NOT_FOUND must never be silently auto-approved. This used to check for a loose
        # keyword match anywhere in the full combined document text (all uploaded files,
        # unscoped) and, if found, stamp the finding COMPLIANT with hardcoded boilerplate
        # text written for one specific control (8.6 Capacity Management) -- which then
        # appeared verbatim on unrelated controls (e.g. 5.1 Policies for Information
        # Security) any time the LLM itself found no real evidence to quote. A generic
        # keyword match is not evidence the control is satisfied. Fail safe instead:
        # always NON_COMPLIANT, flagged for human review; the keyword hit only changes
        # the review note/severity, it never upgrades the status.
        has_keyword_hit = potential_evidence_exists(control_id, document_text)
        # Describe WHAT is missing, not just that review is needed -- pull the control's
        # own expected-evidence description (set upstream in audit_graph.py) so the finding
        # names the actual requirement instead of a generic "requires manual review" note.
        expected_hints = expected_evidence_map.get(code) if expected_evidence_map else None
        expected_text = str(expected_hints[0]).strip().rstrip(".") if expected_hints and expected_hints[0] else ""
        print(
            f"[VALIDATOR DEBUG] [NON_COMPLIANT] {control_id}: LLM returned NOT_FOUND evidence "
            f"(keyword-level match in documents: {has_keyword_hit}). Setting NON_COMPLIANT for human review.",
            flush=True
        )
        finding["status"] = "NON_COMPLIANT"
        finding["hallucination_check"] = "NOT_FOUND"
        finding["requires_human_review"] = True
        finding["requires_review"] = True
        finding["confidence"] = 1

        pol_stat = str(finding.get("policy_status") or "").upper()
        pol_assess = str(finding.get("policy_assessment") or "").upper()
        if pol_stat == "FOUND" and pol_assess == "COMPLIANT":
            gap_text = "Policy requirements are adequately documented, but no operational evidence was provided to demonstrate implementation."
            finding["validator_note"] = gap_text
            finding["review_note"] = gap_text
            finding["finding"] = gap_text
            finding["severity"] = "P3 Medium"
            finding["recommendation"] = (
                f"A policy for {control_id} was found and is adequately documented, but no operational evidence "
                f"of implementation was provided. Provide appropriate operational evidence such as access logs, "
                f"visitor records, access approval records, or completed access-review records demonstrating implementation."
            )
            return finding

        if has_keyword_hit:
            gap_text = (
                f"The uploaded documents reference related terms, but do not contain {expected_text}."
                if expected_text else
                "The uploaded documents reference related terms, but no passage documenting this control's requirement could be found."
            )
            finding["validator_note"] = gap_text
            finding["review_note"] = gap_text
            finding["finding"] = gap_text
            finding["severity"] = "P3 Medium"
            finding["recommendation"] = (
                f"Upload or point to the specific document containing {expected_text}, "
                f"or add the missing passage to an existing document, for auditor review."
                if expected_text else
                f"Provide the specific document demonstrating compliance with {control_id} for auditor review."
            )
        else:
            gap_text = (
                f"The uploaded documents contain no evidence of {expected_text}."
                if expected_text else
                f"The uploaded documents contain no evidence addressing {control_id}."
            )
            finding["validator_note"] = gap_text
            finding["review_note"] = gap_text
            finding["recommendation"] = (
                f"Establish, document, and implement {expected_text} to satisfy this control."
                if expected_text else
                f"Establish, document, and implement procedures to satisfy {control_id}."
            )
            finding["finding"] = gap_text
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
    # evidence_clean may contain multiple distinct excerpts joined by "\n\n" (multi-
    # evidence findings). Each one is verified INDEPENDENTLY here — checking the whole
    # joined blob as a single quote would (and did) always fail, since 6 sentences from
    # different parts of a document never appear as one continuous block anywhere in the
    # source, which silently collapsed correct multi-item findings down to whichever
    # single prefix happened to match first.
    # ════════════════════════════════════════
    grounded_state = "NOT_GROUNDED"
    matched_chunk_id = None

    candidate_items = (
        [c.strip() for c in evidence_clean.split("\n\n") if c.strip()]
        if evidence_clean != "NOT_FOUND" else []
    )
    grounded_items = []

    for item_text in candidate_items:
        norm_item = normalize_text(item_text)
        if not norm_item or norm_item == "not_found":
            continue

        item_grounded = False
        item_final_text = item_text

        if db_chunks:
            for chunk in db_chunks:
                norm_chunk = normalize_text(chunk.content)
                if norm_item in norm_chunk:
                    item_grounded = True
                    matched_chunk_id = matched_chunk_id or chunk.id
                    item_final_text = expand_to_complete_sentence(item_text, chunk.content)
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
        if not item_grounded and document_text:
            norm_doc = normalize_text(document_text)
            if norm_item in norm_doc:
                item_grounded = True
                item_final_text = expand_to_complete_sentence(item_text, document_text)
            else:
                # Fallback: check via alphanumeric-only match to handle smart quote / encoding differences
                alpha_item = clean_alphanumeric(item_text)
                alpha_doc = clean_alphanumeric(document_text)
                if alpha_item and alpha_item in alpha_doc:
                    item_grounded = True
                    item_final_text = expand_to_complete_sentence(item_text, document_text)
                    print(f"[VALIDATOR] Grounding matched via alphanumeric fallback for control {control_id}", flush=True)
                else:
                    # Look for the longest prefix of THIS item (word by word) that exists in the document
                    words = item_text.split()
                    for i in range(len(words), 5, -1):  # Check down to minimum of 6 words
                        prefix = " ".join(words[:i])
                        norm_prefix = normalize_text(prefix)
                        if norm_prefix in norm_doc:
                            item_final_text = expand_to_complete_sentence(prefix, document_text)
                            item_grounded = True
                            print(f"[VALIDATOR] Longest matching quote prefix expanded to complete sentence: '{item_final_text}'", flush=True)
                            break
                        alpha_prefix = clean_alphanumeric(prefix)
                        if alpha_prefix and alpha_prefix in alpha_doc:
                            item_final_text = expand_to_complete_sentence(prefix, document_text)
                            item_grounded = True
                            print(f"[VALIDATOR] Longest matching quote prefix expanded (alphanumeric): '{item_final_text}'", flush=True)
                            break

        if item_grounded:
            grounded_items.append(item_final_text)

    if grounded_items:
        grounded_state = "GROUNDED"
        evidence_clean = "\n\n".join(grounded_items)
        finding["evidence_quote"] = evidence_clean
        finding["evidence_snippet"] = evidence_clean

    norm_evidence = normalize_text(evidence_clean) if evidence_clean != "NOT_FOUND" else ""


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

    # Get & Normalize status — strictly binary COMPLIANT/NON_COMPLIANT, with FALSE_POSITIVE
    # preserved as its own third state (a control that doesn't apply is not the same as a
    # failed one). Pre-existing bug fixed here: FALSE_POSITIVE doesn't contain the substring
    # "COMPLIANT", so this used to always fall through to the `else` and get silently
    # relabeled NON_COMPLIANT, destroying the FALSE_POSITIVE/Out-of-Scope classification
    # set earlier in this function (the "PASSED all gates as FALSE_POSITIVE" branch above).
    status = finding.get("status", "NON_COMPLIANT").upper()
    if status == "FALSE_POSITIVE":
        finding["status"] = "FALSE_POSITIVE"
    elif "COMPLIANT" in status and "NON" not in status and "PARTIAL" not in status:
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
        _rec_lower = finding.get("recommendation", "").lower()
        if not finding.get("recommendation") or _rec_lower.startswith("establish") or _is_stale_no_action_recommendation(_rec_lower):
            from src.core.controls_data import USE_CASES

            # ── Base recommendation from USE_CASES (control-specific fallback) ──
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

            # ── Smart recommendation: diagnose WHY it failed, give targeted advice ──
            # Priority order: OCR/image quality → wrong document → missing policy →
            # missing evidence → insufficient evidence → fallback to USE_CASES rec.
            _ev_gap   = str(finding.get("evidence_gap")   or "").lower()
            _pol_gap  = str(finding.get("policy_gap")     or "").lower()
            _ev_rel   = str(finding.get("evidence_relevance") or "").upper()
            _ev_stat  = str(finding.get("evidence_status")    or "").upper()
            _pol_stat = str(finding.get("policy_status")      or "").upper()
            _ev_snip  = str(finding.get("evidence_snippet") or finding.get("evidence_quote") or "").lower()

            # 1. OCR / image quality issue — blurry, unreadable, garbled text
            _ocr_signals = ("cannot read", "unreadable", "unclear", "blurry", "illegible",
                            "ocr", "poor quality", "low resolution", "garbled", "distorted",
                            "text not extracted", "no text", "image quality", "scan quality")
            if any(s in _ev_gap for s in _ocr_signals) or any(s in _ev_snip for s in _ocr_signals):
                rec = (
                    f"The uploaded image/scan could not be read clearly by OCR. "
                    f"Re-upload a higher-resolution scan or a text-based PDF for {control_id}. "
                    f"Ensure the document is at least 150 DPI and not password-protected."
                )

            # 2. Wrong document type — evidence is IRRELEVANT to this control
            elif _ev_rel == "IRRELEVANT":
                rec = (
                    f"The uploaded document does not contain evidence relevant to {control_id}. "
                    f"Upload the correct document type. Expected: "
                    f"{next((uc.get('expected','') for uc in USE_CASES if uc['use_case']==control_id or uc['label']==control_id), 'appropriate evidence for this control')}."
                )

            # 3. Policy missing, evidence present → need a policy statement
            elif _pol_stat == "NOT_FOUND" and _ev_stat == "FOUND":
                rec = (
                    f"Evidence of implementation was found but no formal policy statement was identified for {control_id}. "
                    f"Document a written policy or procedure that mandates this control requirement."
                )

            # 4. Policy present, evidence missing → need operational proof
            elif _pol_stat == "FOUND" and _ev_stat == "NOT_FOUND":
                rec = (
                    f"A policy for {control_id} was found but no operational evidence of implementation was provided. "
                    f"Upload records, logs, screenshots, or reports that demonstrate the policy is actively followed."
                )

            # 5. Both missing — nothing found at all
            elif _pol_stat == "NOT_FOUND" and _ev_stat == "NOT_FOUND":
                rec = (
                    f"No policy or evidence was found for {control_id}. "
                    f"Upload both: (1) a documented policy or procedure, and (2) operational evidence "
                    f"such as logs, reports, or screenshots that prove implementation."
                )

            # 6. Both found but insufficient — use gap text if available
            elif _ev_gap and _ev_gap not in ("no evidence gap identified.", "none", "n/a", ""):
                # Use the LLM's own gap description trimmed to 200 chars
                _gap_summary = _ev_gap[:200].rstrip("., ")
                rec = (
                    f"For {control_id}: {_gap_summary.capitalize()}. "
                    f"Address this specific gap and re-upload supporting evidence."
                )

            finding["recommendation"] = rec

    return finding


_STALE_NO_ACTION_PHRASES = [
    "no action required", "no action needed", "no further action",
    "no corrective action", "no remediation required", "no remediation needed",
    "evidence satisfies", "adequately addressed", "not required",
    "continue to maintain current procedures",
]


def _is_stale_no_action_recommendation(rec_lower: str) -> bool:
    """True if a recommendation reads like a COMPLIANT closure note (any phrasing),
    which must never survive on a finding whose final status is NON_COMPLIANT."""
    return any(phrase in rec_lower for phrase in _STALE_NO_ACTION_PHRASES)


# ── Date grounding & deterministic freshness/validity ──────────────────────────
# The LLM's own evidence_date / policy_*_date and evidence_freshness /
# policy_validity fields were previously trusted unverified -- unlike the main
# evidence quote, which is grounding-checked against the source text, a claimed
# date could be entirely fabricated (never appeared anywhere in the document)
# and still get labeled CURRENT, or a genuinely old-but-real date could get
# labeled CURRENT because LLMs are unreliable at date arithmetic. Both were
# observed on a real audit run: a claimed 2026 date with no date anywhere in
# the source text, and real 2024 backup dates labeled CURRENT during a 2026
# audit.

_STALENESS_KEYWORDS = [
    "expired", "deprecated", "decommissioned", "no longer valid", "no longer used",
    "no longer in use", "superseded", "obsolete", "discontinued", "retired",
    "end of life", "end-of-life", "sunset", "not in use",
]


def _has_staleness_language(text):
    """Explicit staleness signal in the text itself, independent of any date --
    catches documents that say they're outdated even when no parseable date
    exists to compare, or overrides a stale document that happens to carry a
    misleadingly recent-looking date."""
    if not text:
        return False
    t = text.lower()
    return any(kw in t for kw in _STALENESS_KEYWORDS)


def _extract_date_tokens(date_str):
    import re
    return re.findall(r"\d+", date_str or "")


def check_date_grounding(date_str, *texts):
    """
    Verifies a claimed date has real support in the source text(s), the same
    principle as check_grounding() for evidence quotes -- don't trust a date
    the LLM output unless the document actually contains it. Loosely matches
    on numeric tokens (a 4-digit year plus at least one day/month-sized token)
    rather than requiring an exact string match, since dates get reformatted
    between the LLM's output and whatever format the source document used.
    """
    if not date_str:
        return False
    tokens = _extract_date_tokens(date_str)
    if not tokens:
        return False
    year_tokens = [t for t in tokens if len(t) == 4]
    other_tokens = [t for t in tokens if len(t) in (1, 2)]
    haystack = " ".join(t for t in texts if t).lower()
    if not haystack:
        return False
    year_ok = any(t in haystack for t in year_tokens) if year_tokens else True
    other_ok = any(t in haystack for t in other_tokens) if other_tokens else True
    return year_ok and other_ok


def _parse_loose_date(date_str):
    """Best-effort parse of a date string in whatever format the LLM/document used."""
    if not date_str:
        return None
    from datetime import datetime
    formats = [
        "%Y-%m-%d", "%d-%m-%Y", "%d/%m/%Y", "%m/%d/%Y", "%B %d, %Y", "%d %B %Y",
        "%b %d, %Y", "%d %b %Y", "%Y/%m/%d", "%d-%b-%Y", "%d.%m.%Y",
    ]
    s = date_str.strip()
    for fmt in formats:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def resolve_evidence_freshness(finding, document_text, db_chunks=None):
    """
    Replaces the LLM's raw, unverified evidence_freshness self-rating with a
    grounded, conservative determination:
      - evidence_date must actually appear in the source text, or it's wiped
        and freshness forced to UNKNOWN (never trust an ungrounded date).
      - Evidence has no documented required-recency in this system (unlike
        policy, which can carry its own stated review/expiry dates) -- so a
        grounded-but-old date does NOT get auto-flipped to STALE; that would
        be inventing a cadence requirement that was never actually stated
        anywhere. Freshness stays UNKNOWN, but the real grounded date is kept
        and shown, so a human auditor can judge the age themselves instead of
        being told (wrongly) that it's current.
      - Explicit staleness language in the evidence text itself (e.g.
        "decommissioned", "no longer in use") overrides to STALE regardless
        of any date, since that's a real, checkable textual signal.
    """
    chunks_text = " ".join(c.content for c in db_chunks if getattr(c, "content", None)) if db_chunks else ""
    evidence_date = str(finding.get("evidence_date") or "").strip()
    evidence_quote = str(finding.get("evidence_quote") or finding.get("evidence_snippet") or "")

    if evidence_date and not check_date_grounding(evidence_date, document_text or "", chunks_text, evidence_quote):
        finding["evidence_date"] = ""
        evidence_date = ""

    if _has_staleness_language(evidence_quote) or _has_staleness_language(document_text or ""):
        finding["evidence_freshness"] = "STALE"
    elif not evidence_date:
        finding["evidence_freshness"] = "UNKNOWN"
    else:
        # Grounded date exists but no stated recency requirement to compare
        # against -- keep it visible, don't assert a verdict it can't support.
        finding["evidence_freshness"] = "UNKNOWN"

    return finding


def resolve_policy_validity(finding, document_text, db_chunks=None):
    """
    Same grounding principle as resolve_evidence_freshness(), but policy DOES
    have an explicit requirement to compare against when the document states
    one: its own effective/review/expiry dates. When those are grounded and
    parseable, validity is computed deterministically against today's real
    date instead of trusting the LLM's own arithmetic.
    """
    chunks_text = " ".join(c.content for c in db_chunks if getattr(c, "content", None)) if db_chunks else ""
    policy_text = str(finding.get("policy_finding") or "") + " " + str(finding.get("policy_clause") or "")

    for field in ("policy_effective_date", "policy_review_date", "policy_expiry_date"):
        val = str(finding.get(field) or "").strip()
        if val and not check_date_grounding(val, document_text or "", chunks_text, policy_text):
            finding[field] = ""

    if _has_staleness_language(policy_text) or _has_staleness_language(document_text or ""):
        finding["policy_validity"] = "EXPIRED"
        return finding

    from datetime import datetime
    today = datetime.now()

    expiry = _parse_loose_date(finding.get("policy_expiry_date"))
    if expiry:
        finding["policy_validity"] = "EXPIRED" if expiry < today else "CURRENT"
        return finding

    review = _parse_loose_date(finding.get("policy_review_date"))
    if review:
        finding["policy_validity"] = "REVIEW_OVERDUE" if review < today else "CURRENT"
        return finding

    # No grounded, parseable date to compare against -- don't invent a verdict.
    finding["policy_validity"] = "UNKNOWN"
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

    # ── DETERMINISTIC POLICY/EVIDENCE FINAL RESULT (RAG accuracy overhaul, Phase 6) ──
    # Replaces both the removed "Rule 8" heuristic upgrade (which silently upgraded
    # NON_COMPLIANT to COMPLIANT based on keyword matches in the LLM's own reasoning
    # text) and the old policy_present/evidence_present combination matrix. This is
    # plain Python conditional logic operating on the Phase 5 policy/evidence fields,
    # not LLM judgment -- per the user's explicit "deterministic, not free LLM
    # judgment" requirement. The LLM still gets exactly one chance to judge
    # equivalent-terminology evidence as satisfying the control, in its own
    # evidence_assessment/evidence_relevance fields -- there is no second guess here.
    #
    # FALSE_POSITIVE (control doesn't apply) is a different concept entirely and is
    # left untouched rather than being forced into this formula.
    if finding.get("status") != "FALSE_POSITIVE":
        # Replace the LLM's raw, unverified date/freshness self-ratings with a
        # grounded, deterministic determination before the formula below reads
        # them -- see resolve_evidence_freshness/resolve_policy_validity for why.
        finding = resolve_evidence_freshness(finding, document_text, db_chunks)
        finding = resolve_policy_validity(finding, document_text, db_chunks)

        policy_status = str(finding.get("policy_status") or "NOT_FOUND").strip().upper()
        policy_assessment = str(finding.get("policy_assessment") or "NON_COMPLIANT").strip().upper()
        policy_validity = str(finding.get("policy_validity") or "UNKNOWN").strip().upper()
        evidence_status = str(finding.get("evidence_status") or "NOT_FOUND").strip().upper()
        evidence_assessment = str(finding.get("evidence_assessment") or "NON_COMPLIANT").strip().upper()
        evidence_freshness = str(finding.get("evidence_freshness") or "UNKNOWN").strip().upper()

        # Trust independently-verified grounding (Gates 1-3.5, checked against the
        # actual source document) over the LLM's own unverified evidence_status
        # self-rating, so the two can never disagree about whether real evidence
        # text exists.
        _quote_check = str(finding.get("evidence_quote") or "").strip()
        if (finding.get("hallucination_check") in ("GROUNDED", "GROUNDED_WITH_OCR_WARNING")
                and _quote_check and _quote_check.upper() != "NOT_FOUND"):
            evidence_status = "FOUND"

        # UNKNOWN validity/freshness is acceptable (confirmed with the user) -- most
        # real documents never state effective/review/expiry dates or evidence
        # timestamps, and "never invent/assume" means an absent date is not itself
        # evidence of a problem. Only an explicitly *confirmed* issue (EXPIRED,
        # REVIEW_OVERDUE, STALE) blocks COMPLIANT.
        policy_valid_ok = policy_validity in ("CURRENT", "UNKNOWN")
        evidence_fresh_ok = evidence_freshness in ("CURRENT", "UNKNOWN")

        is_compliant = (
            policy_status == "FOUND" and policy_assessment == "COMPLIANT"
            and evidence_status == "FOUND" and evidence_assessment == "COMPLIANT"
            and policy_valid_ok and evidence_fresh_ok
        )

        finding["policy_status"] = policy_status
        finding["evidence_status"] = evidence_status
        finding["final_result"] = "COMPLIANT" if is_compliant else "NON_COMPLIANT"
        finding["status"] = finding["final_result"]

        # Keep the legacy policy_present/evidence_present fields (still read by the
        # UI/DB pending Phase 7) in sync with the new deterministic fields, rather
        # than the LLM's separate old-schema self-rating.
        if is_compliant:
            finding["policy_present"] = "Compliant"
            finding["evidence_present"] = "Compliant"
            finding["severity"] = "N/A"
            if finding.get("reasoning"):
                finding["description"] = finding["reasoning"]
            finding["recommendation"] = finding.get("recommendation") or "No action required. Continue to maintain current procedures and ensure periodic review of compliance evidence."
        else:
            cid = finding.get("control_id") or ""
            cname = finding.get("control_name") or "Control"
            print(f"[DETERMINISTIC FINAL RESULT] Control {cid}: policy_status={policy_status}, "
                  f"policy_assessment={policy_assessment}, policy_validity={policy_validity}, "
                  f"evidence_status={evidence_status}, evidence_assessment={evidence_assessment}, "
                  f"evidence_freshness={evidence_freshness} -> NON_COMPLIANT", flush=True)

            # ── FOUND vs NOT FOUND & POLICY vs EVIDENCE MAPPING ──────
            doc_text_present = bool(str(finding.get("condensed_context") or
                                       finding.get("evidence_snippet") or
                                       finding.get("justification") or "").strip())
            pol_found = policy_status == "FOUND"
            ev_found = evidence_status == "FOUND"

            # Separate presence mapping for policy and evidence
            if pol_found:
                finding["policy_present"] = "Compliant" if policy_assessment == "COMPLIANT" else "Found"
            else:
                finding["policy_present"] = "Not Found"

            if ev_found:
                finding["evidence_present"] = "Compliant" if evidence_assessment == "COMPLIANT" else "Found"
            else:
                finding["evidence_present"] = "Not Found"

            # Targeted smart recommendation for NON_COMPLIANT findings
            rec_str = str(finding.get("recommendation") or "").lower()
            if pol_found and policy_assessment == "COMPLIANT" and not ev_found:
                if not rec_str or "operational evidence" not in rec_str or _is_stale_no_action_recommendation(rec_str):
                    finding["recommendation"] = (
                        f"A policy for {cname} (ISO 27001 Control {cid}) was found and is adequately documented, "
                        f"but no operational evidence of implementation was provided. Provide appropriate "
                        f"operational evidence such as access logs, visitor records, access approval records, "
                        f"or completed access-review records demonstrating implementation."
                    )
            elif not rec_str or _is_stale_no_action_recommendation(rec_str):
                if not pol_found and ev_found:
                    finding["recommendation"] = (
                        f"Operational evidence was found for {cname} (ISO 27001 Control {cid}), but no formal "
                        f"policy statement was identified. Document and approve a written policy or standard "
                        f"that mandates this control requirement."
                    )
                elif pol_found or ev_found or doc_text_present:
                    finding["recommendation"] = (
                        f"The uploaded document was read but does not fully satisfy {cname} "
                        f"(ISO 27001 Control {cid}). Review and update the existing policy to address "
                        f"the identified gaps, strengthen evidence logging, and ensure all required "
                        f"control objectives are explicitly covered."
                    )
                else:
                    # Clear misleading snippet if evidence absent
                    snip_lower = str(finding.get("evidence_snippet") or "").lower()
                    if any(neg in snip_lower for neg in ["no evidence", "not found", "focuses entirely on", "exclusively details"]):
                        finding["evidence_snippet"] = ""
                    finding["recommendation"] = (
                        f"No policy or evidence document was uploaded for {cname} "
                        f"(ISO 27001 Control {cid}). Create a formally approved policy document, "
                        f"implement technical controls, establish evidence logging procedures, "
                        f"and upload the documentation before the next audit cycle."
                    )

            # Safeguard: if marked NON_COMPLIANT, ensure severity is never "N/A"
            if not finding.get("severity") or finding.get("severity") == "N/A":
                score = float(finding.get("severity_score", 0.0) or 0.0)
                if score >= 9.0:
                    finding["severity"] = "P1 Critical"
                elif score >= 7.0:
                    finding["severity"] = "P2 High"
                elif score >= 4.0:
                    finding["severity"] = "P3 Medium"
                elif score >= 0.1:
                    finding["severity"] = "P4 Low"
                else:
                    from src.core.controls_data import USE_CASES
                    uc_severity = "MEDIUM"
                    for uc in USE_CASES:
                        if uc["use_case"] == cid or uc["label"] == cid or uc["use_case"].startswith(cid):
                            uc_severity = uc.get("severity", "MEDIUM")
                            break
                    severity_map = {
                        "CRITICAL": "P1 Critical",
                        "HIGH": "P2 High",
                        "MEDIUM": "P3 Medium",
                        "LOW": "P4 Low"
                    }
                    finding["severity"] = severity_map.get(uc_severity.upper(), "P3 Medium")

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
