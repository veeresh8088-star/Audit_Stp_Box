# -*- coding: utf-8 -*-
"""
Excel Scoping Parser
====================
Dynamically parses any ISO 27001 audit scoping checklist from an Excel file.

Features:
- Auto-detects 1 to N file columns from the header row (keywords: file, evidence,
  policy, document, attachment, doc, upload)
- Resolves ISO control IDs using 3 fallback steps:
    1. Direct control ID match (e.g. "5.15", "ISO 8.17")
    2. Control name keyword match against USE_CASES
    3. Embedding cosine-similarity against USE_CASES descriptions (no LLM needed)
- Returns a list of dicts: {question, files, control_id, control_label,
  expected_evidence, prompt_hint, severity}
- Works for 8 rows, 50 rows, 100+ rows
"""

import re
import os
from typing import List, Dict, Optional

# ── Keywords that identify file-reference columns in the Excel header ─────────
# IMPORTANT: 'type' columns (File type, Document type) must be EXCLUDED because
# they contain extensions like 'PNG', 'JPG', 'PDF' which are not filenames.
_FILE_COL_KEYWORDS = {
    "file", "evidence", "policy", "document", "attachment", "doc", "upload",
    "exhibit", "reference", "source", "artifact"
}
# Words that, when present, indicate a TYPE/FORMAT column (not a filename column)
_FILE_TYPE_EXCLUSION_KEYWORDS = {"type", "format", "extension", "ext", "kind"}

# ── Direct keyword-to-control mapping for common audit questions ──────────────
# These cover the most frequent audit check phrasings so they resolve instantly
# without needing embedding similarity (which requires Ollama to be running).
_DIRECT_KEYWORD_CONTROL_MAP = [
    # Keywords in question text               -> control use_case string
    (["ntp", "clock", "synchroni", "time server"], "8.17 Clock Synchronization"),
    (["fraud analytics"], "5.1 Policies for Information Security"),
    (["multifactor", "mfa", "multi-factor", "2fa", "two-factor"], "8.5 Secure Authentication"),
    (["pam", "privileged access", "pim", "idam"], "8.2 Privileged Access Rights"),
    (["access control policy", "access control"], "5.15 Access Control"),
    # NOTE: control 8.5 is literally named "Secure Authentication" -- MFA and general
    # "how is authentication done" questions are about the authentication *mechanism*,
    # which is 8.5's scope, not 5.17 (which covers password/credential *lifecycle*
    # management -- issuance, storage, revocation -- see the password/credential/secret
    # entry further down, which correctly stays on 5.17). Bare "auth" was removed: as a
    # substring match it also fired on "authorization"/"author" and could out-rank the
    # more specific "access control" entry above depending on list order, misrouting an
    # Access Control row's evidence file into 8.5's (or vice versa) whenever both
    # keywords co-occurred in a question.
    (["authentication", "how is the auth"], "8.5 Secure Authentication"),
    # Bare "register" removed: as a substring it also matched "risk register",
    # misrouting risk-assessment questions into Asset Inventory.
    (["asset management policy", "asset management", "asset inventory"], "5.9 Inventory of Information and Other Associated Assets"),
    (["incident management policy", "incident response", "incident plan", "irp"], "5.24 Information Security Incident Management Planning and Preparation"),
    (["business continuity plan", "bcp", "disaster recovery", "dr plan"], "5.29 Information Security During Disruption"),
    # Checked BEFORE the HR "screening" entry below so "vulnerability screening"
    # resolves to 8.8 instead of being caught by the HR background-check keyword.
    (["vulnerability", "patch", "scan"], "8.8 Management of Technical Vulnerabilities"),
    (["hr security policy", "people security policy", "screening"], "6.1 Screening"),
    (["physical security policy", "physical entry", "physical perimeter"], "7.1 Physical Security Perimeters"),
    # Checked BEFORE Capacity Management below: a bare "monitoring" mention should
    # default to Monitoring Activities (8.16), not be swallowed by Capacity
    # Management, which previously had no dedicated competing entry at all.
    (["security monitoring", "log monitoring", "siem", "monitoring activities", "monitoring"], "8.16 Monitoring Activities"),
    (["cpu", "memory", "disk", "utilization", "capacity", "cloudwatch"], "8.6 Capacity Management"),
    (["log archival", "log archived", "archiv", "retention", "records"], "5.33 Protection of Records"),
    (["backup", "recovery", "restore"], "8.13 Information Backup"),
    (["incident", "response", "breach"], "5.24 Information Security Incident Management Planning and Preparation"),
    (["encryption", "tls", "ssl", "cipher"], "8.24 Use of Cryptography"),
    (["password", "credential", "secret"], "5.17 Authentication Information"),
    (["firewall", "network", "traffic"], "8.20 Networks Security"),
    (["gdpr", "pii", "personal data", "privacy"], "5.34 Privacy and Protection of Personally Identifiable Information (Pii)"),
]


def _resolve_control_by_direct_map(text: str, use_cases: List[Dict]) -> Optional[Dict]:
    """Fast O(n) keyword-map lookup before falling back to USE_CASES search."""
    text_norm = _normalize(text)
    for keywords, target_use_case in _DIRECT_KEYWORD_CONTROL_MAP:
        if any(kw in text_norm for kw in keywords):
            # Find the matching USE_CASE entry
            target_norm = _normalize(target_use_case)
            for uc in use_cases:
                if _normalize(uc.get("use_case", "")) == target_norm:
                    return uc
    return None



# ── Known ISO 27001 & VAPT control short-IDs (matches 5.15, 8.17, VAPT-1 .. VAPT-15)
_CONTROL_ID_RE = re.compile(
    r'\b(VAPT\s*-?\s*\d{1,2}|\d{1,2}\.\d{1,2}(?:\.\d{1,2})?)\b',
    re.IGNORECASE
)


def _normalize(text: str) -> str:
    """Lowercase and strip punctuation for fuzzy matching."""
    return re.sub(r'[^a-z0-9\s]', ' ', str(text or "").lower()).strip()


def _load_use_cases() -> List[Dict]:
    """Load USE_CASES from controls_data safely."""
    try:
        from src.core.controls_data import USE_CASES
        return USE_CASES
    except ImportError:
        return []


def _resolve_control_by_id(text: str, use_cases: List[Dict]) -> Optional[Dict]:
    """Step 1: Extract control ID directly from text (e.g., '8.16', '5.15', 'VAPT-1', 'ISO 8.17')."""
    if not text:
        return None
    matches = _CONTROL_ID_RE.findall(str(text))
    for m in matches:
        m_norm = re.sub(r'vapt\s*-?\s*', 'VAPT-', m, flags=re.IGNORECASE).strip().upper()
        for uc in use_cases:
            uc_id = str(uc.get("use_case", "")).split(" ")[0].upper()
            if uc_id == m_norm or uc_id == m.upper():
                return uc
    return None




def _resolve_control_by_name(text: str, use_cases: List[Dict]) -> Optional[Dict]:
    """Step 2: Match control by name keywords from USE_CASES labels."""
    norm = _normalize(text)
    if not norm:
        return None

    words = [w for w in norm.split() if len(w) > 2]  # Filter tiny stop words
    if not words:
        return None

    best_uc = None
    best_score = 0

    for uc in use_cases:
        label = _normalize(uc.get("label", "") + " " + uc.get("use_case", ""))
        l_words = set(label.split())
        overlap = len(set(words) & l_words)
        if overlap > best_score:
            best_score = overlap
            best_uc = uc

    # If query is short (1-2 meaningful words like 'Capacity' or 'Screening'), require at least 1 match.
    # Otherwise require at least 2 matches.
    min_required = 1 if len(words) <= 2 else 2
    return best_uc if best_score >= min_required else None


def _resolve_control_by_embedding(text: str, use_cases: List[Dict]) -> Optional[Dict]:
    """Step 3: Cosine similarity against USE_CASES descriptions using cached embeddings."""
    try:
        import numpy as np
        import requests

        # Use Ollama embedding model
        ollama_url = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
        if not ollama_url.startswith("http"):
            ollama_url = f"http://{ollama_url}"

        embed_model = os.environ.get("EMBED_MODEL", "nomic-embed-text")

        def get_embedding(t: str):
            try:
                resp = requests.post(
                    f"{ollama_url}/api/embeddings",
                    json={"model": embed_model, "prompt": t},
                    timeout=60

                )
                if resp.status_code == 200:
                    return np.array(resp.json().get("embedding", []), dtype=np.float32)
            except Exception:
                pass
            return None

        q_vec = get_embedding(text)
        if q_vec is None or len(q_vec) == 0:
            return None

        best_uc = None
        best_sim = -1.0

        for uc in use_cases:
            desc = f"{uc.get('use_case', '')} {uc.get('label', '')} {uc.get('prompt_hint', '')}"
            uc_vec = get_embedding(desc)
            if uc_vec is None or len(uc_vec) == 0:
                continue
            # Cosine similarity
            denom = (np.linalg.norm(q_vec) * np.linalg.norm(uc_vec))
            if denom == 0:
                continue
            sim = float(np.dot(q_vec, uc_vec) / denom)
            if sim > best_sim:
                best_sim = sim
                best_uc = uc

        return best_uc if best_sim > 0.5 else None

    except Exception as e:
        print(f"[EXCEL SCOPING] Embedding resolution failed: {e}", flush=True)
        return None


def _resolve_control(text: str, use_cases: List[Dict]) -> Dict:
    """
    Resolve ISO control from question/control-name text using 4 fallback steps.
    Returns a dict with control_id, control_label, expected_evidence, prompt_hint, severity.
    Falls back to a generic unknown control if all steps fail.
    """
    uc = (
        _resolve_control_by_id(text, use_cases) or
        _resolve_control_by_direct_map(text, use_cases) or   # Fast keyword map
        _resolve_control_by_name(text, use_cases) or
        _resolve_control_by_embedding(text, use_cases)
    )

    if uc:
        use_case_str = str(uc.get("use_case", ""))
        parts = use_case_str.split(" ", 1)
        ctrl_id = parts[0] if parts else "UNKNOWN"
        return {
            "control_id":        ctrl_id,
            "control_label":     use_case_str,
            "expected_evidence": str(uc.get("expected", "")),
            "prompt_hint":       str(uc.get("prompt_hint", "")),
            "severity":          str(uc.get("severity", "MEDIUM")),
        }

    # Fallback: unknown control
    return {
        "control_id":        "UNKNOWN",
        "control_label":     str(text).strip(),
        "expected_evidence": "",
        "prompt_hint":       f"Evaluate the provided document against: {text}",
        "severity":          "MEDIUM",
    }


def _detect_file_columns(header_row: list) -> List[int]:
    """
    Auto-detect which column indices contain file references based on header keywords.
    Excludes columns that are clearly FILE TYPE / FORMAT columns (e.g. 'File type', 'Format').
    Returns a list of column indices (0-based).
    """
    file_col_indices = []
    for idx, cell in enumerate(header_row):
        cell_norm = _normalize(str(cell) if cell is not None else "")
        has_file_kw = any(kw in cell_norm for kw in _FILE_COL_KEYWORDS)
        has_type_kw = any(kw in cell_norm for kw in _FILE_TYPE_EXCLUSION_KEYWORDS)
        # Include only if it has a file keyword AND does NOT have a type/format keyword
        if has_file_kw and not has_type_kw:
            file_col_indices.append(idx)
    return file_col_indices


def _get_file_column_roles(header_row: list, file_cols: List[int]) -> Dict[int, str]:
    """
    Classifies each detected file column as 'policy', 'evidence', or 'generic' based
    on its header text (e.g. 'Policy (source-grounded)' -> 'policy', 'File name' ->
    'generic'). Lets downstream code tell the LLM which locked file(s) the auditor
    intended as policy proof vs operational evidence proof, instead of locking both
    into one undifferentiated blob and making the LLM re-derive the split blind.
    """
    roles = {}
    for idx in file_cols:
        cell_norm = _normalize(str(header_row[idx]) if idx < len(header_row) else "")
        if "policy" in cell_norm:
            roles[idx] = "policy"
        elif "evidence" in cell_norm:
            roles[idx] = "evidence"
        else:
            roles[idx] = "generic"
    return roles


_ROW_NUMBER_HEADER_LABELS = {"s no", "sno", "sl no", "sl", "no", "sr no", "srno", "#", "row", "row no", "index", ""}


def _detect_question_column(header_row: list) -> int:
    """
    Auto-detect which column holds the audit check question/control name.
    Falls back to column index 1 (second column) if none found.
    """
    question_keywords = {
        "audit", "check", "question", "control", "policy", "observation",
        "item", "objective", "requirement", "whether", "sl", "no"
    }
    for idx, cell in enumerate(header_row):
        cell_norm = _normalize(str(cell) if cell is not None else "")
        # Column 0 is often S.No / row number -- skip ONLY if its header text
        # specifically looks like a row-index label. A real question column that
        # happens to be first (e.g. "Audit check" as literal column 0, which some
        # real checklists use with no separate S.No column) must NOT be skipped --
        # a blanket "always skip column 0" previously caused column detection to
        # fail entirely on that layout, matching nothing and silently defaulting
        # to the wrong column with zero evidence files attached to any control.
        if idx == 0 and cell_norm in _ROW_NUMBER_HEADER_LABELS:
            continue
        for kw in question_keywords:
            if kw in cell_norm:
                return idx
    return 1  # Default: second column


def _detect_supplementary_name_column(header_row: list, question_col: int) -> Optional[int]:
    """
    Some checklists split control identification across two columns, e.g. a short
    "Control" ID column plus a separate "Control Name" column. Detects that second
    column so its text can be combined with the primary question column -- this
    matters when a row has a blank Control ID but a filled Control Name (or vice
    versa): without combining them, a row with the primary column blank looks like
    an empty row and gets silently dropped, even though the other column has
    everything needed to resolve the control.
    """
    for idx, cell in enumerate(header_row):
        if idx == question_col:
            continue
        cell_norm = _normalize(str(cell) if cell is not None else "")
        if "name" in cell_norm and ("control" in cell_norm or "audit" in cell_norm or "check" in cell_norm):
            return idx
    return None


def parse_excel_scoping_checklist(
    file_path: str,
    sheet_name: str = None,
    uploaded_filenames: List[str] = None
) -> List[Dict]:
    """
    Parse an Excel scoping checklist and return a list of checklist items.

    Parameters
    ----------
    file_path : str
        Absolute path to the .xlsx file.
    sheet_name : str, optional
        Sheet to read. If None, tries common names then falls back to first sheet.
    uploaded_filenames : list[str], optional
        List of filenames already uploaded to the audit session.
        Used to fuzzy-match Excel file references to actual uploaded files.

    Returns
    -------
    list[dict]
        Each item:
        {
            "row_index":        int,      # 1-based row number
            "question":         str,      # Audit check question / control name
            "files":            list[str],# Locked filenames for this item
            "control_id":       str,      # e.g. "8.17"
            "control_label":    str,      # e.g. "8.17 Clock Synchronization"
            "expected_evidence":str,
            "prompt_hint":      str,
            "severity":         str,
        }
    """
    try:
        import openpyxl
    except ImportError:
        raise ImportError("openpyxl is required: pip install openpyxl")

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Excel scoping file not found: {file_path}")

    wb = openpyxl.load_workbook(file_path, read_only=True, data_only=True)
    try:
        # ── Determine which sheet to read ─────────────────────────────────────────
        preferred_names = ["Audit Check", "Scoping", "Checklist", "Controls",
                           "Sheet1", "Sheet 1", "Data"]
        target_sheet = None

        if sheet_name and sheet_name in wb.sheetnames:
            target_sheet = wb[sheet_name]
        else:
            for name in preferred_names:
                if name in wb.sheetnames:
                    target_sheet = wb[name]
                    break
            if target_sheet is None:
                target_sheet = wb[wb.sheetnames[0]]

        rows = list(target_sheet.iter_rows(values_only=True))
        if not rows:
            return []

        # ── Detect header row (first non-empty row) ────────────────────────────────
        header_row_idx = 0
        for i, row in enumerate(rows):
            if any(cell is not None and str(cell).strip() for cell in row):
                header_row_idx = i
                break

        header_row = [str(c).strip() if c is not None else "" for c in rows[header_row_idx]]

        # ── Auto-detect columns ────────────────────────────────────────────────────
        question_col = _detect_question_column(header_row)
        name_col = _detect_supplementary_name_column(header_row, question_col)
        file_cols = _detect_file_columns(header_row)

        # A column cannot be BOTH the question column and a file column.
        # This happens when the header is just "Policy Name" (matches both sets of keywords).
        # In that case, treat it as question-only (no file columns).
        file_cols = [c for c in file_cols if c != question_col and c != name_col]
        file_col_roles = _get_file_column_roles(header_row, file_cols)

        print(f"[EXCEL PARSER] Sheet: '{target_sheet.title}' | "
              f"Question col: {question_col} ('{header_row[question_col]}') | "
              f"Name col: {name_col} ({header_row[name_col] if name_col is not None else None}) | "
              f"File cols: {file_cols} ({[header_row[c] for c in file_cols]}) | "
              f"Roles: {file_col_roles}",
              flush=True)

        use_cases = _load_use_cases()
        items = []

        # ── Iterate data rows ──────────────────────────────────────────────────────
        for row_idx, row in enumerate(rows[header_row_idx + 1:], start=header_row_idx + 2):
            # Skip completely empty rows
            if not any(c is not None and str(c).strip() for c in row):
                continue

            # Extract question text -- combine the primary column with the
            # supplementary name column (if any) so a row is still resolvable
            # and non-empty when only one of the two is filled in (e.g. a
            # blank Control ID but a filled Control Name, or vice versa).
            q_cell = row[question_col] if question_col < len(row) else None
            q_text = str(q_cell).strip() if q_cell is not None else ""
            name_text = ""
            if name_col is not None and name_col < len(row) and row[name_col] is not None:
                name_text = str(row[name_col]).strip()
            resolution_text = " ".join(t for t in [q_text, name_text] if t)
            question = name_text or q_text  # prefer the more descriptive text for display

            # Skip header-like rows (e.g., "Audit check" appearing mid-sheet)
            if not resolution_text or _normalize(resolution_text) in {
                "audit check", "question", "control", "sl no", "s.no", "sno",
                "control control name", "control name"
            }:
                continue

            # Extract filenames from all detected file columns, split by the
            # column's role (policy/evidence/generic) so the split can be
            # preserved downstream instead of collapsing into one blob.
            raw_files, raw_policy_files, raw_evidence_files = [], [], []
            for fc in file_cols:
                if fc < len(row) and row[fc] is not None:
                    val = str(row[fc]).strip()
                    if val and val.lower() not in {"file name", "file", "filename", "n/a", "na", "-", ""}:
                        raw_files.append(val)
                        role = file_col_roles.get(fc, "generic")
                        if role == "policy":
                            raw_policy_files.append(val)
                        elif role == "evidence":
                            raw_evidence_files.append(val)

            # Fuzzy-match raw file names to actually uploaded files
            matched_files = _match_filenames(raw_files, uploaded_filenames or [])
            matched_policy_files = _match_filenames(raw_policy_files, uploaded_filenames or [])
            matched_evidence_files = _match_filenames(raw_evidence_files, uploaded_filenames or [])

            # Resolve ISO control from the combined text (ID regex needs the raw
            # "5.15"-style value if present; name-keyword/embedding fallback needs
            # the descriptive text if the ID is blank) -- either source alone may
            # be missing for a given row, so both are passed together.
            ctrl_info = _resolve_control(resolution_text, use_cases)

            items.append({
                "row_index":         row_idx,
                "question":          question,
                "files":             matched_files,
                # Role-split view of the same files, when the sheet has separately
                # named Policy/Evidence columns -- both empty for a generic single
                # "File name" column, since there's no column-level signal to split.
                "policy_files":      matched_policy_files,
                "evidence_files":    matched_evidence_files,
                "raw_file_refs":     raw_files,   # original Excel values (for debugging)
                "control_id":        ctrl_info["control_id"],
                "control_label":     ctrl_info["control_label"],
                "expected_evidence": ctrl_info["expected_evidence"],
                "prompt_hint":       ctrl_info["prompt_hint"],
                "severity":          ctrl_info["severity"],
            })

        print(f"[EXCEL PARSER] Parsed {len(items)} checklist items.", flush=True)
        return items
    finally:
        try:
            wb.close()
        except Exception:
            pass



_FILENAME_EXT_RE = re.compile(r'\.(docx?|pdf|xlsx?|csv|pptx?|txt|png|jpe?g|zip)\b', re.IGNORECASE)
_CITATION_SPLIT_RE = re.compile(r'\s*;\s*|\n')
_CITATION_LEADING_TAG_RE = re.compile(r'^\[[^\]]+\]\s*')


def _looks_like_filename_reference(segment: str) -> bool:
    """
    A segment is only treated as a candidate file citation (matched against
    uploads, or kept as an unresolved reference) if it's filename-shaped -- has
    a recognized extension, or is short enough to plausibly be a citation like
    "Some Policy V17.0 -- p.2." rather than a full prose sentence describing
    what a policy says. Long narrative text with no extension is never kept as
    a fake "locked filename" -- that silently breaks retrieval later, since no
    real file will ever match it.
    """
    if _FILENAME_EXT_RE.search(segment):
        return True
    return len(segment) <= 80


def _split_citation_segments(raw_ref: str) -> List[str]:
    """
    A single cell may cite multiple files at once (e.g. "A.docx; B.pdf -- p.2."),
    or bracket-tag a citation (e.g. "[Published] Some Policy.docx"). Splits on
    ';' / newlines and strips leading bracket tags so each file gets matched
    independently instead of the whole cell being treated as one reference.
    """
    parts = [p.strip() for p in _CITATION_SPLIT_RE.split(raw_ref) if p.strip()]
    cleaned = [_CITATION_LEADING_TAG_RE.sub('', p).strip() for p in parts]
    cleaned = [p for p in cleaned if p]
    return cleaned or [raw_ref]


def _match_filenames(
    raw_refs: List[str],
    uploaded_filenames: List[str]
) -> List[str]:
    """
    Fuzzy-match raw Excel file references to actual uploaded filenames.

    Each raw reference may cite multiple files in one cell, or be pure
    narrative text with no file reference at all -- both are handled by first
    splitting into citation segments (see _split_citation_segments), then
    matching each segment independently.

    Strategy per segment:
    1. Exact match (case-insensitive, extension-stripped)
    2. Partial match -- checks BOTH the full uploaded filename and its
       extension-stripped stem as a substring, since citation text doesn't
       always repeat the file extension (e.g. "...Policy V17.0 -- p.2." cites
       "...Policy V17.0.pdf" without ever writing ".pdf")
    3. If nothing matches, keep the segment only if it's filename-shaped (see
       _looks_like_filename_reference) so the auditor can see an expected file
       that hasn't been uploaded yet. Pure narrative segments are dropped
       instead of being kept as a fake filename reference.
    """
    def _resolve_segment(seg: str) -> Optional[str]:
        seg_norm = _normalize(seg)

        # Step 1: exact match (extension-stripped)
        for upl in uploaded_filenames:
            upl_stem_norm = _normalize(os.path.splitext(upl)[0])
            if seg_norm == upl_stem_norm or seg_norm == _normalize(upl):
                return upl

        # Step 2: partial match -- try both the full filename and its
        # extension-stripped stem, since citations often omit the extension
        best_match, best_len = None, 0
        for upl in uploaded_filenames:
            for candidate in (_normalize(upl), _normalize(os.path.splitext(upl)[0])):
                if not candidate:
                    continue
                if candidate in seg_norm and len(candidate) > best_len:
                    best_len, best_match = len(candidate), upl
                elif seg_norm in candidate and len(seg_norm) > best_len:
                    best_len, best_match = len(seg_norm), upl
        return best_match

    matched = []
    for ref in raw_refs:
        for seg in _split_citation_segments(ref):
            resolved = _resolve_segment(seg) if uploaded_filenames else None
            if resolved:
                matched.append(resolved)
            elif _looks_like_filename_reference(seg):
                # Step 3: keep as an unresolved-but-plausible reference
                matched.append(seg)

    # Deduplicate while preserving order -- the same file can legitimately be
    # cited twice (e.g. once in the Policy column, once in Evidence)
    seen = set()
    result = []
    for f in matched:
        if f not in seen:
            seen.add(f)
            result.append(f)
    return result


def get_locked_filenames_for_control(
    checklist_items: List[Dict],
    control_id: str
) -> List[str]:
    """
    Returns all locked filenames for a given control_id across all checklist items.
    Useful when multiple checklist rows map to the same control (e.g., two NTP rows → 8.17).
    """
    files = []
    for item in checklist_items:
        if item.get("control_id") == control_id:
            files.extend(item.get("files", []))
    # Deduplicate while preserving order
    seen = set()
    result = []
    for f in files:
        if f not in seen:
            seen.add(f)
            result.append(f)
    return result
