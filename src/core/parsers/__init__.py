# -*- coding: utf-8 -*-
"""
Multi-Tool Vulnerability Ingestion Engine (Nessus, Nmap, BurpSuite, Qualys, Trivy, CSV, HTML)
"""
from typing import List, Tuple, Any
from .finding_schema import Finding
from .base_parser import BaseParser, is_image_file
from .control_mapper import map_finding_to_control, map_findings_list, map_pqc_findings_list
from .nessus_parser import NessusParser
from .nmap_parser import NmapParser
from .burp_parser import BurpParser
from .qualys_parser import QualysParser
from .trivy_parser import TrivyParser
from .pqc_parser import PQCParser, pqc_extract_text, _PQC_BINARY_EXTENSIONS

ALL_PARSERS = [
    NessusParser(),
    NmapParser(),
    BurpParser(),
    QualysParser(),
    TrivyParser(),
    # PQCParser goes LAST -- its can_parse() is a weak-signal (2+ keyword) check
    # like Nessus's own fallback path, so it must never steal a file that a more
    # specific structural-signature parser above would have claimed.
    PQCParser(),
]

def parse_tool_file(filename: str, content: str) -> Tuple[List[Finding], Any]:
    """
    Auto-detects file type and dispatches to the appropriate security tool parser.

    Detection strategy (in order):
    1. PDF / DOCX / image files with binary extensions are tried through ALL_PARSERS
       FIRST (PQCParser.can_parse() returns True for these extensions immediately).
       If PQCParser claims the file, it extracts text internally and scans it.
    2. Image files NOT claimed by PQCParser are returned early with [] -- they are
       visual PoC evidence screenshots with no XML/HTML scanner structure.
    3. All other files are tried against ALL_PARSERS using content-signature detection.
    4. If no parser claims the file, NessusParser handles it as a fallback.

    Returns (actionable_findings, extra_info/inventory).
    """
    # ── Stage 1: Binary document fast-path (PDF / DOCX / images) ─────────────
    # Route to PQCParser FIRST for PQC-relevant binary formats. PQCParser.can_parse()
    # accepts binary extensions without needing text content. If PQCParser fires and
    # finds PQC findings, return them directly. Otherwise fall through to VAPT path.
    ext_lower = __import__('os').path.splitext(filename.lower())[1]
    if ext_lower in _PQC_BINARY_EXTENSIONS:
        pqc_p = ALL_PARSERS[-1]  # PQCParser is always last
        if pqc_p.can_parse(filename, content):
            res = pqc_p.parse(filename, content)
            findings, extra = res if isinstance(res, tuple) else (res, None)
            if findings:
                map_pqc_findings_list(findings)
                return findings, extra
        # PQCParser got nothing from this binary -- if it's an image, the
        # VAPT path handles it (OCR in bg_worker). If PDF/DOCX with no PQC
        # content, fall through to VAPT parsers below.
        if is_image_file(filename):
            # Images with no PQC content: route to caller for VAPT OCR.
            return [], None

    # ── Stage 2: Image fast-path for VAPT (non-PQC images) ───────────────────
    # Images with no binary-extension claim above are visual PoC screenshots.
    if is_image_file(filename):
        return [], None

    # ── Stage 3: Content-signature parser dispatch (text-based files) ────────
    for p in ALL_PARSERS:
        if p.can_parse(filename, content):
            res = p.parse(filename, content)
            findings, extra = res if isinstance(res, tuple) else (res, None)
            if not findings:
                print(
                    f"[VAPT PARSER WARNING] '{p.__class__.__name__}' recognized '{filename}' "
                    f"but extracted 0 findings. If this file genuinely contains vulnerabilities, "
                    f"the parser may not support this export's exact format/columns and needs review.",
                    flush=True
                )
            if findings:
                # PQCParser findings use the PQC-specific mapper (CIA, risk score,
                # per-algorithm remediation, OEM readiness, business priority).
                # All other parsers (Nessus, Burp, Nmap, Qualys, Trivy) use the
                # VAPT mapper. This is the gate that keeps the two pipelines separate.
                if p.__class__.__name__ == "PQCParser":
                    map_pqc_findings_list(findings)
                else:
                    map_findings_list(findings)
                return findings, extra

    # ── Stage 3: Fallback (general HTML/XML/PDF via NessusParser & BurpParser) ──
    findings, extra = NessusParser().parse(filename, content)
    if not findings:
        res_burp = BurpParser().parse(filename, content)
        findings, extra = res_burp if isinstance(res_burp, tuple) else (res_burp, None)
    if findings:
        map_findings_list(findings)
    return findings, extra

__all__ = [
    "Finding", "BaseParser", "is_image_file", "map_finding_to_control", "map_findings_list",
    "NessusParser", "NmapParser", "BurpParser", "QualysParser", "TrivyParser", "PQCParser",
    "parse_tool_file", "pqc_extract_text",
]
