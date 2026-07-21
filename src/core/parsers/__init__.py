# -*- coding: utf-8 -*-
"""
Multi-Tool Vulnerability Ingestion Engine (Nessus, Nmap, BurpSuite, Qualys, Trivy, CSV, HTML)
"""
from typing import List, Tuple, Any
from .finding_schema import Finding
from .base_parser import BaseParser
from .control_mapper import map_finding_to_control
from .nessus_parser import NessusParser
from .nmap_parser import NmapParser
from .burp_parser import BurpParser
from .qualys_parser import QualysParser
from .trivy_parser import TrivyParser

ALL_PARSERS = [
    NessusParser(),
    NmapParser(),
    BurpParser(),
    QualysParser(),
    TrivyParser(),
]

def parse_tool_file(filename: str, content: str) -> Tuple[List[Finding], Any]:
    """
    Auto-detects file type and dispatches to the appropriate security tool parser.
    Returns (actionable_findings, extra_info/inventory).
    """
    for p in ALL_PARSERS:
        if p.can_parse(filename, content):
            res = p.parse(filename, content)
            if isinstance(res, tuple):
                return res
            return res, None
            
    # Default fallback to NessusParser (handles general HTML/XML)
    return NessusParser().parse(filename, content)

__all__ = [
    "Finding", "BaseParser", "map_finding_to_control",
    "NessusParser", "NmapParser", "BurpParser", "QualysParser", "TrivyParser",
    "parse_tool_file"
]
