# -*- coding: utf-8 -*-
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class Finding:
    title: str
    severity: str                         # CRITICAL, HIGH, MEDIUM, LOW, INFO
    severity_score: Optional[float] = None # Optional CVSS score float
    cvss_vector: Optional[str] = None     # Optional CVSS vector string
    cve_list: List[str] = field(default_factory=list)
    target: str = ""                      # Host IP / Port / Domain
    description: str = ""                 # Synopsis / Description
    remediation: str = ""                 # Solution / Recommended fix
    evidence: str = ""                    # Raw plugin output text / proof
    plugin_id: str = ""                   # Scanner plugin ID
    source_tool: str = ""                 # Nessus, Nmap, Burp, Qualys, etc.
    control_id: str = ""                  # Mapped centrally by ControlMapper

    def __post_init__(self):
        # Normalize severity to uppercase standard string
        sev_upper = str(self.severity or "INFO").strip().upper()
        if "CRIT" in sev_upper:
            self.severity = "CRITICAL"
        elif "HIGH" in sev_upper:
            self.severity = "HIGH"
        elif "MED" in sev_upper:
            self.severity = "MEDIUM"
        elif "LOW" in sev_upper:
            self.severity = "LOW"
        else:
            self.severity = "INFO"

    def dedup_key(self) -> str:
        """
        Calculates deduplication key:
        1. Primary: CVE list if present (e.g. CVE:CVE-2025-6218)
        2. Secondary (Same Tool): source_tool + plugin_id (e.g. nessus:242073)
        3. Tertiary (Cross Tool / Non-CVE): source_tool + normalized title
        """
        if self.cve_list:
            clean_cves = sorted(set(c.strip().upper() for c in self.cve_list if c and c.strip()))
            if clean_cves:
                return f"CVE:{':'.join(clean_cves)}"
        
        tool = (self.source_tool or "generic").lower().strip()
        if self.plugin_id and self.plugin_id.strip():
            return f"{tool}:{self.plugin_id.strip()}"
        
        clean_title = (self.title or "unnamed").lower().strip()
        return f"{tool}:{clean_title}"
