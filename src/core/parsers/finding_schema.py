# -*- coding: utf-8 -*-
from dataclasses import dataclass, field
from typing import List, Optional

def _calculate_cvss_score(vector_str: str) -> Optional[float]:
    """
    Standards-based CVSS v2 & v3 vector calculation using the `cvss` library.
    Returns the base score float (e.g. 9.8) or None if parsing fails.
    Falls back to regex-based heuristic if the `cvss` library is not installed.
    Runs 100% offline — no network calls.
    """
    if not vector_str or not isinstance(vector_str, str):
        return None

    clean = vector_str.strip()

    # ── Try `cvss` library (exact standards-based calculation) ──
    try:
        if clean.upper().startswith("CVSS:3"):
            from cvss import CVSS3
            c = CVSS3(clean)
            return round(c.base_score, 1)
        elif clean.upper().startswith("CVSS:4"):
            # CVSS v4 support (if cvss library supports it)
            try:
                from cvss import CVSS4
                c = CVSS4(clean)
                return round(c.base_score, 1)
            except (ImportError, Exception):
                pass
        else:
            # Assume CVSS v2 format (AV:N/AC:L/Au:N/C:P/I:P/A:P)
            from cvss import CVSS2
            # CVSS2 expects the vector without prefix
            c = CVSS2(clean)
            return round(c.base_score, 1)
    except ImportError:
        pass  # cvss library not installed — fall through to regex fallback
    except Exception:
        pass  # invalid vector string — fall through to regex fallback

    # ── Regex fallback: extract base score from well-known metric combinations ──
    try:
        import re
        # CVSS v3.x heuristic scoring from vector components
        if "AV:" in clean and "AC:" in clean:
            av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
            ac_map = {"L": 0.77, "H": 0.44}
            # Extract AV and AC values
            av_match = re.search(r'AV:([NALP])', clean, re.IGNORECASE)
            ac_match = re.search(r'AC:([LH])', clean, re.IGNORECASE)
            if av_match and ac_match:
                av = av_map.get(av_match.group(1).upper(), 0.55)
                ac = ac_map.get(ac_match.group(1).upper(), 0.44)
                # Rough base score estimation
                raw = (av * ac) * 10
                return round(min(max(raw, 0.0), 10.0), 1)
    except Exception:
        pass

    return None


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
    confidence: Optional[str] = "Certain" # Certain, Firm, Tentative
    source_tool: str = ""                 # Nessus, Nmap, Burp, Qualys, etc.
    control_id: str = ""                  # Mapped centrally by ControlMapper
    # ── New VAPT Enhancement Fields ──
    category: str = ""                    # Risk Category (Access Control, Injection, etc.)
    cia_impact: str = ""                  # C:HIGH | I:LOW | A:NONE
    is_pii_exposed: bool = False          # PII / sensitive data exposure flag
    remediation_actionable: str = ""      # Developer-actionable mitigation steps

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

        # Auto-calculate CVSS score from vector if score is missing but vector is present
        if self.cvss_vector and self.severity_score is None:
            calculated = _calculate_cvss_score(self.cvss_vector)
            if calculated is not None:
                self.severity_score = calculated

    def dedup_key(self) -> str:
        """
        Calculates deduplication key:
        1. Primary: CVE list if present (e.g. CVE:CVE-2025-6218)
        2. Secondary (Same Tool): source_tool + plugin_id (e.g. nessus:242073)
        3. Tertiary (Cross Tool / Non-CVE): source_tool + normalized title

        Capped at 480 chars (the DB column is VARCHAR(500), src/db/database.py's
        Finding.dedup_key) -- a finding tied to dozens of CVEs (common for EOL/
        outdated-component findings) or a long scanner-generated title could
        otherwise produce an unbounded string and crash the DB insert with
        StringDataRightTruncation on a real scan. Truncation is applied
        consistently on both write and the pre-seed read of existing keys, so
        exact-match comparison still works correctly.
        """
        if self.cve_list:
            clean_cves = sorted(set(c.strip().upper() for c in self.cve_list if c and c.strip()))
            if clean_cves:
                return f"CVE:{':'.join(clean_cves)}"[:480]

        tool = (self.source_tool or "generic").lower().strip()
        if self.plugin_id and self.plugin_id.strip():
            return f"{tool}:{self.plugin_id.strip()}"[:480]

        clean_title = (self.title or "unnamed").lower().strip()
        return f"{tool}:{clean_title}"[:480]

    def to_dict(self) -> dict:
        from dataclasses import asdict
        d = asdict(self)
        d["finding"] = self.title
        d["score"] = self.severity_score
        d["evidence_snippet"] = self.evidence
        return d
