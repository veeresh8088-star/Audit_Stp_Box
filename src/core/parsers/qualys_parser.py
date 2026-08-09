# -*- coding: utf-8 -*-
import csv
import io
import re
from typing import List, Tuple, Optional
from bs4 import BeautifulSoup
from .base_parser import BaseParser
from .finding_schema import Finding
from .control_mapper import map_findings_list

# Qualys' standard numeric severity scale (1-5). Different report templates label
# these differently (Urgent/Critical/Serious/Medium/Minimal etc.) but the 1-5
# numeric scale itself is stable across Qualys deployments.
QUALYS_SEVERITY_MAP = {
    "5": "CRITICAL",
    "4": "HIGH",
    "3": "MEDIUM",
    "2": "LOW",
    "1": "INFO",
}

# CSV export column names vary slightly between Qualys report templates
# (custom templates can rename/reorder columns) -- match case-insensitively
# against known aliases rather than a single fixed header name.
COLUMN_ALIASES = {
    "qid": ["qid"],
    "title": ["title", "vulnerability title"],
    "severity": ["severity"],
    "cve": ["cve id", "cve", "cve ids"],
    "solution": ["solution", "remediation"],
    "threat": ["threat", "impact", "description", "vulnerability description"],
    "ip": ["ip", "ip address"],
    "dns": ["dns", "fqdn", "netbios"],
    "port": ["port"],
    "protocol": ["protocol"],
    "cvss": ["cvss3.1", "cvss3", "cvss", "cvss base", "cvss3.1 base"],
}


def _find_col(headers_norm: dict, key: str) -> Optional[str]:
    for alias in COLUMN_ALIASES[key]:
        if alias in headers_norm:
            return headers_norm[alias]
    return None


class QualysParser(BaseParser):
    """Parses Qualys / OpenVAS vulnerability scan exports.
    Primary support: Qualys CSV export (the most common real-world export format).
    Secondary, best-effort support: Qualys/OpenVAS XML exports.
    NOTE: not yet verified against a real Qualys/OpenVAS export file -- built against
    the documented standard CSV column set and common XML report structures. If a
    real export doesn't parse, this needs adjusting against an actual sample file.
    """

    def can_parse(self, filename: str, content: str) -> bool:
        if not content:
            return False
        fn_lower = filename.lower()
        return "qualys" in fn_lower or "openvas" in fn_lower or "qid" in content[:2000].lower()

    def parse(self, filename: str, content: str) -> Tuple[List[Finding], None]:
        stripped = content.lstrip()
        if stripped.startswith("<"):
            findings = self._parse_xml(content)
        else:
            findings = self._parse_csv(content)

        map_findings_list(findings)
        if not findings:
            print(f"[QUALYS PARSER WARNING] Recognized '{filename}' as a Qualys/OpenVAS file but extracted "
                  f"0 findings -- format may not match the supported CSV/XML structure. Needs review.", flush=True)
        else:
            print(f"[QUALYS PARSER] Extracted {len(findings)} finding(s) from '{filename}'.", flush=True)
        return findings, None

    # ── CSV export (primary path) ──────────────────────────────────────────
    def _parse_csv(self, content: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            reader = csv.DictReader(io.StringIO(content))
            if not reader.fieldnames:
                return []
            headers_norm = {h.strip().lower(): h for h in reader.fieldnames if h}

            col_title = _find_col(headers_norm, "title")
            col_sev = _find_col(headers_norm, "severity")
            col_cve = _find_col(headers_norm, "cve")
            col_solution = _find_col(headers_norm, "solution")
            col_threat = _find_col(headers_norm, "threat")
            col_ip = _find_col(headers_norm, "ip")
            col_dns = _find_col(headers_norm, "dns")
            col_port = _find_col(headers_norm, "port")
            col_qid = _find_col(headers_norm, "qid")
            col_cvss = _find_col(headers_norm, "cvss")

            if not col_title and not col_qid:
                # Doesn't look like a Qualys CSV export at all
                return []

            for row in reader:
                title = (row.get(col_title) or "").strip() if col_title else ""
                qid = (row.get(col_qid) or "").strip() if col_qid else ""
                if not title and not qid:
                    continue
                if not title:
                    title = f"Qualys QID {qid}"

                raw_sev = (row.get(col_sev) or "").strip() if col_sev else ""
                sev_digits = re.sub(r"[^0-9]", "", raw_sev)
                severity = QUALYS_SEVERITY_MAP.get(sev_digits, raw_sev or "INFO")

                cve_raw = (row.get(col_cve) or "").strip() if col_cve else ""
                cve_list = [c.strip() for c in re.split(r"[,;\s]+", cve_raw) if c.strip().upper().startswith("CVE-")]

                ip = (row.get(col_ip) or "").strip() if col_ip else ""
                dns = (row.get(col_dns) or "").strip() if col_dns else ""
                port = (row.get(col_port) or "").strip() if col_port else ""
                target = " / ".join(p for p in [ip, dns] if p) or "Unknown Host"
                if port:
                    target = f"{target}:{port}"

                cvss_score = None
                if col_cvss:
                    try:
                        cvss_score = float((row.get(col_cvss) or "").strip())
                    except (ValueError, TypeError):
                        cvss_score = None

                findings.append(Finding(
                    title=title,
                    severity=severity,
                    severity_score=cvss_score,
                    cve_list=cve_list,
                    target=target,
                    description=(row.get(col_threat) or "").strip() if col_threat else title,
                    remediation=(row.get(col_solution) or "").strip() if col_solution else "Apply vendor patch per Qualys solution guidance.",
                    evidence=f"QID {qid}" if qid else "",
                    plugin_id=qid,
                    source_tool="Qualys",
                ))
        except Exception as e:
            print(f"[QUALYS PARSER ERROR] CSV parsing failed: {e}", flush=True)
            return []
        return findings

    # ── XML export (best-effort secondary path — Qualys XML / OpenVAS GMP XML) ──
    def _parse_xml(self, content: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            soup = BeautifulSoup(content, "xml") if BeautifulSoup(content, "html.parser").find() else None
        except Exception:
            soup = None
        if soup is None:
            try:
                soup = BeautifulSoup(content, "html.parser")
            except Exception:
                return []

        # Qualys XML: <VULN><QID>...</QID><TITLE>...</TITLE><SEVERITY>...</SEVERITY>...
        vuln_nodes = soup.find_all(re.compile(r"^vuln$", re.IGNORECASE))
        # OpenVAS GMP XML: <result><name>...</name><severity>...</severity><nvt><cve>...</cve></nvt></result>
        if not vuln_nodes:
            vuln_nodes = soup.find_all(re.compile(r"^result$", re.IGNORECASE))

        for node in vuln_nodes:
            def _text(tag_name):
                t = node.find(re.compile(f"^{tag_name}$", re.IGNORECASE))
                return t.get_text(strip=True) if t else ""

            title = _text("title") or _text("name") or "Qualys/OpenVAS Finding"
            qid = _text("qid")
            raw_sev = _text("severity")
            sev_digits = re.sub(r"[^0-9]", "", raw_sev)
            severity = QUALYS_SEVERITY_MAP.get(sev_digits, raw_sev or "INFO")

            cve_text = _text("cve") or _text("cve_id")
            cve_list = [c.strip() for c in re.split(r"[,;\s]+", cve_text) if c.strip().upper().startswith("CVE-")]

            threat = _text("threat") or _text("description") or _text("diagnosis")
            solution = _text("solution") or _text("recommendation") or "Apply vendor patch per scanner solution guidance."

            ip_node = node.find_previous(re.compile(r"^ip$", re.IGNORECASE))
            target = ip_node.get_text(strip=True) if ip_node else "Unknown Host"

            if not title and not qid and not cve_list:
                continue

            findings.append(Finding(
                title=title,
                severity=severity,
                cve_list=cve_list,
                target=target,
                description=threat or title,
                remediation=solution,
                evidence=f"QID {qid}" if qid else "",
                plugin_id=qid,
                source_tool="Qualys",
            ))
        return findings
