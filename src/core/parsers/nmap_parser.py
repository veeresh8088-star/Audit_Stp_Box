# -*- coding: utf-8 -*-
import re
from typing import List, Tuple, Dict, Any
from .base_parser import BaseParser
from .finding_schema import Finding
from .control_mapper import map_findings_list

class AssetInventory:
    def __init__(self, target_ip: str = "", open_ports: List[Dict[str, str]] = None):
        self.target_ip = target_ip
        self.open_ports = open_ports or []

# NSE output frequently flags real misconfigurations (weak TLS, unauthenticated services,
# directory listings, default creds) without naming a "*-vuln*" script or citing a CVE.
# These keyword heuristics catch that class of finding.
_RISK_KEYWORDS = [
    (re.compile(r'unauthenticated access permitted', re.IGNORECASE), "HIGH", "Unauthenticated Service Access"),
    (re.compile(r'anonymous (?:login|ftp) (?:allowed|enabled)', re.IGNORECASE), "HIGH", "Anonymous Authentication Allowed"),
    (re.compile(r'weak protocol detected|non-compliant', re.IGNORECASE), "MEDIUM", "Weak/Deprecated Protocol Supported"),
    (re.compile(r'\btlsv?1\.0\b|\bsslv[23]\b', re.IGNORECASE), "MEDIUM", "Weak SSL/TLS Protocol Supported"),
    (re.compile(r'unencrypted connection allowed', re.IGNORECASE), "MEDIUM", "Unencrypted Service Connection Allowed"),
    (re.compile(r'index of /', re.IGNORECASE), "LOW", "Directory Listing Enabled"),
    (re.compile(r'default (?:credentials|password)', re.IGNORECASE), "HIGH", "Default Credentials in Use"),
]

class NmapParser(BaseParser):
    def can_parse(self, filename: str, content: str) -> bool:
        if not content:
            return False
        fn_lower = filename.lower()
        if fn_lower.endswith(".nmap") or fn_lower.endswith(".gnmap"):
            return True
        if "nmap" in fn_lower or "nmap" in content[:2000].lower() or "starting nmap" in content[:2000].lower():
            return True
        return False

    def parse(self, filename: str, content: str) -> Tuple[List[Finding], AssetInventory]:
        content = content.replace('\r\n', '\n')
        findings: List[Finding] = []
        open_ports: List[Dict[str, str]] = []
        target_ip = "Target Host"
        seen_evidence = set()

        m_ip = re.search(r'Nmap scan report for\s+([^\n]+)', content, re.IGNORECASE)
        if m_ip:
            target_ip = m_ip.group(1).strip()

        # Per-port blocks: each port header line through to the next port header (or EOF)
        # so NSE script hits below a port can be attributed to that port/service.
        port_header_re = re.compile(r'^(\d+/(?:tcp|udp))\s+(\w+)\s+([^\n]*)$', re.MULTILINE)
        port_matches = list(port_header_re.finditer(content))

        for pm in port_matches:
            port, state, svc = pm.group(1), pm.group(2), pm.group(3)
            if state.lower() == "open":
                open_ports.append({"port": port, "state": state, "service": svc.strip()})

        def _add_finding(title: str, severity: str, cves: List[str], evidence: str, port_label: str = ""):
            ev_key = evidence.strip()
            if ev_key in seen_evidence:
                return
            seen_evidence.add(ev_key)
            findings.append(Finding(
                title=f"Nmap: {title}" + (f" ({port_label})" if port_label else ""),
                severity=severity,
                cve_list=cves,
                target=target_ip,
                description=f"Nmap NSE script detection on target {target_ip}"
                            f"{(' port ' + port_label) if port_label else ''}.",
                remediation="Investigate service misconfiguration and apply vendor patches/hardening.",
                evidence=ev_key,
                source_tool="Nmap"
            ))

        for idx, pm in enumerate(port_matches):
            port_label = pm.group(1)
            block_start = pm.end()
            block_end = port_matches[idx + 1].start() if idx + 1 < len(port_matches) else len(content)
            block = content[block_start:block_end]

            # 1. Explicit NSE "-vuln" scripts / CVE mentions
            nse_hits = re.findall(r'\|_?([a-zA-Z0-9_-]+-vuln[^\n]*|\bCVE-\d{4}-\d+\b[^\n]*)', block)
            for hit in nse_hits:
                cves = re.findall(r'CVE-\d{4}-\d{4,7}', hit, re.IGNORECASE)
                _add_finding(f"Vuln Script Finding: {hit[:60]}", "HIGH" if cves else "MEDIUM", cves, hit, port_label)

            # 2. Keyword-based misconfiguration detection across NSE script lines in the block
            for line in block.splitlines():
                stripped = line.strip()
                if not stripped.startswith('|'):
                    continue
                for pattern, severity, label in _RISK_KEYWORDS:
                    if pattern.search(stripped):
                        _add_finding(label, severity, [], stripped.lstrip('|_ '), port_label)

        map_findings_list(findings)
        asset_inv = AssetInventory(target_ip=target_ip, open_ports=open_ports)
        return findings, asset_inv
