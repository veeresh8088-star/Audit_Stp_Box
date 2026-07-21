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
        findings: List[Finding] = []
        open_ports: List[Dict[str, str]] = []
        target_ip = "Target Host"

        m_ip = re.search(r'Nmap scan report for\s+([^\n]+)', content, re.IGNORECASE)
        if m_ip:
            target_ip = m_ip.group(1).strip()

        # Parse open ports & services for Appendix Asset Inventory
        port_lines = re.findall(r'(\d+/(?:tcp|udp))\s+(\w+)\s+([^\n]+)', content)
        for port, state, svc in port_lines:
            if state.lower() == "open":
                open_ports.append({"port": port, "state": state, "service": svc.strip()})

        # Parse NSE vulnerability script findings (CVE / Vuln hits)
        nse_hits = re.findall(r'\|_?([a-zA-Z0-9_-]+-vuln[^\n]*|\bCVE-\d{4}-\d+\b[^\n]*)', content)
        for hit in nse_hits:
            cves = re.findall(r'CVE-\d{4}-\d{4,7}', hit, re.IGNORECASE)
            findings.append(Finding(
                title=f"Nmap Vuln Script Finding: {hit[:60]}",
                severity="HIGH" if cves else "MEDIUM",
                cve_list=cves,
                target=target_ip,
                description=f"Nmap NSE script vulnerability detection on target {target_ip}.",
                remediation="Investigate service misconfiguration and apply vendor patches.",
                evidence=hit,
                source_tool="Nmap"
            ))

        map_findings_list(findings)
        asset_inv = AssetInventory(target_ip=target_ip, open_ports=open_ports)
        return findings, asset_inv
