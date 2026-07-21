# -*- coding: utf-8 -*-
import re
from typing import List, Tuple, Any
from bs4 import BeautifulSoup
from .base_parser import BaseParser
from .finding_schema import Finding
from .control_mapper import map_findings_list

class NessusParser(BaseParser):
    def can_parse(self, filename: str, content: str) -> bool:
        if not content:
            return False
        fn_lower = filename.lower()
        if fn_lower.endswith(".nessus"):
            return True
        sample = content[:100000].lower()
        if "nessus" in fn_lower or "nessus" in sample or "risk factor" in sample or "vulnerabilities by plugin" in sample:
            return True
        return False

    def parse(self, filename: str, content: str) -> Tuple[List[Finding], List[Finding]]:
        if not content:
            return [], []

        soup = BeautifulSoup(content, 'html.parser')
        actionable_findings: List[Finding] = []
        info_findings: List[Finding] = []

        for div in soup.find_all('div'):
            txt = div.get_text()
            if 'Risk Factor' in txt and 'Synopsis' in txt and 'Description' in txt:
                # Ensure this is a leaf plugin container div
                if any('Risk Factor' in child.get_text() and 'Synopsis' in child.get_text() for child in div.find_all('div', recursive=False)):
                    continue

                # Header div preceding this body div
                header = div.find_previous_sibling('div')
                h_text = header.get_text().strip() if header else ''
                
                # Extract plugin_id and title
                m_header = re.search(r'(\d+)\s*\(\d+\)\s*-\s*(.+)', h_text)
                plugin_id = m_header.group(1).strip() if m_header else ''
                title = m_header.group(2).strip() if m_header else (h_text or "Nessus Vulnerability Finding")

                # Extract Risk Factor / Severity
                m_rf = re.search(r'Risk Factor\s*\n*\s*(Critical|High|Medium|Low|None|Informational)', txt, re.IGNORECASE)
                raw_sev = m_rf.group(1).strip() if m_rf else "INFO"
                
                # Normalize severity
                if raw_sev.lower() == "none":
                    severity = "INFO"
                else:
                    severity = raw_sev.upper()

                # Extract CVSS Score & Vector
                m_cvss = re.search(r'CVSS v3\.0 Base Score\s*\n*\s*([\d\.]+)', txt)
                score = float(m_cvss.group(1)) if m_cvss else None

                m_vec = re.search(r'\(CVSS:3\.0/([^\)]+)\)', txt)
                cvss_vector = f"CVSS:3.0/{m_vec.group(1)}" if m_vec else None

                # Extract CVEs
                cves = sorted(list(set(re.findall(r'CVE-\d{4}-\d{4,7}', txt, re.IGNORECASE))))

                # Extract Synopsis / Description
                desc = ""
                m_desc = re.search(r'Description\s*\n\s*(.*?)(?=\n\s*(?:See Also|Solution|Risk Factor|Plugin Information|Plugin Output|$))', txt, re.DOTALL)
                if m_desc:
                    desc = m_desc.group(1).strip()

                # Extract Solution / Remediation
                remed = ""
                m_sol = re.search(r'Solution\s*\n\s*(.*?)(?=\n\s*(?:Risk Factor|Plugin Information|Plugin Output|See Also|$))', txt, re.DOTALL)
                if m_sol:
                    remed = m_sol.group(1).strip()

                # Extract Plugin Output & Targets
                evidence = ""
                targets = []
                m_out = re.search(r'Plugin Output\s*\n\s*(.*?)(?=\n\s*(?:Algorithm|Risk Factor|$))', txt, re.DOTALL)
                if m_out:
                    evidence = m_out.group(1).strip()[:1500]
                    # Extract target IP / Host
                    ip_hits = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', evidence)
                    if ip_hits:
                        targets = list(set(ip_hits))

                target_str = ", ".join(targets) if targets else "Scoped Target Systems"

                finding = Finding(
                    title=title,
                    severity=severity,
                    severity_score=score,
                    cvss_vector=cvss_vector,
                    cve_list=cves,
                    target=target_str,
                    description=desc,
                    remediation=remed,
                    evidence=evidence,
                    plugin_id=plugin_id,
                    source_tool="Nessus"
                )

                if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    actionable_findings.append(finding)
                else:
                    info_findings.append(finding)

        # Apply central VAPT control mapping
        map_findings_list(actionable_findings)
        map_findings_list(info_findings)

        return actionable_findings, info_findings
