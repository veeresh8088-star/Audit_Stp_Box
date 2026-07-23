# -*- coding: utf-8 -*-
import re
from typing import List, Tuple, Optional
from bs4 import BeautifulSoup
from .base_parser import BaseParser
from .finding_schema import Finding
from .control_mapper import map_findings_list

class BurpParser(BaseParser):
    def can_parse(self, filename: str, content: str) -> bool:
        if not content:
            return False
        fn_lower = filename.lower()
        if "burp" in fn_lower or "zap" in fn_lower:
            return True
        sample = content[:10000].lower()
        if "burp scanner" in sample or "burp suite" in sample or "owasp zap" in sample or "<issues" in sample or "bodh0" in sample:
            return True
        return False

    def parse(self, filename: str, content: str) -> Tuple[List[Finding], List[Finding]]:
        if not content:
            return [], []

        # Check if content is XML format
        if content.strip().startswith("<?xml") or "<issues" in content[:2000]:
            return self._parse_xml(content)
        
        # Default to HTML format parsing
        return self._parse_html(content)

    def _calculate_score(self, severity: str, confidence: str) -> float:
        sev_upper = (severity or "").strip().upper()
        conf_upper = (confidence or "").strip().upper()

        if "HIGH" in sev_upper:
            if "CERTAIN" in conf_upper:
                return 9.0
            elif "TENTATIVE" in conf_upper:
                return 7.5
            return 8.5  # Firm / default
        elif "MED" in sev_upper:
            if "CERTAIN" in conf_upper:
                return 6.5
            elif "TENTATIVE" in conf_upper:
                return 4.5
            return 5.5
        elif "LOW" in sev_upper:
            if "CERTAIN" in conf_upper:
                return 3.5
            elif "TENTATIVE" in conf_upper:
                return 1.5
            return 2.5
        return 0.0  # Information / None

    def _parse_html(self, content: str) -> Tuple[List[Finding], List[Finding]]:
        soup = BeautifulSoup(content, 'html.parser')
        actionable_findings: List[Finding] = []
        info_findings: List[Finding] = []

        bodh0s = soup.find_all('span', class_='BODH0')

        for b0 in bodh0s:
            cat_id = b0.get('id', '')
            raw_cat_title = b0.get_text().strip()
            cat_title = re.sub(r'^\d+\.\s*', '', raw_cat_title)
            next_b0 = b0.find_next('span', class_='BODH0')

            # Extract category-level background, remediation, and CWEs
            cat_bg, cat_remed = "", ""
            cat_cwes = []

            # Inspect headings following b0 up to next_b0
            for h2 in b0.find_all_next('h2'):
                if next_b0 and h2.sourceline and next_b0.sourceline and h2.sourceline > next_b0.sourceline:
                    break
                h2_text = h2.get_text().strip().lower()
                next_span = h2.find_next_sibling('span', class_='TEXT')
                txt_val = next_span.get_text().strip() if next_span else ""

                if "background" in h2_text and not cat_bg:
                    cat_bg = txt_val
                elif "remediation" in h2_text and not cat_remed:
                    cat_remed = txt_val
                elif "classifications" in h2_text or "references" in h2_text:
                    if next_span:
                        cwe_matches = re.findall(r'CWE-\d+', next_span.get_text())
                        cat_cwes.extend(cwe_matches)

            # Find child BODH1s under this BODH0
            b1_list = []
            for b1 in soup.find_all('span', class_='BODH1'):
                if b1.sourceline > b0.sourceline and (not next_b0 or b1.sourceline < next_b0.sourceline):
                    b1_list.append(b1)

            # Parse instance (helper function)
            def process_element(elem, is_b1=True) -> Finding:
                inst_id = elem.get('id', '')
                raw_inst_title = elem.get_text().strip()
                inst_title = re.sub(r'^\d+(\.\d+)?\.\s*', '', raw_inst_title)

                # Look for summary_table following elem
                st = elem.find_next('table', class_='summary_table')
                raw_sev, raw_conf, host, path = "INFO", "Firm", "", ""

                if st:
                    for tr in st.find_all('tr'):
                        row_txt = " ".join([td.get_text().strip() for td in tr.find_all('td')])
                        if "Severity:" in row_txt:
                            raw_sev = row_txt.split("Severity:")[-1].strip()
                        elif "Confidence:" in row_txt:
                            raw_conf = row_txt.split("Confidence:")[-1].strip()
                        elif "Host:" in row_txt:
                            host = row_txt.split("Host:")[-1].strip()
                        elif "Path:" in row_txt:
                            path = row_txt.split("Path:")[-1].strip()

                sev_upper = raw_sev.strip().upper()
                if "HIGH" in sev_upper:
                    severity = "HIGH"
                elif "MED" in sev_upper:
                    severity = "MEDIUM"
                elif "LOW" in sev_upper:
                    severity = "LOW"
                else:
                    severity = "INFO"

                score = self._calculate_score(severity, raw_conf)

                # Extract issue detail and request/response snippets
                issue_detail = ""
                remed_detail = ""
                evidence = ""
                next_elem = elem.find_next('span', class_=['BODH1', 'BODH0'])

                for h2 in elem.find_all_next('h2'):
                    if next_elem and h2.sourceline and next_elem.sourceline and h2.sourceline > next_elem.sourceline:
                        break
                    h2_text = h2.get_text().strip().lower()
                    if "issue detail" in h2_text and not issue_detail:
                        next_span = h2.find_next_sibling('span', class_='TEXT')
                        if next_span:
                            issue_detail = next_span.get_text().strip()
                    elif "remediation detail" in h2_text and not remed_detail:
                        next_span = h2.find_next_sibling('span', class_='TEXT')
                        if next_span:
                            remed_detail = next_span.get_text().strip()
                    elif "request" in h2_text or "response" in h2_text:
                        rr_div = h2.find_next_sibling('div', class_='rr_div')
                        if rr_div and len(evidence) < 1500:
                            evidence += f"\n[{h2.get_text().strip()}]\n{rr_div.get_text().strip()[:400]}"

                target_str = f"{host}{path}".strip() if host else (path or "Web Application Endpoint")

                # Clean Title formatting
                if is_b1 and inst_title and inst_title != cat_title:
                    clean_inst = inst_title.replace(host, '').strip()
                    title = f"{cat_title} ({clean_inst})" if clean_inst else f"{cat_title} ({target_str})"
                else:
                    title = cat_title

                full_desc = f"{issue_detail}\n\n[Background]\n{cat_bg}".strip()
                full_remed = f"{remed_detail}\n\n[Remediation]\n{cat_remed}".strip()

                cves = sorted(list(set(re.findall(r'CVE-\d{4}-\d{4,7}', full_desc + evidence, re.IGNORECASE))))

                return Finding(
                    title=title,
                    severity=severity,
                    severity_score=score,
                    cve_list=cves,
                    target=target_str,
                    description=full_desc,
                    remediation=full_remed,
                    evidence=evidence.strip() or issue_detail[:500],
                    plugin_id=inst_id or "burp-issue",
                    source_tool="Burp Suite"
                )

            if b1_list:
                for b1 in b1_list:
                    f = process_element(b1, is_b1=True)
                    if f.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                        actionable_findings.append(f)
                    else:
                        info_findings.append(f)
            else:
                f = process_element(b0, is_b1=False)
                if f.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    actionable_findings.append(f)
                else:
                    info_findings.append(f)

        map_findings_list(actionable_findings)
        map_findings_list(info_findings)

        return actionable_findings, info_findings

    def _parse_xml(self, content: str) -> Tuple[List[Finding], List[Finding]]:
        soup = BeautifulSoup(content, 'html.parser')
        actionable_findings: List[Finding] = []
        info_findings: List[Finding] = []

        issues = soup.find_all('issue')
        for issue in issues:
            name = issue.find('name')
            title = name.get_text().strip() if name else "Burp Suite Finding"

            sev = issue.find('severity')
            raw_sev = sev.get_text().strip().upper() if sev else "INFO"
            
            conf = issue.find('confidence')
            raw_conf = conf.get_text().strip() if conf else "Firm"

            if "HIGH" in raw_sev:
                severity = "HIGH"
            elif "MED" in raw_sev:
                severity = "MEDIUM"
            elif "LOW" in raw_sev:
                severity = "LOW"
            else:
                severity = "INFO"

            score = self._calculate_score(severity, raw_conf)

            host = issue.find('host')
            path = issue.find('path')
            location = issue.find('location')
            h_str = host.get_text().strip() if host else ""
            p_str = path.get_text().strip() if path else ""
            loc_str = location.get_text().strip() if location else ""
            target_str = f"{h_str}{p_str} ({loc_str})".strip()

            detail = issue.find('issuedetail')
            desc = detail.get_text().strip() if detail else ""

            remed = issue.find('remediationbackground')
            remed_str = remed.get_text().strip() if remed else ""

            finding = Finding(
                title=title,
                severity=severity,
                severity_score=score,
                target=target_str,
                description=desc,
                remediation=remed_str,
                source_tool="Burp Suite"
            )

            if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                actionable_findings.append(finding)
            else:
                info_findings.append(finding)

        map_findings_list(actionable_findings)
        map_findings_list(info_findings)

        return actionable_findings, info_findings
