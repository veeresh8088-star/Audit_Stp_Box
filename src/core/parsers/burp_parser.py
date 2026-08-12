# -*- coding: utf-8 -*-
import re
from typing import List, Tuple, Optional
from bs4 import BeautifulSoup
from .base_parser import BaseParser

# Prefer lxml for speed; fallback to html.parser if unavailable
try:
    import lxml  # noqa: F401
    _HTML_PARSER = "lxml"
    _XML_PARSER = "lxml-xml"
except ImportError:
    _HTML_PARSER = "html.parser"
    _XML_PARSER = "html.parser"
from .finding_schema import Finding
from .control_mapper import map_findings_list

class BurpParser(BaseParser):
    def can_parse(self, filename: str, content: str) -> bool:
        if not content:
            return False
        fn_lower = filename.lower()
        if "burp" in fn_lower or "zap" in fn_lower:
            return True
        sample = content[:100000].lower()
        if "burp scanner" in sample or "burp suite" in sample or "owasp zap" in sample or "<issues" in sample or "bodh0" in sample or "issue background" in sample or "issue detail" in sample:
            return True
        return False

    def parse(self, filename: str, content: str) -> Tuple[List[Finding], List[Finding]]:
        if not content:
            return [], []

        # Check if content is XML format
        if content.strip().startswith("<?xml") or "<issues" in content[:2000]:
            return self._parse_xml(content)
        
        # HTML format parsing
        res_act, res_inf = self._parse_html(content)
        if res_act or res_inf:
            return res_act, res_inf
            
        # Fallback to plain-text / PDF text parsing
        return self._parse_plaintext(content)

    def _calculate_score(self, severity: str, confidence: str) -> float:
        score, _ = self._calculate_score_and_vector("", severity, confidence)
        return score

    def _calculate_score_and_vector(self, vuln_title: str, severity: str, confidence: str) -> Tuple[float, str]:
        t_lower = (vuln_title or "").lower()
        sev_upper = (severity or "").strip().upper()

        if "sql injection" in t_lower:
            return 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        elif "xml external entity" in t_lower or "xxe" in t_lower:
            return 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        elif "template injection" in t_lower or "csti" in t_lower:
            return 8.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"
        elif "external service interaction (http)" in t_lower or "ssrf" in t_lower:
            return 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"
        elif "cross-site scripting" in t_lower or "xss" in t_lower:
            return 7.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        elif "open redirection" in t_lower or "open redirect" in t_lower:
            return 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        elif "javascript dependency" in t_lower or "cve-2020-7676" in t_lower:
            return 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        elif "autocomplete" in t_lower:
            return 3.5, "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        elif "strict transport security" in t_lower or "hsts" in t_lower:
            return 3.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
        elif "information" in sev_upper or "info" in sev_upper:
            return 0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"

        if "HIGH" in sev_upper:
            return 8.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
        elif "MED" in sev_upper:
            return 5.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        elif "LOW" in sev_upper:
            return 2.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
        return 0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"

    def _parse_html(self, content: str) -> Tuple[List[Finding], List[Finding]]:
        soup = BeautifulSoup(content, _HTML_PARSER)
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

                score, cvss_vector = self._calculate_score_and_vector(cat_title, raw_sev, raw_conf)
                if score >= 9.0: severity = "CRITICAL"
                elif score >= 7.0: severity = "HIGH"
                elif score >= 4.0: severity = "MEDIUM"
                elif score > 0.0: severity = "LOW"
                else: severity = "INFO"

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
                    cvss_vector=cvss_vector,
                    confidence=raw_conf or "Firm",
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
        import base64
        soup = BeautifulSoup(content, _XML_PARSER)
        actionable_findings: List[Finding] = []
        info_findings: List[Finding] = []

        def _get_child_text(parent, tag_pattern):
            node = parent.find(re.compile(rf'^{tag_pattern}$', re.IGNORECASE))
            return node.get_text().strip() if node else ""

        issues = soup.find_all(re.compile(r'^issue$', re.IGNORECASE))
        for issue in issues:
            title = _get_child_text(issue, 'name') or "Burp Suite Finding"
            raw_sev = _get_child_text(issue, 'severity').upper() or "INFO"
            raw_conf = _get_child_text(issue, 'confidence') or "Firm"

            if "HIGH" in raw_sev:
                severity = "HIGH"
            elif "MED" in raw_sev:
                severity = "MEDIUM"
            elif "LOW" in raw_sev:
                severity = "LOW"
            else:
                severity = "INFO"

            score, cvss_vector = self._calculate_score_and_vector(title, raw_sev, raw_conf)

            h_str = _get_child_text(issue, 'host')
            p_str = _get_child_text(issue, 'path')
            loc_str = _get_child_text(issue, 'location')
            target_str = f"{h_str}{p_str} ({loc_str})".strip() if loc_str else f"{h_str}{p_str}".strip()

            desc_detail = _get_child_text(issue, 'issuedetail')
            desc_bg = _get_child_text(issue, 'issuebackground')
            
            if desc_detail and desc_bg:
                full_desc = f"{desc_detail}\n\n[Issue Background]\n{desc_bg}"
            else:
                full_desc = desc_detail or desc_bg

            r_bg_str = _get_child_text(issue, 'remediationbackground')
            r_dt_str = _get_child_text(issue, 'remediationdetail')
            if r_dt_str and r_bg_str:
                full_remed = f"{r_dt_str}\n\n[Remediation Background]\n{r_bg_str}"
            else:
                full_remed = r_dt_str or r_bg_str


            # Parse HTTP Request / Response evidence proof
            evidence = ""
            for rr in issue.find_all(['requestresponse', 'request', 'response']):
                req = rr.find('request') if rr.name == 'requestresponse' else (rr if rr.name == 'request' else None)
                resp = rr.find('response') if rr.name == 'requestresponse' else (rr if rr.name == 'response' else None)
                
                if req:
                    req_text = req.get_text().strip()
                    if req.get('base64') == 'true':
                        try:
                            req_text = base64.b64decode(req_text).decode('utf-8', errors='ignore')
                        except Exception:
                            pass
                    if req_text and "[HTTP Request]" not in evidence:
                        evidence += f"[HTTP Request]\n{req_text[:1200]}\n\n"
                
                if resp:
                    resp_text = resp.get_text().strip()
                    if resp.get('base64') == 'true':
                        try:
                            resp_text = base64.b64decode(resp_text).decode('utf-8', errors='ignore')
                        except Exception:
                            pass
                    if resp_text and "[HTTP Response]" not in evidence:
                        evidence += f"[HTTP Response Snippet]\n{resp_text[:1200]}\n\n"

            cves = sorted(list(set(re.findall(r'CVE-\d{4}-\d{4,7}', full_desc + evidence, re.IGNORECASE))))

            type_elem = issue.find('type')
            plugin_id = type_elem.get_text().strip() if type_elem else "burp-issue"

            finding = Finding(
                title=title,
                severity=severity,
                severity_score=score,
                cvss_vector=cvss_vector,
                confidence=raw_conf,
                cve_list=cves,
                target=target_str or "Web Application Endpoint",
                description=full_desc,
                remediation=full_remed,
                evidence=evidence.strip() or desc_detail[:500],
                plugin_id=plugin_id,
                source_tool="Burp Suite"
            )

            if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                actionable_findings.append(finding)
            else:
                info_findings.append(finding)

        map_findings_list(actionable_findings)
        map_findings_list(info_findings)

        return actionable_findings, info_findings

    def _parse_plaintext(self, content: str) -> Tuple[List[Finding], List[Finding]]:
        """
        Parses text extracted from PDF reports or plain text Burp exports.
        """
        actionable_findings: List[Finding] = []
        info_findings: List[Finding] = []

        # Split into blocks by numbered headings (e.g., "\n1. SQL injection", "\n1.1. https://...")
        blocks = re.split(r'(?:\r?\n)+(?=\d+\.(?:\d+)?\s+[A-Za-z0-9_])', content)

        cur_cat_title = "Burp Suite Finding"
        for block in blocks:
            lines = [l.strip() for l in block.strip().split('\n') if l.strip()]
            if not lines:
                continue

            first_line = lines[0]
            m_cat = re.match(r'^\d+\.\s+([A-Za-z0-9_\-\s\(\)]+)', first_line)
            m_inst = re.match(r'^\d+\.\d+\.\s+(https?://[^\s]+|\/[^\s]+)', first_line)

            if m_cat and not m_inst:
                cur_cat_title = m_cat.group(1).strip()

            # Parse finding details
            sev_match = re.search(r'Severity:\s*(Critical|High|Medium|Low|Information|Info)', block, re.IGNORECASE)
            conf_match = re.search(r'Confidence:\s*(Certain|Firm|Tentative)', block, re.IGNORECASE)
            host_match = re.search(r'Host:\s*(https?://[^\s\n]+)', block, re.IGNORECASE)
            path_match = re.search(r'Path:\s*([^\s\n]+)', block, re.IGNORECASE)

            if not (sev_match or host_match or m_inst or "Issue detail" in block):
                continue

            raw_sev = sev_match.group(1).upper() if sev_match else "INFO"
            raw_conf = conf_match.group(1) if conf_match else "Firm"
            host = host_match.group(1) if host_match else ""
            path = path_match.group(1) if path_match else ""
            target_str = f"{host}{path}".strip() if host else (path or "Web Application Endpoint")

            if "HIGH" in raw_sev:
                severity = "HIGH"
            elif "MED" in raw_sev:
                severity = "MEDIUM"
            elif "LOW" in raw_sev:
                severity = "LOW"
            else:
                severity = "INFO"

            score = self._calculate_score(severity, raw_conf)

            title = cur_cat_title
            if m_inst:
                inst_target = m_inst.group(1)
                title = f"{cur_cat_title} ({inst_target})"

            # Extract Issue Detail
            desc = ""
            m_desc = re.search(r'Issue detail\s*\n\s*(.*?)(?=\n\s*(?:Issue background|Issue remediation|Request|Response|References|$))', block, re.DOTALL)
            if m_desc:
                desc = m_desc.group(1).strip()
            else:
                desc = block[:400]

            # Extract Remediation
            remed = ""
            m_remed = re.search(r'Issue remediation\s*\n\s*(.*?)(?=\n\s*(?:References|Vulnerability classifications|Request|Response|$))', block, re.DOTALL)
            if m_remed:
                remed = m_remed.group(1).strip()

            cves = sorted(list(set(re.findall(r'CVE-\d{4}-\d{4,7}', block, re.IGNORECASE))))

            f = Finding(
                title=title,
                severity=severity,
                severity_score=score,
                cve_list=cves,
                target=target_str,
                description=desc,
                remediation=remed,
                source_tool="Burp Suite"
            )

            if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                actionable_findings.append(f)
            else:
                info_findings.append(f)

        map_findings_list(actionable_findings)
        map_findings_list(info_findings)

        return actionable_findings, info_findings

