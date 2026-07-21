# -*- coding: utf-8 -*-
import re
from typing import List
from .finding_schema import Finding

def map_finding_to_control(finding: Finding) -> str:
    """
    Centralized VAPT control mapper.
    Assigns a VAPT control ID (VAPT-1 .. VAPT-15) based on finding metadata,
    title, CVEs, and description.
    """
    title_lower = (finding.title or "").lower()
    desc_lower = (finding.description or "").lower()
    ev_lower = (finding.evidence or "").lower()
    combined = f"{title_lower} {desc_lower} {ev_lower}"

    # 1. Specific technical vulnerability classifications
    if any(k in combined for k in ("rce", "remote code execution", "directory traversal", "winrar", "buffer overflow")):
        return "VAPT-5"

    if any(k in combined for k in ("privilege escalation", "privesc", "uac bypass", "sudo")):
        return "VAPT-7"

    if any(k in combined for k in ("weak cipher", "ssl", "tls", "rc4", "3des", "cbc", "plaintext", "unencrypted", "default credentials", "default password")):
        return "VAPT-14"

    if any(k in combined for k in ("web", "http", "https", "xss", "sqli", "csrf", "hsts", "cookie", "apache", "nginx", "iis", "owasp")):
        return "VAPT-4"

    if any(k in combined for k in ("patch", "outdated", "update required", "installed version", "fixed version", "end of life", "eol")):
        return "VAPT-12"

    if any(k in combined for k in ("api", "rest", "graphql", "jwt", "swagger", "openapi")):
        return "VAPT-10"

    if any(k in combined for k in ("wireless", "wifi", "wpa", "802.11", "bluetooth")):
        return "VAPT-9"

    if any(k in combined for k in ("phishing", "spf", "dkim", "dmarc", "social engineering")):
        return "VAPT-8"

    if any(k in combined for k in ("reconnaissance", "osint", "whois", "dns zone")):
        return "VAPT-2"

    if any(k in combined for k in ("firewall", "segmentation", "filtered port")):
        return "VAPT-13"

    # Default fallback for network scanner findings
    return "VAPT-3"

def map_findings_list(findings: List[Finding]) -> List[Finding]:
    """
    Centralized mapper helper to assign control_id to a list of Findings in-place.
    """
    for f in findings:
        if not f.control_id:
            f.control_id = map_finding_to_control(f)
    return findings
