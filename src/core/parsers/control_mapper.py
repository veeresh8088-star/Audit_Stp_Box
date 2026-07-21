# -*- coding: utf-8 -*-
import re
from typing import List, Optional
from .finding_schema import Finding

# Official Published MITRE CWE to OWASP Top 10 (2021) Deterministic Lookup Table
CWE_TO_OWASP_MAP = {
    # A01:2021 - Broken Access Control
    "CWE-22": "A01:2021 Broken Access Control",
    "CWE-284": "A01:2021 Broken Access Control",
    "CWE-285": "A01:2021 Broken Access Control",
    "CWE-639": "A01:2021 Broken Access Control",
    "CWE-862": "A01:2021 Broken Access Control",
    "CWE-863": "A01:2021 Broken Access Control",
    
    # A02:2021 - Cryptographic Failures
    "CWE-259": "A02:2021 Cryptographic Failures",
    "CWE-326": "A02:2021 Cryptographic Failures",
    "CWE-327": "A02:2021 Cryptographic Failures",
    "CWE-331": "A02:2021 Cryptographic Failures",

    # A03:2021 - Injection
    "CWE-79": "A03:2021 Injection", # XSS
    "CWE-89": "A03:2021 Injection", # SQLi
    "CWE-77": "A03:2021 Injection", # Command Injection
    "CWE-78": "A03:2021 Injection",
    "CWE-94": "A03:2021 Injection",

    # A04:2021 - Insecure Design
    "CWE-209": "A04:2021 Insecure Design",
    "CWE-522": "A04:2021 Insecure Design",

    # A05:2021 - Security Misconfiguration
    "CWE-16": "A05:2021 Security Misconfiguration",
    "CWE-200": "A05:2021 Security Misconfiguration",
    "CWE-693": "A05:2021 Security Misconfiguration",

    # A06:2021 - Vulnerable and Outdated Components
    "CWE-937": "A06:2021 Vulnerable and Outdated Components",
    "CWE-1104": "A06:2021 Vulnerable and Outdated Components",

    # A07:2021 - Identification and Authentication Failures
    "CWE-287": "A07:2021 Identification & Auth Failures",
    "CWE-384": "A07:2021 Identification & Auth Failures",
    "CWE-798": "A07:2021 Identification & Auth Failures",

    # A08:2021 - Software and Data Integrity Failures
    "CWE-502": "A08:2021 Software and Data Integrity Failures",
    "CWE-829": "A08:2021 Software and Data Integrity Failures",

    # A09:2021 - Security Logging and Monitoring Failures
    "CWE-778": "A09:2021 Security Logging & Monitoring Failures",
    "CWE-117": "A09:2021 Security Logging & Monitoring Failures",

    # A10:2021 - Server-Side Request Forgery (SSRF)
    "CWE-918": "A10:2021 Server-Side Request Forgery (SSRF)",
}

def get_dedup_key(title: str, target: str, cve_list: Optional[List[str]] = None, plugin_id: Optional[str] = None) -> str:
    """
    CVE-First, Plugin-ID-fallback, Title-last Deduplication Strategy.
    Prevents accidentally merging distinct vulnerabilities (e.g. Notepad++ < 8.8.2 vs < 8.9.2).
    """
    t_clean = (target or "").strip().lower()
    if cve_list and len(cve_list) > 0:
        cve_str = ",".join(sorted([str(c).upper().strip() for c in cve_list if c]))
        if cve_str:
            return f"cve:{cve_str}|target:{t_clean}"
    if plugin_id and str(plugin_id).strip():
        return f"plugin:{str(plugin_id).strip()}|target:{t_clean}"
    return f"title:{(title or '').strip().lower()}|target:{t_clean}"

def map_finding_to_owasp(cwe_id: Optional[str], title: str, desc: str) -> str:
    """
    100% Deterministic OWASP Top 10 Mapper via static CWE tables.
    """
    if cwe_id:
        cwe_clean = f"CWE-{re.sub(r'[^0-9]', '', str(cwe_id))}"
        if cwe_clean in CWE_TO_OWASP_MAP:
            return CWE_TO_OWASP_MAP[cwe_clean]
            
    combined = f"{(title or '').lower()} {(desc or '').lower()}"
    if any(k in combined for k in ("xss", "sqli", "sql injection", "command injection", "ldap injection")):
        return "A03:2021 Injection"
    if any(k in combined for k in ("access control", "privilege escalation", "directory traversal", "cors", "idor")):
        return "A01:2021 Broken Access Control"
    if any(k in combined for k in ("weak cipher", "ssl", "tls", "plaintext", "unencrypted", "hsts")):
        return "A02:2021 Cryptographic Failures"
    if any(k in combined for k in ("outdated", "end of life", "eol", "unpatched")):
        return "A06:2021 Vulnerable and Outdated Components"
    if any(k in combined for k in ("auth", "password", "session", "credential", "jwt")):
        return "A07:2021 Identification & Auth Failures"
    if any(k in combined for k in ("ssrf", "server-side request forgery")):
        return "A10:2021 Server-Side Request Forgery (SSRF)"
        
    return "A05:2021 Security Misconfiguration"

def map_finding_to_control(finding: Finding) -> str:
    """
    Centralized 100% Deterministic VAPT control mapper.
    Assigns a VAPT control ID (VAPT-1 .. VAPT-15) based on finding metadata,
    title, CVEs, and description. ZERO LLM dependency for category mapping.
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
