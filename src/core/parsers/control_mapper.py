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


# ══════════════════════════════════════════════════════════════════════════════
# RISK CATEGORY TAXONOMY  (100% offline — static deterministic lookup)
# ══════════════════════════════════════════════════════════════════════════════

# Maps OWASP Top 10 codes to human-readable risk categories
_OWASP_TO_CATEGORY = {
    "A01": "Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable Components",
    "A07": "Authentication Failures",
    "A08": "Data Integrity Failures",
    "A09": "Logging & Monitoring",
    "A10": "SSRF",
}

def map_finding_to_risk_category(finding: Finding) -> str:
    """
    Maps a Finding to a human-readable Risk Category using:
    1. CWE → OWASP Top 10 static lookup
    2. Title/description keyword fallback
    Returns a category string like 'Injection', 'Access Control', etc.
    100% offline — no network calls.
    """
    # Try CWE-based OWASP mapping first
    cwe_id = None
    # Extract CWE from CVE list or evidence
    combined = f"{(finding.title or '').lower()} {(finding.description or '').lower()} {(finding.evidence or '').lower()}"
    cwe_match = re.search(r'CWE-(\d+)', combined, re.IGNORECASE)
    if cwe_match:
        cwe_id = cwe_match.group(0).upper()

    if cwe_id:
        owasp = CWE_TO_OWASP_MAP.get(cwe_id, "")
        if owasp:
            # Extract A0x prefix to map to category
            code = owasp[:3]
            if code in _OWASP_TO_CATEGORY:
                return _OWASP_TO_CATEGORY[code]

    # Use the existing OWASP mapper as fallback
    owasp_str = map_finding_to_owasp(cwe_id, finding.title, finding.description)
    if owasp_str:
        code = owasp_str[:3]
        if code in _OWASP_TO_CATEGORY:
            return _OWASP_TO_CATEGORY[code]

    # Final keyword-based fallback
    if any(k in combined for k in ("xss", "sqli", "sql injection", "command injection", "ldap injection", "scripting", "injection")):
        return "Injection"
    if any(k in combined for k in ("access control", "privilege escalation", "directory traversal", "cors", "idor", "unauthorized")):
        return "Access Control"
    if any(k in combined for k in ("weak cipher", "ssl", "tls", "plaintext", "unencrypted", "hsts", "crypto")):
        return "Cryptographic Failures"
    if any(k in combined for k in ("auth", "password", "session", "credential", "jwt", "login")):
        return "Authentication Failures"
    if any(k in combined for k in ("ssrf", "server-side request forgery")):
        return "SSRF"
    if any(k in combined for k in ("patch", "update", "outdated", "eol", "end of life")):
        return "Vulnerable Components"
    if any(k in combined for k in ("network", "port", "tcp", "udp", "firewall", "nmap", "open port")):
        return "Network Security"
    if any(k in combined for k in ("log", "monitoring", "audit trail")):
        return "Logging & Monitoring"

    return "Security Misconfiguration"



# ══════════════════════════════════════════════════════════════════════════════
# CIA IMPACT & PII EXPOSURE EVALUATOR  (100% offline — regex-based)
# ══════════════════════════════════════════════════════════════════════════════

# PII / sensitive data patterns (reused from src/core/pii_redactor.py logic)
_PII_PATTERNS = [
    re.compile(r'[\w.+\-]+@[\w\-]+\.(?:[a-zA-Z]{2,})', re.IGNORECASE),        # Email
    re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'),  # IPv4
    re.compile(r'(?:password|passwd|pwd|secret|api[_\-]?key|token|credential|private[_\-]?key)\s*[:=]\s*\S+', re.IGNORECASE),  # Credentials
    re.compile(r'(?:ssn|social\s+security|credit\s+card|card\s+number|pan\s+number|aadhaar)', re.IGNORECASE),  # PII identifiers
]

def evaluate_cia_and_pii_impact(finding: Finding) -> tuple:
    """
    Evaluates CIA (Confidentiality, Integrity, Availability) impact and
    PII exposure for a Finding based on its content.
    Returns (cia_impact_str, is_pii_exposed).
    100% offline — uses local regex patterns only.
    """
    combined = f"{finding.title or ''} {finding.description or ''} {finding.evidence or ''} {finding.remediation or ''}"

    # ── PII Exposure Detection ──
    is_pii = False
    for pattern in _PII_PATTERNS:
        if pattern.search(combined):
            is_pii = True
            break

    # ── CIA Impact Assessment ──
    combined_lower = combined.lower()
    c_impact = "NONE"
    i_impact = "NONE"
    a_impact = "NONE"

    # Confidentiality indicators
    if is_pii or any(k in combined_lower for k in (
        "information disclosure", "data leak", "sensitive", "credential",
        "password", "token", "private key", "directory listing",
        "source code", "backup file", "database dump", "pii"
    )):
        c_impact = "HIGH"
    elif any(k in combined_lower for k in (
        "version disclosure", "banner", "stack trace", "error message",
        "server header", "configuration"
    )):
        c_impact = "MEDIUM"

    # Integrity indicators
    if any(k in combined_lower for k in (
        "injection", "sqli", "xss", "csrf", "command injection",
        "code execution", "rce", "file upload", "deserialization"
    )):
        i_impact = "HIGH"
    elif any(k in combined_lower for k in (
        "open redirect", "clickjacking", "header injection"
    )):
        i_impact = "MEDIUM"

    # Availability indicators
    if any(k in combined_lower for k in (
        "denial of service", "dos", "ddos", "buffer overflow",
        "resource exhaustion", "crash", "memory corruption"
    )):
        a_impact = "HIGH"
    elif any(k in combined_lower for k in (
        "rate limit", "timeout", "slow"
    )):
        a_impact = "MEDIUM"

    if is_pii:
        c_impact = "Confidential (High - PII Data Present)"
    cia_str = f"C:{c_impact} | I:{i_impact} | A:{a_impact}"
    return cia_str, is_pii


# ══════════════════════════════════════════════════════════════════════════════
# ACTIONABLE DEVELOPER REMEDIATION ENGINE  (100% offline — template-based)
# ══════════════════════════════════════════════════════════════════════════════

_REMEDIATION_TEMPLATES = {
    "sql injection": "Use parameterized queries (prepared statements) instead of string concatenation. Example: `cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))`. Apply input validation and use an ORM where possible.",
    "sqli": "Use parameterized queries (prepared statements) instead of string concatenation. Apply input validation and use an ORM where possible.",
    "cross-site scripting": "Encode all user-supplied output using context-aware encoding (HTML entity, JavaScript, URL encoding). Implement Content-Security-Policy (CSP) headers. Use frameworks with auto-escaping (React, Angular).",
    "xss": "Encode all user-supplied output using context-aware encoding. Implement Content-Security-Policy (CSP) headers.",
    "csrf": "Implement anti-CSRF tokens (synchronizer token pattern) on all state-changing requests. Set `SameSite=Strict` or `SameSite=Lax` on session cookies.",
    "hsts": "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` to all HTTPS responses. Ensure all resources load over HTTPS.",
    "ssl": "Upgrade to TLS 1.2+ minimum. Disable SSLv3, TLS 1.0, TLS 1.1. Use strong cipher suites (AES-GCM, ChaCha20). Renew expired certificates.",
    "tls": "Upgrade to TLS 1.2+ minimum. Disable weak protocols and cipher suites. Configure perfect forward secrecy (ECDHE).",
    "weak cipher": "Disable RC4, DES, 3DES, and CBC-mode ciphers. Configure server to prefer AES-256-GCM or ChaCha20-Poly1305.",
    "outdated": "Update the affected software/library to the latest stable version. Establish a patch management policy with regular update cycles.",
    "end of life": "Migrate to a supported version of the software immediately. Unsupported software receives no security patches.",
    "open redirect": "Validate and whitelist redirect URLs against a list of allowed domains. Never pass user-controlled URLs directly to redirect functions.",
    "directory traversal": "Sanitize file path inputs. Use a whitelist of allowed file paths. Never use user input directly in file system operations.",
    "command injection": "Avoid passing user input to shell commands. Use language-specific safe APIs (e.g., `subprocess.run()` with `shell=False`). Apply strict input validation.",
    "rce": "Patch the vulnerable component immediately. Isolate the affected service using network segmentation. Apply least-privilege execution context.",
    "default credentials": "Change all default usernames and passwords before deployment. Implement strong password policies and credential rotation.",
    "missing security headers": "Add security headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, `Content-Security-Policy`, `Referrer-Policy: strict-origin-when-cross-origin`.",
    "clickjacking": "Set `X-Frame-Options: DENY` or `SAMEORIGIN`. Implement `Content-Security-Policy: frame-ancestors 'none'`.",
    "information disclosure": "Remove verbose error messages from production. Disable server version banners. Remove unnecessary HTTP response headers.",
    "ssrf": "Validate and whitelist allowed URLs/IP ranges. Block requests to internal/private IP ranges (10.x, 172.16-31.x, 192.168.x). Use a dedicated egress proxy.",
    "deserialization": "Avoid deserializing untrusted data. Use safe serialization formats (JSON) instead of native object serialization. Implement integrity checks.",
    "file upload": "Validate file types using content inspection (magic bytes), not just extensions. Store uploads outside the web root. Set size limits and scan for malware.",
    "privilege escalation": "Apply principle of least privilege. Validate authorization on every privileged action server-side. Use role-based access control (RBAC).",
    "brute force": "Implement account lockout or rate limiting after failed attempts. Use CAPTCHA. Enforce strong password policies and multi-factor authentication.",
}

def get_actionable_remediation(finding: Finding) -> str:
    """
    Returns developer-actionable remediation guidance based on finding title/description.
    Uses a deterministic local template dictionary — 100% offline, no LLM required.
    Falls back to the scanner's original remediation text if no template matches.
    """
    combined = f"{(finding.title or '').lower()} {(finding.description or '').lower()}"

    # Check each template key against combined text
    for key, guidance in _REMEDIATION_TEMPLATES.items():
        if key in combined:
            return guidance

    # Fallback: return the scanner's own remediation if available
    if finding.remediation and finding.remediation.strip():
        return finding.remediation.strip()

    return ""


# ══════════════════════════════════════════════════════════════════════════════
# UNIFIED ENRICHMENT PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

def map_findings_list(findings: List[Finding]) -> List[Finding]:
    """
    Centralized mapper helper that enriches a list of Findings in-place:
    1. Assigns control_id (VAPT-1..VAPT-15)
    2. Assigns risk category (Access Control, Injection, etc.)
    3. Evaluates CIA impact & PII exposure
    4. Generates actionable developer remediation
    All operations are 100% offline and deterministic.
    """
    for f in findings:
        if not f.control_id:
            f.control_id = map_finding_to_control(f)
        if not f.category:
            f.category = map_finding_to_risk_category(f)
        if not f.cia_impact:
            cia_str, is_pii = evaluate_cia_and_pii_impact(f)
            f.cia_impact = cia_str
            f.is_pii_exposed = is_pii
        if not f.remediation_actionable:
            f.remediation_actionable = get_actionable_remediation(f)
    return findings
