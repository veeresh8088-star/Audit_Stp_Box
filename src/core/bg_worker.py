import os
import io
import sys
import time
import json
import uuid
import threading
from datetime import datetime, timezone
from src.db.database import (
    SessionLocal,
    User,
    AuditReport,
    EvidenceFile,
    Finding,
    ComplianceScore,
    AuditCheckpoint,
    AuditTrail,
    SystemEvent,
    force_master,
    get_all_custom_controls
)

def log_system_event(event_type, severity, details, session_id=None, actor="System"):
    """Logs an audit error/warning/event into SystemEvent for the Privacy-Safe System Log Trail.

    Default actor is "System", not a specific person -- most callers that omit
    `actor` are logging system-initiated events (LLM timeouts, malware blocks,
    port-lock failures, background thread exceptions), not a real user's
    action, so attributing them to one specific hardcoded email was both
    misleading and a minor accuracy/privacy issue in the admin log trail.
    """
    for attempt in range(3):
        try:
            with force_master():
                db = SessionLocal()
                try:
                    db.add(SystemEvent(
                        event_type=event_type,
                        severity=severity,
                        actor=actor or "System",
                        session_id=session_id or "System",
                        meta=details
                    ))
                    db.commit()
                    return
                finally:
                    db.close()
        except Exception as _e:
            if attempt == 2:
                print(f"[SYSTEM EVENT LOG ERROR] {_e}", flush=True)
            time.sleep(0.15)
from src.core.controls_data import USE_CASES
from src.core.control_keywords import CONTROL_KEYWORDS
from src.core.input_guardrail import scan_document
from src.core.parsers.doc_parsers import extract_text
from src.core.retrieval import save_document_chunks
from src.core.bg_state import _bg_store, _bg_results, _bg_running, _bg_lock, _bg_stop_flags
from src.ai.audit_graph import audit_graph
from src.core.token_tracker import record_token_metrics
from src.core import redis_metrics as _rm


_CUSTOM_USE_CASES_CACHE = []
_CUSTOM_UC_CACHE_TS = 0
BACKEND_NAME = "Ollama"

# ── GLOBAL TOPIC → ISO CONTROL MAPPING TABLE ─────────────────────────────
TOPIC_CONTROL_MAP = {
    # ── Authentication & Identity ─────────────────────────────────────────────
    "multi-factor authentication": ["8.5", "5.17", "5.16"],
    "mfa": ["8.5", "5.17"], "otp": ["8.5", "5.17"], "2fa": ["8.5", "5.17"],
    "two-factor": ["8.5", "5.17"], "password": ["8.5", "5.17"],
    "authentication": ["8.5", "5.17", "5.15"], "authentication process": ["8.5", "5.17"],
    "authentication information": ["5.17"], "identity management": ["5.16", "5.15"],
    "iam": ["5.16", "5.15", "8.2", "5.18"], "idam": ["5.16", "5.15", "8.2", "5.18"],
    "single sign-on": ["8.5", "5.16"], "sso": ["8.5", "5.16"],
    "user provisioning": ["5.16", "5.18"], "account lifecycle": ["5.16", "5.18"],
    "joiner leaver": ["5.16", "5.18", "6.5"],

    # ── Privileged Access / PAM ───────────────────────────────────────────────
    "privileged access": ["8.2", "5.15", "5.18"], "pam": ["8.2", "5.15", "5.18"],
    "pim": ["8.2", "5.15"], "admin access": ["8.2", "5.18"],
    "root access": ["8.2", "5.18"], "role based access": ["5.15", "5.18", "8.2"],
    "rbac": ["5.15", "5.18"], "access rights": ["5.18", "5.15"],
    "access control": ["5.15", "5.18", "8.3"], "access management": ["5.15", "5.18"],
    "least privilege": ["5.18", "8.3"], "need to know": ["5.18", "8.3"],
    "access restriction": ["8.3", "5.18"],

    # ── Monitoring & Logging ──────────────────────────────────────────────────
    # NOTE: 7.4 (Physical Security Monitoring / CCTV) and 5.22 (Monitoring of SUPPLIER
    # Services specifically) were previously attached to every "monitoring" keyword here
    # just because their control names contain the word "monitoring" -- neither has
    # anything to do with system/cloud/log monitoring. Removed; 8.16 (Monitoring
    # Activities) is the correct general-purpose match for this keyword family.
    "monitoring": ["8.16"], "cloudwatch": ["8.16"],
    "aws cloudwatch": ["8.16", "5.23"], "cloud monitoring": ["8.16", "5.23"],
    "siem": ["8.16", "8.15"], "alerting": ["8.16", "5.25"],
    "logging": ["8.15", "8.16", "5.28"], "log management": ["8.15", "5.28"],
    "log archival": ["8.15", "5.28"], "log archive": ["8.15", "5.28"],
    "archived log": ["8.15", "5.28"], "audit log": ["8.15", "5.28"],
    "prod log": ["8.15", "5.28"], "syslog": ["8.15"], "event logs": ["8.15"],
    "log retention": ["8.15", "5.33"],
    "collection of evidence": ["5.28"], "evidence collection": ["5.28"],

    # ── NTP / Clock ───────────────────────────────────────────────────────────
    "ntp": ["8.17"], "ntp server": ["8.17"], "clock synchronization": ["8.17"],
    "clock sync": ["8.17"], "ntp clock sync": ["8.17"],
    "time sync": ["8.17"], "time server": ["8.17"], "timestamp": ["8.17"],

    # ── Cloud Services ────────────────────────────────────────────────────────
    "cloud": ["5.23", "8.16"], "aws": ["5.23", "8.16"], "azure": ["5.23"], "gcp": ["5.23"],
    "cloud services": ["5.23"], "cloud security": ["5.23"],
    "saas": ["5.23"], "iaas": ["5.23"], "paas": ["5.23"],

    # ── Network Security ──────────────────────────────────────────────────────
    "network security": ["8.20", "8.21", "8.22"], "firewall": ["8.20", "VAPT-13"],
    "network segmentation": ["8.22", "VAPT-13"], "vlan": ["8.22"],
    "dmz": ["8.22"], "micro segmentation": ["8.22"],
    "vpn": ["6.7", "8.20"], "remote working": ["6.7"], "remote access": ["6.7", "8.20"],
    "network services": ["8.21"], "api gateway": ["8.21"],
    "web filtering": ["8.23"], "url filtering": ["8.23"], "proxy": ["8.23"],
    "content filter": ["8.23"], "internet filtering": ["8.23"],

    # ── Vulnerability & Patch ─────────────────────────────────────────────────
    "vulnerability": ["8.8", "VAPT-11"], "patch": ["VAPT-12", "8.8"],
    "patch management": ["VAPT-12", "8.8"], "vulnerability scan": ["8.8", "VAPT-3"],
    "penetration test": ["VAPT-5", "VAPT-6", "8.29"],
    "pentest": ["VAPT-5", "VAPT-6"], "vapt": ["VAPT-5", "VAPT-6", "8.29"],

    # ── Operations & Procedures ───────────────────────────────────────────────
    "operating procedures": ["5.37"], "documented procedures": ["5.37"],
    "sop": ["5.37"], "operational procedure": ["5.37"],
    "standard operating procedure": ["5.37"],

    # ── Policy & Governance ───────────────────────────────────────────────────
    "information security policy": ["5.1"], "isms policy": ["5.1"],
    "security policy": ["5.1"], "iprotect": ["5.1"], "isms": ["5.1"],
    "roles and responsibilities": ["5.2"], "isms roles": ["5.2"],
    "security roles": ["5.2"], "responsibility assignment": ["5.2"],
    "segregation of duties": ["5.3"], "separation of duties": ["5.3"],
    "dual control": ["5.3"], "four eyes principle": ["5.3"],
    "management commitment": ["5.4"], "management responsibilities": ["5.4"],
    "senior management": ["5.4"], "executive sponsor": ["5.4"],
    "contact with authorities": ["5.5"], "law enforcement": ["5.5"],
    "regulatory body": ["5.5"], "government contact": ["5.5"],
    "special interest group": ["5.6"], "isac": ["5.6"], "industry group": ["5.6"],
    "security forum": ["5.6"],

    # ── Threat Intelligence ───────────────────────────────────────────────────
    "threat intelligence": ["5.7"], "threat feed": ["5.7"], "cti": ["5.7"],
    "threat data": ["5.7"], "ioc": ["5.7"], "indicators of compromise": ["5.7"],

    # ── Project & SDLC Governance ─────────────────────────────────────────────
    "project security": ["5.8"], "sdlc governance": ["5.8"], "project risk": ["5.8"],
    "security in projects": ["5.8"], "project management": ["5.8"],

    # ── Asset Management ──────────────────────────────────────────────────────
    "asset inventory": ["5.9"], "asset register": ["5.9"], "asset management": ["5.9"],
    "acceptable use": ["5.10"], "aup": ["5.10"], "usage policy": ["5.10"],
    "return of assets": ["5.11"], "asset return": ["5.11"], "equipment return": ["5.11"],
    "data classification": ["5.12"], "information classification": ["5.12"],
    "classification scheme": ["5.12"], "sensitivity label": ["5.12"],
    "data labelling": ["5.13"], "information labelling": ["5.13"], "document marking": ["5.13"],
    "information transfer": ["5.14"], "data transfer": ["5.14"],
    "file transfer": ["5.14"], "email security": ["5.14"], "secure ftp": ["5.14"], "sftp protocol": ["5.14"],

    # ── Supplier / Third Party ────────────────────────────────────────────────
    "supplier": ["5.19", "5.21", "5.22"], "vendor": ["5.19", "5.21", "5.22"],
    "third party": ["5.19", "5.22"], "supplier security": ["5.19", "5.21", "5.22"],
    "supplier relationship": ["5.19"], "vendor relationship": ["5.19"],
    "supplier agreement": ["5.20"], "vendor contract": ["5.20"],
    "third party contract": ["5.20"], "outsourcing agreement": ["5.20"],
    "ict supply chain": ["5.21"], "supply chain security": ["5.21"],
    "supply chain risk": ["5.21"], "hardware supply": ["5.21"],
    "supplier monitoring": ["5.22"], "vendor monitoring": ["5.22"],
    "third party review": ["5.22"], "supplier audit": ["5.22"],

    # ── Incident Management ───────────────────────────────────────────────────
    "incident": ["5.24", "5.25", "5.26"], "incident response": ["5.24", "5.25"],
    "security incident": ["5.24"], "incident management": ["5.24", "5.25"],
    "incident assessment": ["5.25"], "incident triage": ["5.25"],
    "event decision": ["5.25"], "incident classification": ["5.25"],
    "incident handling": ["5.26"], "containment": ["5.26"], "eradication": ["5.26"],
    "recovery response": ["5.26"],
    "lessons learned": ["5.27"], "post incident review": ["5.27"],
    "learning from incidents": ["5.27"], "incident debrief": ["5.27"],
    "forensic": ["5.28"], "digital forensic": ["5.28"],
    "chain of custody": ["5.28"], "evidence forensic": ["5.28"],

    # ── Business Continuity ───────────────────────────────────────────────────
    "business continuity": ["5.29", "5.30"], "bcp": ["5.29", "5.30"],
    "disaster recovery": ["5.29", "5.30"], "dr": ["5.29", "5.30"],
    "ict continuity": ["5.30"], "ict readiness": ["5.30"], "it continuity": ["5.30"],
    "backup": ["8.13"], "data backup": ["8.13"], "backup policy": ["8.13"],
    "system redundancy": ["8.14"], "failover mechanism": ["8.14"], "high availability setup": ["8.14"],

    # ── Compliance & Legal ────────────────────────────────────────────────────
    "legal requirement": ["5.31"], "statutory requirement": ["5.31"],
    "regulatory requirement": ["5.31"], "contractual requirement": ["5.31"],
    "compliance obligation": ["5.31"], "regulatory": ["5.31"],
    "intellectual property": ["5.32"], "copyright": ["5.32"],
    "software license": ["5.32"], "license management": ["5.32"], "ip rights": ["5.32"],
    "log retention policy": ["5.33"], "records retention": ["5.33"], "record management": ["5.33"],
    "gdpr": ["5.34"], "pii": ["5.34"], "personal data": ["5.34"],
    "privacy": ["5.34"], "data privacy": ["5.34"],
    "independent review": ["5.35"], "internal audit": ["5.35"], "isms review": ["5.35"],
    "external audit": ["5.35"],
    "compliance check": ["5.36"], "policy compliance": ["5.36"],
    "compliance review": ["5.36"], "standards compliance": ["5.36"],
    # ── HR & Personnel ────────────────────────────────────────────────────────
    # FIXED: was mapped to 5.1 (wrong); screening/onboarding are 6.1 people controls
    "background check": ["6.1"], "screening": ["6.1"], "pre-employment": ["6.1"],
    "onboarding": ["6.1"], "hr security": ["6.1"],
    "employment terms": ["6.2"], "terms of employment": ["6.2"],
    "employment contract": ["6.2"], "offer letter": ["6.2"],
    "security awareness": ["6.3"], "awareness training": ["6.3"],
    "staff training": ["6.3"], "phishing awareness": ["6.3"], "e-learning": ["6.3"],
    "disciplinary": ["6.4"], "misconduct": ["6.4"], "policy violation": ["6.4"],
    "termination": ["6.5"], "offboarding": ["6.5"], "exit process": ["6.5"],
    "leaver": ["6.5"], "resignation": ["6.5"], "dismissal": ["6.5"],
    "nda": ["6.6"], "non-disclosure": ["6.6"], "confidentiality agreement": ["6.6"],
    "remote work": ["6.7"], "work from home": ["6.7"], "wfh": ["6.7"],
    "telework": ["6.7"], "home working": ["6.7"], "vpn policy": ["6.7"],
    "security event reporting": ["6.8"], "event reporting": ["6.8"],
    "how to report": ["6.8"], "staff reporting": ["6.8"],

    # ── Physical Security ─────────────────────────────────────────────────────
    "physical security": ["7.1", "7.2", "7.4"], "visitor": ["7.2"],
    "visitor log": ["7.2"], "cctv": ["7.4"], "badge": ["7.2"],
    "physical access": ["7.1", "7.2"],
    "physical entry": ["7.2"], "entry control": ["7.2"],
    "door access": ["7.2"], "turnstile": ["7.2"],
    "secure office": ["7.3"], "secure room": ["7.3"], "server room": ["7.3"],
    "data center access": ["7.3"],
    "physical monitoring": ["7.4"], "camera surveillance": ["7.4"],
    "security camera": ["7.4"], "video surveillance": ["7.4"],
    "environmental threat": ["7.5"], "flood protection": ["7.5"], "fire protection": ["7.5"],
    "power protection": ["7.5"], "uninterruptible power": ["7.5", "7.11"],
    "secure area": ["7.6"], "restricted area": ["7.6"],
    "clean desk policy": ["7.7"], "clear screen policy": ["7.7"], "unattended workstation": ["7.7"],
    "equipment siting": ["7.8"], "rack security": ["7.8"],
    "assets off-premises": ["7.9"], "remote equipment": ["7.9"], "equipment offsite": ["7.9"],
    "storage media": ["7.10"], "removable media": ["7.10"], "usb": ["7.10"],
    "media handling": ["7.10"], "removable storage": ["7.10"],
    "supporting utilities": ["7.11"], "power supply failure": ["7.11"], "backup generator": ["7.11"],
    "utility failure": ["7.11"],
    "cabling": ["7.12"], "cable security": ["7.12"], "network cabling": ["7.12"],
    "structured cabling": ["7.12"],
    "equipment maintenance": ["7.13"], "maintenance schedule": ["7.13"],
    "hardware maintenance": ["7.13"], "preventive maintenance": ["7.13"],
    "secure disposal": ["7.14"], "equipment disposal": ["7.14"],
    "data destruction": ["7.14"], "disk wipe": ["7.14"],
    "degauss": ["7.14"], "decommission": ["7.14"],

    # ── Endpoint & Device ─────────────────────────────────────────────────────
    "endpoint": ["8.1"], "user endpoint": ["8.1"], "laptop policy": ["8.1"],
    "mobile device": ["8.1"], "mdm": ["8.1"], "byod": ["8.1"],
    "endpoint security": ["8.1"],

    # ── Source Code ───────────────────────────────────────────────────────────
    "software development": ["8.25", "8.28"], "sdlc": ["8.25", "8.28"],
    "secure coding": ["8.28"], "code review": ["8.28"],
    "source code": ["8.4", "8.28"], "code repository": ["8.4"],
    "git access": ["8.4"], "github": ["8.4"], "gitlab": ["8.4"],

    # ── Malware & Configuration ───────────────────────────────────────────────
    "antivirus": ["8.7"], "anti-malware": ["8.7"], "edr": ["8.7"],
    "malware": ["8.7"], "av policy": ["8.7"],
    "configuration management": ["8.9"], "hardening": ["8.9"],
    "cmdb": ["8.9"], "baseline configuration": ["8.9"],

    # ── Data Management ───────────────────────────────────────────────────────
    "data deletion": ["8.10"], "information deletion": ["8.10"],
    "secure erase": ["8.10"], "data wiping": ["8.10"],
    "data masking": ["8.11"], "anonymization": ["8.11"], "pseudonymization": ["8.11"],
    "dlp": ["8.12"], "data leakage prevention": ["8.12"],
    "data loss prevention": ["8.12"], "data exfiltration": ["8.12"],

    # ── Capacity & Utilities ──────────────────────────────────────────────────
    "api security": ["8.26"], "fraud analytics": ["8.26"],
    "capacity": ["8.6"], "cpu": ["8.6"], "memory": ["8.6"],
    "disk utilization": ["8.6"],
    "privileged utility": ["8.18"], "admin tools": ["8.18"],
    "utility programs": ["8.18"], "system utilities": ["8.18"],
    "software installation": ["8.19"], "approved software": ["8.19"],
    "application whitelist": ["8.19"], "install policy": ["8.19"],

    # ── Cryptography & Key Management ─────────────────────────────────────────
    "encryption": ["8.24"], "cryptography": ["8.24"],
    "kms": ["8.24"], "ssl": ["8.24"], "tls": ["8.24"], "key management": ["8.24"],

    # ── Risk Assessment ───────────────────────────────────────────────────────
    # FIXED: was mapped to 5.12 (Classification) which is wrong; risk assessment = 5.1, 5.7
    "risk assessment": ["5.1", "5.7", "5.8"],
    "risk management": ["5.1", "5.7"], "risk": ["5.1", "5.7"],
    "risk register": ["5.1", "5.7"], "risk treatment": ["5.1", "5.7"],
    "residual risk": ["5.1", "5.7"], "risk appetite": ["5.1", "5.7"],

    # ── Secure Development ────────────────────────────────────────────────────
    "secure development": ["8.25"], "secure development lifecycle": ["8.25"],
    "application security": ["8.26"], "security requirements": ["8.26"],
    "secure architecture": ["8.27"], "security architecture": ["8.27"],
    "engineering principles": ["8.27"], "security by design": ["8.27"],
    "security testing": ["8.29"], "acceptance testing": ["8.29"],
    "outsourced development": ["8.30"], "third party development": ["8.30"],
    "separation of environments": ["8.31"], "dev test prod": ["8.31"],
    "staging environment": ["8.31"], "non-production": ["8.31"],
    "change management": ["8.32"], "change control": ["8.32"],
    "change request": ["8.32"], "change advisory board": ["8.32"], "change approval process": ["8.32"],
    "test data": ["8.33"], "test information": ["8.33"],
    "production data in test": ["8.33"], "sanitised test data": ["8.33"],
    "audit testing": ["8.34"], "audit tools": ["8.34"], "audit environment": ["8.34"],
}

def log_dev_latency(message: str):
    """Appends performance and execution log entries for developer latency tracking."""
    try:
        os.makedirs("data", exist_ok=True)
        with open("data/audit_run_latency.log", "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")
    except Exception:
        pass

def _resolve_llm_model(model_choice):
    """Map UI model name to LLM model identifier."""
    MODEL_MAP = {
        "Gemma 4 (e4b)": "gemma4:e4b",
        "Gemma 4 (2b)": "gemma-2-2b-it",
    }
    if model_choice in MODEL_MAP:
        return MODEL_MAP[model_choice]
    if "12B" in model_choice:
        return "gemma4:12b"
    if "e4b" in model_choice or "4B" in model_choice:
        return "gemma4:e4b"
    if "Gemma" in model_choice or "9B" in model_choice or "2B" in model_choice:
        return "gemma2:9b"
    return "qwen2.5:7b"

def _load_custom_use_cases(force: bool = False) -> list:
    global _CUSTOM_USE_CASES_CACHE, _CUSTOM_UC_CACHE_TS
    now = time.time()
    if not force and (now - _CUSTOM_UC_CACHE_TS) < 60 and _CUSTOM_USE_CASES_CACHE:
        return _CUSTOM_USE_CASES_CACHE

    try:
        rows = get_all_custom_controls(active_only=True)
    except Exception:
        return []

    custom_ucs = []
    for idx, row in enumerate(rows):
        sl = 10000 + idx
        name = row["control_name"]
        cid = row["control_id"]
        desc = row["description"] or name
        cat = row["category"]
        kws = ", ".join(row["keywords"]) if row["keywords"] else name

        custom_ucs.append({
            "sl": sl,
            "standard": "Custom",
            "category": f"Custom — {cat}",
            "label": f"{name} ({cid}) [Custom]",
            "icon": "🔧",
            "use_case": name,
            "expected": f"Evidence of compliance with {name}. {desc}",
            "format": "PDF",
            "prompt_hint": (
                f"Verify compliance against the custom control: {name} ({cid}). "
                f"Category: {cat}. "
                f"Description: {desc}. "
                f"Relevant keywords: {kws}. "
                f"Check whether the uploaded documents demonstrate that this control "
                f"has been implemented, documented, and is being followed."
            ),
            "scope_tags": [cat],
            "severity": "MEDIUM",
            "finding": f"No documented evidence found for custom control {cid} ({name}).",
            "recommendation": (
                f"Establish, document, and implement procedures to satisfy "
                f"the custom control {cid} ({name})."
            ),
            "_is_custom": True,
            # Raw curated keywords (structured, not just flattened into prompt_hint text
            # above) so _build_controls_for_audit() can turn them into real retrieval
            # scoring weights instead of leaving retrieval.py's keyword scorer blind to them.
            "keywords": row["keywords"] or [],
        })

    _CUSTOM_USE_CASES_CACHE = custom_ucs
    _CUSTOM_UC_CACHE_TS = now
    return custom_ucs

def _get_expected_evidence(uc, custom_evidence=None):
    if custom_evidence is not None:
        return custom_evidence.get(uc["use_case"], uc["expected"])
    return uc["expected"]

def _build_controls_for_audit(selected_sls=None, custom_evidence=None):
    if custom_evidence is not None and isinstance(custom_evidence, dict) and "excel_items" in custom_evidence:
        excel_items = custom_evidence["excel_items"]
        if excel_items and isinstance(excel_items, list):
            controls = []
            for item in excel_items:
                ctrl_id = item.get("control_id", "UNKNOWN")
                # control_label is the official ISO name resolved by excel_scoping_parser
                # (e.g. "5.15 Access Control"), not the raw checklist question. Without it,
                # "control" ends up as just "5.15 — <question text>", and the UI's header
                # renderer strips everything after " — " assuming what's left is a real
                # name — leaving a bare "5.15" with no control name shown at all.
                ctrl_full_label = item.get("control_label") or ctrl_id
                q_text = item.get("question") or ctrl_full_label
                files = item.get("files") or item.get("raw_file_refs") or []
                files_str = ", ".join(files) if isinstance(files, list) else str(files)
                primary_file = files[0] if (files and isinstance(files, list) and len(files) > 0) else files_str

                # Role-split file lists, when the sheet has separately named
                # Policy/Evidence columns (both empty for a generic "File name"
                # column) -- carried through so the LLM can be told which locked
                # file(s) the auditor intended as policy proof vs evidence proof,
                # instead of re-deriving the split blind from undifferentiated text.
                policy_files = item.get("policy_files") or []
                evidence_files = item.get("evidence_files") or []

                controls.append({
                    "control": f"{ctrl_full_label} — {q_text}",
                    "control_id": ctrl_full_label,
                    "label": f"{ctrl_full_label} — {q_text}",
                    "expected": item.get("expected_evidence") or q_text,
                    "prompt_hint": item.get("prompt_hint") or f"Evaluate evidence for: {q_text}",
                    "severity": item.get("severity", "MEDIUM"),
                    "standard": "ISO 27001",
                    "recommendation": f"Establish, document, and implement procedures to satisfy {ctrl_full_label}.",
                    "evidence_location": primary_file,
                    "evidence_source_file": primary_file,
                    # Full file list for THIS row (not just the first one) — used by the
                    # scoping block below to lock retrieval to every file actually listed
                    # against this row, not only file[0], when a single row names multiple.
                    "evidence_source_files_all": files_str,
                    "policy_source_files_all": ", ".join(policy_files) if policy_files else "",
                    "evidence_only_source_files_all": ", ".join(evidence_files) if evidence_files else "",
                })
            return controls

    all_ucs = list(USE_CASES) + _load_custom_use_cases()
    controls = []
    seen_controls = set()
    for uc in all_ucs:
        ctrl_id = uc["use_case"]
        if ctrl_id in seen_controls:
            continue
        if selected_sls is None or uc["sl"] in selected_sls:
            seen_controls.add(ctrl_id)
            # Custom controls carry real auditor-curated keywords (weighted highest, 2.5,
            # since a human picked them) via _load_custom_use_cases(); standard controls
            # use the deterministically pre-generated CONTROL_KEYWORDS lookup. Either way,
            # retrieval.py's keyword scorer previously always fell back to empty here.
            if uc.get("_is_custom") and uc.get("keywords"):
                kw_weights = {kw: 2.5 for kw in uc["keywords"]}
            else:
                kw_weights = CONTROL_KEYWORDS.get(ctrl_id, {})
            controls.append({
                "control": ctrl_id,
                "label": uc["label"],
                "expected": _get_expected_evidence(uc, custom_evidence),
                "prompt_hint": uc["prompt_hint"],
                "severity": uc.get("severity", "MEDIUM"),
                "standard": uc.get("standard", ""),
                "recommendation": uc.get("recommendation", ""),
                "keywords": kw_weights,
            })
    return controls


def get_num_ctx(model_name: str) -> int:
    name = model_name.lower()
    if "12b" in name:
        return 8192
    if any(x in name for x in ["7b", "8b", "9b", "27b"]):
        return 8192
    if "3b" in name:
        return 4096
    if "e4b" in name:
        return 32768  # server runs -c 32768 → full 32k context available per request
    return 4096

def _generate_context_summary(context, llm_model):
    """Generates a brief document scope summary using the configured LLM backend.
    Routes through query_llm() so it correctly uses llama.cpp or Ollama.
    Hard timeout of 15s — skips gracefully if LLM is unresponsive."""
    import re
    files = re.split(r'--- FILE: (.*?) ---', context)
    sample_text = ""
    if len(files) > 1:
        for idx in range(1, len(files), 2):
            fname = files[idx]
            fcontent = files[idx+1] if idx+1 < len(files) else ""
            sample_text += f"FILE: {fname}\n{fcontent.strip()[:1000]}\n\n"
    else:
        sample_text = context[:8000]

    sample_text = sample_text[:8000]   # Keep prompt short for fast response

    summary_prompt = f"""You are a forensic compliance auditor assistant.
Analyze the following document beginning text and extract its overall scope:
1. What is the main purpose of this document?
2. What are the key topics it covers?
3. What does it explicitly state it does NOT cover (exclusions)?

Keep your response brief, under 150 words.

--- START DOCUMENT TEXT ---
{sample_text}
--- END DOCUMENT TEXT ---

Output:"""

    try:
        from src.core.llm_client import query_llm
        # Use query_llm which correctly routes to llama.cpp or Ollama
        summary = query_llm(
            prompt=summary_prompt,
            model=llm_model,
            num_ctx=get_num_ctx(llm_model),
            temperature=0.0,
            timeout=1800   # 1800s (30 mins) timeout for 3-pass LLM reasoning, OCR, and multi-user queueing



        )
        return summary if summary.strip() else "Document scope summary unavailable."
    except Exception as e:
        print(f"[CONTEXT SUMMARY] Skipped (LLM unavailable or timeout): {e}", flush=True)
        return "Document scope summary unavailable (LLM not ready)."

def _checkpoint_create(session_id, bg_key, ai_model, selected_sls, file_names, context_str, total_controls, batch_size):
    with force_master():
        db = SessionLocal()
        try:
            # Only discard checkpoints for THIS session — other sessions' checkpoints stay intact
            db.query(AuditCheckpoint).filter(
                AuditCheckpoint.session_id == session_id,
                AuditCheckpoint.status.in_(["in_progress", "failed", "paused", "interrupted"])
            ).update({AuditCheckpoint.status: "discarded"}, synchronize_session=False)

            db.query(AuditCheckpoint).filter(
                AuditCheckpoint.session_id == session_id
            ).delete(synchronize_session=False)

            chk = AuditCheckpoint(
                session_id=session_id,
                bg_key=bg_key,
                ai_model=ai_model,
                selected_sls_json=json.dumps(list(selected_sls)),
                file_names_json=json.dumps(file_names),
                context_text=context_str,
                total_controls=total_controls,
                completed_batches=0,
                batch_size=batch_size,
                partial_results_json="[]",
                status="in_progress",
            )
            db.add(chk)
            db.commit()
            chk_id = chk.id
            return chk_id
        except Exception as e:
            print(f"[checkpoint] Failed to create checkpoint: {e}", flush=True)
            return None
        finally:
            db.close()

def _checkpoint_update(session_id, completed_batches, all_results_so_far):
    """Legacy batch-level checkpoint update — kept for compatibility."""
    with force_master():
        db = SessionLocal()
        try:
            chk = db.query(AuditCheckpoint).filter(
                AuditCheckpoint.session_id == session_id,
                AuditCheckpoint.status.in_(["in_progress", "paused"])
            ).first()
            if chk:
                chk.completed_batches = completed_batches
                chk.partial_results_json = json.dumps(all_results_so_far)
                chk.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
                db.commit()
        except Exception as e:
            print(f"[checkpoint] Failed to update checkpoint: {e}", flush=True)
        finally:
            db.close()

def _checkpoint_update_per_control(session_id, control_id, all_results_so_far):
    """
    Per-control granular checkpoint.
    Called after EVERY single control is evaluated (~3ms overhead).
    Saves:
      - completed_controls: integer count
      - completed_control_ids_json: JSON list of control IDs already done
      - partial_results_json: full results so far (for resume)
    On resume, any control whose ID is in completed_control_ids_json is SKIPPED.
    """
    with force_master():
        db = SessionLocal()
        try:
            chk = db.query(AuditCheckpoint).filter(
                AuditCheckpoint.session_id == session_id,
                AuditCheckpoint.status.in_(["in_progress", "paused"])
            ).first()
            if chk:
                # Parse existing completed IDs and add new one
                try:
                    done_ids = json.loads(chk.completed_control_ids_json or "[]")
                except Exception:
                    done_ids = []
                if control_id and control_id not in done_ids:
                    done_ids.append(control_id)
                chk.completed_controls = len(done_ids)
                chk.completed_control_ids_json = json.dumps(done_ids)
                chk.partial_results_json = json.dumps(all_results_so_far)
                chk.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
                db.commit()
                print(
                    f"[CHECKPOINT] Control '{control_id}' saved "
                    f"({len(done_ids)}/{chk.total_controls} done)",
                    flush=True
                )
        except Exception as e:
            print(f"[checkpoint] Per-control update failed for '{control_id}': {e}", flush=True)
        finally:
            db.close()


def _checkpoint_finish(session_id, status="completed"):
    with force_master():
        db = SessionLocal()
        try:
            chk = db.query(AuditCheckpoint).filter(
                AuditCheckpoint.session_id == session_id,
                AuditCheckpoint.status.in_(["in_progress", "failed", "paused", "interrupted"])
            ).first()
            if chk:
                chk.status = status
                chk.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
                db.commit()
        except Exception as e:
            print(f"[checkpoint] Failed to finish checkpoint: {e}", flush=True)
        finally:
            db.close()

def get_resumable_checkpoint(session_id):
    # force_master() for read-after-write consistency -- this is checked right after
    # a checkpoint write (crash detection on restart), and without pinning to master
    # a lagging replica read could report "nothing to resume" even though the
    # checkpoint was just committed, defeating the one scenario this exists for.
    with force_master():
        db = SessionLocal()
        try:
            return db.query(AuditCheckpoint).filter(
                AuditCheckpoint.session_id == session_id,
                AuditCheckpoint.status.in_(["in_progress", "failed", "paused", "interrupted"])
            ).order_by(AuditCheckpoint.created_at.desc()).first()
        except Exception as e:
            print(f"[checkpoint] Failed to get checkpoint: {e}", flush=True)
            return None
        finally:
            db.close()

def get_global_resumable_checkpoint():
    with force_master():
        db = SessionLocal()
        try:
            return db.query(AuditCheckpoint).filter(
                AuditCheckpoint.status.in_(["in_progress", "failed", "paused", "interrupted"])
            ).order_by(AuditCheckpoint.created_at.desc()).first()
        except Exception as e:
            print(f"[checkpoint] Failed to get global checkpoint: {e}", flush=True)
            return None
        finally:
            db.close()

def generate_ollama_findings(context, file_names_list, selected_sls, model_choice, bg_key=None, batch_size=None, checkpoint_session_id=None, audit_mode="Deep", custom_docs=None, custom_evidence=None, file_registry=None, already_done_ids=None, username=None):
    os.environ["RAG_RERANK_MODE"] = "quick" if "quick" in str(audit_mode).lower() else "deep"
    llm_model = _resolve_llm_model(model_choice)
    controls = _build_controls_for_audit(selected_sls, custom_evidence)
    scanned_files_str = ", ".join(file_names_list) if file_names_list else "None"

    # Resolved once and threaded into every control's graph state below, so
    # retrieval can scope document_chunks reads/writes to THIS session's own
    # report_id -- without it, two sessions uploading identically-named files
    # collide in the shared, session-agnostic document_chunks table (see
    # save_document_chunks / _vec_native_search).
    report_id_for_retrieval = None
    if checkpoint_session_id:
        try:
            with force_master():
                _rid_session = SessionLocal()
                _rid_report = _rid_session.query(AuditReport).filter(
                    AuditReport.session_id == checkpoint_session_id
                ).first()
                report_id_for_retrieval = _rid_report.id if _rid_report else None
                _rid_session.close()
        except Exception as _rid_err:
            print(f"[REPORT ID RESOLVE] Failed to resolve report_id for {checkpoint_session_id}: {_rid_err}", flush=True)

    # ── On RESUME: restore already-completed results from checkpoint and skip those controls ──
    _already_done_set = set(already_done_ids or [])
    if _already_done_set:
        print(
            f"[RESUME] Skipping {len(_already_done_set)} already-completed controls: {sorted(_already_done_set)}",
            flush=True
        )

    # ── SCOPING MODE DETERMINATION & ISOLATION ─────────────────────────────
    # Mode 1: EXCEL UPLOAD SCOPE (custom_evidence provided from uploaded Excel checklist)
    # Mode 2: CUSTOM / MANUAL SCOPE (user manually selected specific subset of controls < 30)
    # Mode 3: AI AUTO-SCOPING (full control pool scan; runs Evidence-First topic pre-filter)
    is_excel_scope = custom_evidence is not None
    is_manual_scope = (selected_sls is not None and len(selected_sls) < 30)

    is_auto_scoping = (not is_excel_scope) and (not is_manual_scope) and (
        "auto" in str(audit_mode).lower() or 
        "scope" in str(audit_mode).lower() or 
        selected_sls is None or 
        len(controls) >= 30
    )

    filtered_controls = []
    out_of_scope_results = []

    if is_auto_scoping:
        import re
        from src.core.llm_client import query_llm

        def _extract_topics_llm(file_names_list, context_text):
            """Extract security topics from evidence using LLM (file names + per-file snippets)."""
            file_summaries = []
            chunks = context_text.split("\n\n") if context_text else []
            fnames = file_names_list or []
            for i, fname in enumerate(fnames):
                snippet = (chunks[i][:300] if i < len(chunks) else "").replace("\n", " ").strip()
                file_summaries.append(f"FILE: {fname}\nCONTENT: {snippet}")
            files_block = "\n\n".join(file_summaries) if file_summaries else context_text[:2000]

            prompt = f"""You are a security auditor assistant. Below are evidence files for an ISO 27001 audit.
Extract the specific security topics these files cover.
Rules:
- Return ONLY a JSON array of short topic strings (1-4 words each)
- Cover ALL files listed
- Focus on: authentication, access control, logging, NTP/clock, cloud, backup, encryption, fraud, monitoring
- Maximum 20 topics, no duplicates
- No explanation, just the JSON array

Evidence Files:
{files_block}

Return format: ["topic1", "topic2", ...]"""

            try:
                response = query_llm(
                    prompt, model=llm_model, num_ctx=4096, temperature=0.0, timeout=1800,


                    stop=["<end_of_turn>", "<eos>", "<|im_end|>", "</s>"]
                )
                if not response:
                    return []
                match = re.search(r'\[.*?\]', response, re.DOTALL)
                if match:
                    topics = __import__("json").loads(match.group())
                    return [t.lower().strip() for t in topics if isinstance(t, str)]
                lines = [l.strip().strip('"\'').strip('-').strip() for l in response.splitlines() if l.strip()]
                return [l.lower() for l in lines if 2 < len(l) < 60 and not l.startswith('{')]
            except Exception as e:
                print(f"[AI AUTO-SCOPE] LLM topic extraction failed: {e}", flush=True)
                return []

        def _ctrl_prefix(ctrl_str):
            parts = ctrl_str.strip().split()
            return parts[0] if parts else ctrl_str

        print(f"[AI AUTO-SCOPE] Starting Evidence-First scoping for {len(controls)} controls...", flush=True)
        topics = _extract_topics_llm(file_names_list, context or "")

        if topics:
            print(f"[AI AUTO-SCOPE] LLM extracted topics: {topics}", flush=True)
            matched_ids = set()
            for topic in topics:
                for key, ctrl_ids in TOPIC_CONTROL_MAP.items():
                    if key in topic or topic in key:
                        matched_ids.update(ctrl_ids)

            for c in controls:
                prefix = _ctrl_prefix(c["control"])
                if prefix in matched_ids:
                    filtered_controls.append(c)
                else:
                    out_of_scope_results.append({
                        "control_id": c["control"], "control": c["label"],
                        "relevance_score": 0, "evidence_found": "Not Relevant",
                        "evidence_snippet": "", "status": "Out of Scope", "severity": "N/A",
                        "finding": "Control does not apply to this document scope",
                        "recommendation": "",
                        "reasoning": f"AI Evidence-First Scoping: topics {topics} did not match this control.",
                        "source_files": scanned_files_str,
                    })
            print(f"[AI AUTO-SCOPE] Evidence-First filtered {len(controls)} → {len(filtered_controls)} controls.", flush=True)

            if not filtered_controls:
                print(f"[AI AUTO-SCOPE] WARNING: 0 controls matched map. Running keyword fallback.", flush=True)
                stopwords = {"whether","is","are","the","and","for","with","available","enabled","done","used","audit","evidence","check","system","information","security","management","policies","policy","shall","should","must","will","has","have","been","that","this","also","from","into","their","which","data","user","users","access","control","controls","process","processes","document","documents","record","records","activity","activities","include","including","ensure","required","requirement","requirements","related","relevant","review","reviews","update","updates","implement","implementation","define","defined","maintain","maintained","establish","established","appropriate","effective","internal","external","based","provide","provided","all","each","other","any","not","only","such","may","its","use","organization","asset","assets","risk","risks","measure","measures","protect","protection"}
                full_text = (str(context or "") + " " + " ".join(file_names_list or [])).lower()
                out_of_scope_results = []
                for c in controls:
                    combined = (c.get("label","") + " " + c.get("expected","") + " " + c.get("prompt_hint","")).lower()
                    phrases = re.findall(r'\b[a-z]{5,}(?:\s+[a-z]{4,}){1,3}\b', combined)
                    phrases = [p for p in phrases if not any(w in stopwords for w in p.split())]
                    single_kw = [w for w in set(re.findall(r'\b[a-z]{7,}\b', combined)) if w not in stopwords]
                    score = sum(3 for p in phrases if p in full_text) + sum(1 for w in single_kw if w in full_text)
                    if score >= 3:
                        filtered_controls.append(c)
                    else:
                        out_of_scope_results.append({
                            "control_id": c["control"], "control": c["label"],
                            "relevance_score": score, "evidence_found": "Not Relevant",
                            "evidence_snippet": "", "status": "Out of Scope", "severity": "N/A",
                            "finding": "Control does not apply to this document scope",
                            "recommendation": "",
                            "reasoning": f"Safety net keyword fallback: score {score} < 3.",
                            "source_files": scanned_files_str,
                        })
                print(f"[AI AUTO-SCOPE] Safety net keyword: {len(filtered_controls)} controls matched.", flush=True)
        else:
            print(f"[AI AUTO-SCOPE] LLM unavailable — using keyword fallback.", flush=True)
            import re
            stopwords = {"whether","is","are","the","and","for","with","available","enabled","done","used","audit","evidence","check","system","information","security","management","policies","policy","shall","should","must","will","has","have","been","that","this","also","from","into","their","which","data","user","users","access","control","controls","process","processes","document","documents","record","records","activity","activities","include","including","ensure","required","requirement","requirements","related","relevant","review","reviews","update","updates","implement","implementation","define","defined","maintain","maintained","establish","established","appropriate","effective","internal","external","based","provide","provided","all","each","other","any","not","only","such","may","its","use","organization","asset","assets","risk","risks","measure","measures","protect","protection"}
            full_text = (str(context or "") + " " + " ".join(file_names_list or [])).lower()
            for c in controls:
                combined = (c.get("label","") + " " + c.get("expected","") + " " + c.get("prompt_hint","")).lower()
                phrases = re.findall(r'\b[a-z]{5,}(?:\s+[a-z]{4,}){1,3}\b', combined)
                phrases = [p for p in phrases if not any(w in stopwords for w in p.split())]
                single_kw = [w for w in set(re.findall(r'\b[a-z]{7,}\b', combined)) if w not in stopwords]
                score = sum(3 for p in phrases if p in full_text) + sum(1 for w in single_kw if w in full_text)
                if score >= 5:
                    filtered_controls.append(c)
                else:
                    out_of_scope_results.append({
                        "control_id": c["control"], "control": c["label"],
                        "relevance_score": score, "evidence_found": "Not Relevant",
                        "evidence_snippet": "", "status": "Out of Scope", "severity": "N/A",
                        "finding": "Control does not apply to this document scope",
                        "recommendation": "",
                        "reasoning": f"Keyword fallback: score {score} below threshold 5.",
                        "source_files": scanned_files_str,
                    })

        if filtered_controls:
            print(f"[AI AUTO-SCOPE] Final: {len(filtered_controls)} controls will be audited by LLM.", flush=True)
            controls = filtered_controls
            all_results = out_of_scope_results
        else:
            print(f"[AI AUTO-SCOPE] ULTIMATE SAFETY NET: All filters returned 0 — auditing ALL {len(controls)} controls.", flush=True)
            all_results = []
    else:
        print(f"[MANUAL/EXCEL SCOPE] Auditing all {len(controls)} controls selected by user/Excel checklist without auto-scoping pre-filter.", flush=True)
        all_results = []





    if not controls:
        all_results = []
        for uc in USE_CASES:
            all_results.append({
                "control_id": uc["use_case"],
                "control": uc["label"],
                "relevance_score": 0,
                "evidence_found": "Not Relevant",
                "evidence_snippet": "",
                "status": "Out of Scope",
                "severity": "N/A",
                "finding": "Control does not apply to this document type",
                "recommendation": "",
                "reasoning": "Control is out of scope for the detected document type.",
                "source_files": scanned_files_str,
            })
        return [], all_results

    all_results = []
    # ── RESUME: restore already-completed results from the checkpoint ─────────
    # Without this, resuming correctly SKIPS re-running already-done controls
    # (see _already_done_set below) but their prior results were never re-added
    # to all_results, so the final saved report only ever contained controls
    # processed after the resume point -- the pre-crash work vanished from the
    # output even though it was never actually lost from the checkpoint itself.
    if already_done_ids and checkpoint_session_id:
        try:
            with force_master():
                _resume_session = SessionLocal()
                _resume_chk = (
                    _resume_session.query(AuditCheckpoint)
                    .filter(AuditCheckpoint.session_id == checkpoint_session_id)
                    .order_by(AuditCheckpoint.created_at.desc())
                    .first()
                )
                _resume_session.close()
            if _resume_chk and _resume_chk.partial_results_json:
                restored = json.loads(_resume_chk.partial_results_json)
                if isinstance(restored, list):
                    all_results = restored
                    print(
                        f"[RESUME] Restored {len(all_results)} already-completed result(s) "
                        f"from checkpoint for session {checkpoint_session_id}.",
                        flush=True
                    )
        except Exception as e:
            print(f"[RESUME] Failed to restore partial results from checkpoint: {e}", flush=True)
    total = len(controls)
    overall_start_time = time.time()
    _audit_real_prompt_toks = 0
    _audit_real_comp_toks = 0

    # ── Busy-system notice (warning only, never blocks) ────────────────────────
    # Measured directly: 2 concurrent audits on a 12-core machine ran ~1.7-2x
    # slower each (still genuinely parallel, not queued -- see
    # qa/checkpointing/test_concurrent_sessions.py). At 2+ already running,
    # tell the auditor to expect a slower run instead of leaving them guessing
    # why it's taking longer than usual.
    try:
        from src.core.redis_metrics import get_running_session_count
        _running_now = get_running_session_count()
    except Exception:
        _running_now = 0
    # _running_now includes this audit itself (session_start() already ran for
    # it before this point), so "other" audits = _running_now - 1.
    _other_running = max(0, _running_now - 1)
    _busy_warning = (
        f"⚠️ System is busy — {_other_running} other audit(s) running, this may take longer than usual."
        if _other_running >= 1 else None
    )

    msg = f"[AUDIT START] Starting LangGraph ISO 27001 Audit for {total} controls (Model: {model_choice}, Mode: {audit_mode})"
    print(f"\n[{time.strftime('%H:%M:%S')}] {msg}", flush=True)
    log_dev_latency(msg)

    # Generate context summary
    summary_text = _generate_context_summary(context, llm_model)

    # ── Universal Pre-Ingest for Top 6 RAG Vector Retrieval across ALL Scoping Modes (Manual, AI Auto-Scoping, Excel) ──
    if file_registry:
        for fname, ftext in file_registry.items():
            if fname and ftext:
                try:
                    save_document_chunks(fname, ftext, report_id=report_id_for_retrieval)
                except Exception as _e_ingest:
                    print(f"[RAG INGEST WARNING] Pre-ingest for '{fname}' failed: {_e_ingest}", flush=True)

    was_resource_paused = False

    for idx, c in enumerate(controls):
        # ── STOP FLAG CHECK ─────────────────────────────────────────────
        if _bg_stop_flags.get(bg_key) or (checkpoint_session_id and _bg_stop_flags.get(checkpoint_session_id)):

            print(f"[AUDIT STOPPED] User requested stop at control {idx + 1}/{total}. Exiting early.", flush=True)
            break
        # ────────────────────────────────────────────────────────────────


        # ── RESOURCE GUARD: stop gracefully (not crash) if RAM gets critical ──
        # Checked every control, not just at audit start — a long-running audit
        # can outlive the memory conditions it started under (other processes,
        # other concurrent audits). Already-completed controls stay checkpointed;
        # the rest can be resumed later via the existing resume-checkpoint path.
        from src.core.resource_guard import check_memory_pressure
        _mem = check_memory_pressure()
        if _mem["status"] == "CRITICAL":
            print(f"[RESOURCE GUARD] CRITICAL memory pressure at control {idx + 1}/{total}: {_mem['reason']} Stopping audit gracefully.", flush=True)
            was_resource_paused = True
            if bg_key:
                with _bg_lock:
                    _bg_store["progress"][bg_key] = {
                        "text": f"Paused: system resources critically low ({_mem['available_gb']}GB RAM available). "
                                f"Completed {idx}/{total} controls — resume once resources free up.",
                        "percent": int((idx / total) * 100),
                        "resource_status": "CRITICAL",
                    }
            break
        # ────────────────────────────────────────────────────────────────

        # ── PER-CONTROL RESUME: skip controls already saved in checkpoint ─
        _ctrl_id_str = c.get("control", "")
        if _ctrl_id_str in _already_done_set:
            print(
                f"[RESUME SKIP] Control {idx + 1}/{total}: '{_ctrl_id_str}' already completed — skipping.",
                flush=True
            )
            # Update progress bar so UI shows correct % even for skipped controls
            if bg_key:
                pct = int(((idx + 1) / total) * 100)
                with _bg_lock:
                    _bg_store["progress"][bg_key] = {
                        "text": f"Resuming: {idx + 1}/{total} controls (skipping already done)...",
                        "percent": pct
                    }
            continue
        # ─────────────────────────────────────────────────────────────────

        control_start_time = time.time()
        start_msg = f"-> Running Control {idx + 1}/{total}: {c['control']} ({c['label']})"
        print(f"[{time.strftime('%H:%M:%S')}]   {start_msg}", flush=True)
        log_dev_latency(f"[{idx + 1}/{total}] {start_msg}")


        # ── Strict Scoping: 1 control → 1 specific evidence file ─────────────
        # When an Excel scope sheet maps a control to a specific evidence file,
        # ONLY that file (+ shared policy docs) should be audited for that control.
        # This prevents evidence bleed across controls (e.g. MFA screenshots
        # appearing as evidence for Clock Sync or Capacity Management).
        control_context = context
        control_file_names = file_names_list
        target_evidence_files = []   # Track which specific evidence files this control maps to
        matched_policy_files = []    # Locked files that came from a Policy-named column
        matched_evidence_only_files = []  # Locked files that came from an Evidence-only column
        # Set when this is an Excel-checklist row with NO evidence file mapped to it
        # (either no file referenced at all, or the referenced file wasn't found among
        # uploads). Previously this silently widened control_file_names to the WHOLE
        # session's files instead of correctly reporting "no evidence" -- meaning an
        # unmapped row could cite a file that was never authorized for that control,
        # and did so with source_files left blank (no way to trace which file it used).
        # Handled below: skips retrieval and the LLM call entirely for this control.
        excel_no_evidence_mapped = False

        def _match_control_key(c_id, docs_source):
            if not c_id or not docs_source: return None
            if c_id in docs_source: return docs_source[c_id]
            import re
            def _clean(s): return re.sub(r'[^a-z0-9]', '', str(s).lower())
            clean_cid = _clean(c_id)
            for k, v in docs_source.items():
                clean_k = _clean(k)
                if clean_cid and clean_k and (clean_cid in clean_k or clean_k in clean_cid):
                    return v
            num_cid = re.sub(r'[^0-9\.]', '', str(c_id)).strip('.')
            for k, v in docs_source.items():
                num_k = re.sub(r'[^0-9\.]', '', str(k)).strip('.')
                if num_cid and num_k and (num_cid == num_k or num_cid.endswith('.' + num_k) or num_k.endswith('.' + num_cid)):
                    return v
            return None

        target_doc_name = None
        docs_source = custom_docs if custom_docs is not None else {}

        # ── Row-level file identity (Excel scoping) ───────────────────────────
        # _build_controls_for_audit() already resolves the exact matched file for
        # THIS specific checklist row (evidence_source_file). Prefer that over a
        # lookup in custom_docs, which is keyed by control ID/label and therefore
        # MERGES files from every row that happens to share the same ISO control
        # (e.g. a "PAM access" row and a separate "Authentication method" row
        # both resolving to 5.15 Access Control). Using the merged blob here
        # would make both rows cite both files instead of keeping each row's
        # evidence scoped to only the file listed against it on the sheet.
        row_specific_file = c.get("evidence_source_files_all") or c.get("evidence_source_file")
        if row_specific_file:
            target_doc_name = row_specific_file
        elif docs_source:
            target_doc_name = _match_control_key(c["control"], docs_source)

        # This checklist row has no evidence file referenced at all. Previously fell
        # through to the "no Excel scoping for this control" comment below, which left
        # control_file_names at its default of the FULL session file list -- searching
        # every other uploaded file instead of correctly reporting no evidence.
        if not target_doc_name and is_excel_scope:
            excel_no_evidence_mapped = True
            control_file_names = []
            control_context = ""

        if target_doc_name:
            # Normalise filenames for fuzzy matching (strip extension + punctuation)
            def _norm_fn(s):
                if not s: return ""
                s_no_ext = os.path.splitext(s)[0]
                import re as _re
                return _re.sub(r'[^a-z0-9]', '', s_no_ext.lower())

            # ── Step A: Find which uploaded files are mapped to ANY control in Excel.
            # Unmapped files are shared policy documents that apply to all controls.
            all_mapped_norms = set()
            for mapped_v in docs_source.values():
                all_mapped_norms.add(_norm_fn(mapped_v))

            policy_doc_files = []   # Files not mapped to any control = shared policy docs
            for fname in file_names_list:
                norm_fname = _norm_fn(fname)
                is_any_mapped = any(
                    norm_fname and nm and (norm_fname in nm or nm in norm_fname)
                    for nm in all_mapped_norms
                )
                if not is_any_mapped:
                    policy_doc_files.append(fname)

            # ── Step B: Match the specific evidence file(s) for THIS control.
            # target_doc_name may list several comma-joined file refs (a multi-file
            # row, or the legacy control-ID-keyed merge). Match each ref on its own
            # instead of substring-matching the whole joined blob at once — joining
            # first and searching second lets one filename's normalized form land
            # as a literal prefix of a DIFFERENT file's normalized form (e.g.
            # "..._AUA_DB" is a prefix of "..._AUA_D_B_0_32" once separators are
            # stripped), which pulled in the wrong file. Per-ref matching also
            # tries an EXACT normalized match before falling back to substring
            # containment, which avoids that same prefix collision.
            def _match_refs(refs_str):
                refs = [r.strip() for r in str(refs_str or "").split(",") if r.strip()]
                out = []
                for ref in refs:
                    norm_ref = _norm_fn(ref)
                    if not norm_ref:
                        continue
                    exact_hit = next((fname for fname in file_names_list if _norm_fn(fname) == norm_ref), None)
                    if exact_hit:
                        if exact_hit not in out:
                            out.append(exact_hit)
                        continue
                    for fname in file_names_list:
                        norm_fname = _norm_fn(fname)
                        if norm_fname and (norm_ref in norm_fname or norm_fname in norm_ref):
                            if fname not in out:
                                out.append(fname)
                return out

            matched_files = _match_refs(target_doc_name)

            # ── Column-source split (which locked files came from a Policy-named
            # column vs an Evidence-named column on the sheet, if any) -- lets the
            # LLM be told the auditor's own intent instead of re-deriving the
            # policy/evidence split blind from undifferentiated locked text.
            matched_policy_files = _match_refs(c.get("policy_source_files_all"))
            matched_evidence_only_files = _match_refs(c.get("evidence_only_source_files_all"))

            reg_source = file_registry if file_registry is not None else {}

            if matched_files:
                # PRIMARY context: ONLY the evidence file mapped to this control.
                matched_texts = [reg_source.get(fname, "") for fname in matched_files if reg_source.get(fname)]
                # SECONDARY context: shared policy documents (not evidence-mapped to any control)
                # e.g. an ISO policy.docx uploaded alongside evidence screenshots.
                policy_texts = [reg_source.get(f, "") for f in policy_doc_files if reg_source.get(f)]
                all_context_parts = matched_texts + policy_texts
                if all_context_parts:
                    control_context = "\n\n".join(all_context_parts)
                # STRICT: RAG searches ONLY the matched evidence file + policy docs.
                # This guarantees that e.g. NTP screenshots are never searched for MFA controls.
                control_file_names = matched_files + policy_doc_files
                target_evidence_files = matched_files   # Used for source_files provenance below
                print(
                    f"[SCOPING] Control {c['control']}: "
                    f"Evidence={matched_files}, Policy docs={policy_doc_files}, "
                    f"RAG pool={len(control_file_names)} files (strict — no bleed)",
                    flush=True
                )
            else:
                # Mapped file not found among uploads. Previously fell back to
                # searching every other uploaded file (see removed comment below) --
                # that meant a checklist typo/missing-upload silently pulled in
                # content never authorized for this control instead of surfacing the
                # mismatch. Now treated the same as "no evidence mapped": no
                # retrieval, no LLM call, flagged for human review.
                _scoping_fallback_msg = (
                    f"Control {c['control']}: Excel checklist targets '{target_doc_name}' "
                    f"but that file is not among the uploaded evidence {file_names_list}. "
                    f"Marking as no evidence mapped instead of searching unrelated files."
                )
                print(f"[SCOPING WARNING] {_scoping_fallback_msg}", flush=True)
                log_system_event(
                    "SCOPING_FALLBACK", "WARNING", _scoping_fallback_msg,
                    session_id=checkpoint_session_id or bg_key
                )
                excel_no_evidence_mapped = True
                control_file_names = []
                control_context = ""

        # If no Excel scoping for this control (Manual Scope / AI Auto-Scoping),
        # control_file_names/control_context keep their defaults from above and
        # correctly search all uploaded files -- unchanged, by design.

        # Assemble graph inputs mapping exactly to LangGraph AuditState schema
        state_input = {
            "control_id": c["control"],
            "control_label": c["label"],
            "expected_evidence": c["expected"],
            "prompt_hint": c["prompt_hint"],
            "severity": c["severity"],
            "standard": c.get("standard", "ISO 27001:2022"),
            "recommendation": c.get("recommendation", ""),
            "keywords": c.get("keywords") or {},

            # Context & Config
            "document_text": control_context,
            "file_names_list": control_file_names,
            "llm_model": llm_model,
            "summary_text": summary_text,
            "report_id": report_id_for_retrieval,

            # State tracking
            "retrieved_context": "",
            "draft_finding": None,
            "validation_error": None,
            "retry_count": 0,
            "final_finding": None,
            "token_stats": {},

            # Progress tracking
            "bg_key": bg_key,
            "control_idx": idx,
            "total_controls": total,
            "audit_mode": audit_mode,
            "file_registry": file_registry or {},

            # ── Two-Phase Excel Scoping: pass locked_filenames if scoping is active ──
            # locked_filenames restricts Phase 1 retrieval to ONLY the matched file(s).
            # checklist_question is the original Excel audit check question text.
            "locked_filenames": target_evidence_files if target_evidence_files else [],
            "checklist_question": c.get("checklist_question") or c["label"],
            # Which of the locked files (if any) came from a Policy-named vs an
            # Evidence-named column on the sheet -- lets generate_node tell the LLM
            # the auditor's own intent instead of re-deriving the split blind.
            "policy_locked_filenames": matched_policy_files,
            "evidence_locked_filenames": matched_evidence_only_files,
        }
        
        if excel_no_evidence_mapped:
            # No retrieval, no LLM call -- there's nothing to search or evaluate.
            # Deterministic NON_COMPLIANT-for-human-review, matching the same
            # convention already used elsewhere for a genuine "evidence not found"
            # LLM result, but without spending 10-45 minutes of LLM time (and
            # without the risk of the LLM being handed unrelated session files)
            # to arrive at the same place.
            ctrl_duration = time.time() - control_start_time
            _no_evidence_msg = "No evidence file was mapped to this control in the uploaded Excel checklist."
            result = {
                "control_id": c["control"],
                "control_label": c["label"],
                "control": c["control"],
                "status": "NON_COMPLIANT",
                "severity": c.get("severity", "MEDIUM"),
                "finding": _no_evidence_msg,
                "description": _no_evidence_msg,
                "gap_detected": _no_evidence_msg,
                "evidence_found": "NOT_FOUND",
                "evidence_snippet": "",
                "source_files": "",
                "evidence_location": "",
                "recommendation": f"Map and upload evidence for {c['label']} in the audit checklist, then re-run this control.",
                "reasoning": (
                    "This checklist row had no evidence file mapped to it, so no retrieval or "
                    "LLM evaluation was performed -- flagged for human review instead of "
                    "searching other, unrelated files in this session."
                ),
                "policy_status": "NOT_FOUND",
                "policy_assessment": "NON_COMPLIANT",
                "evidence_status": "NOT_FOUND",
                "evidence_assessment": "NON_COMPLIANT",
                "final_result": "NON_COMPLIANT",
                "final_reason": _no_evidence_msg,
            }
            all_results.append(result)
            print(f"[{time.strftime('%H:%M:%S')}] [CONTROL EVALUATED] {c['control']} ({c['label']}) | Status: NON_COMPLIANT (no evidence mapped -- retrieval/LLM skipped) | Latency: {ctrl_duration:.1f}s | Tokens Used: 0", flush=True)
            log_dev_latency(f"[{idx + 1}/{total}] [NO EVIDENCE MAPPED] Control {c['control']} {c['label']} -- retrieval/LLM skipped ({ctrl_duration:.2f}s)")
        else:
            try:
                # Invoke LangGraph
                state_output = audit_graph.invoke(state_input)
                result = state_output.get("final_finding")
                if result:
                    # ── Excel Scoping Safety Gate (Phase 2 final correction) ─────────────
                    # Overrides N/A evidence and wrong-file citations structurally.
                    if target_evidence_files:
                        try:
                            from src.core.validator import apply_excel_scoping_safety_gate
                            retrieved_ctx = state_output.get("retrieved_context", "")
                            result = apply_excel_scoping_safety_gate(
                                finding=result,
                                locked_filenames=target_evidence_files,
                                retrieved_context=retrieved_ctx,
                                checklist_question=c.get("checklist_question") or c["label"]
                            )
                        except Exception as _sg_err:
                            print(f"[SAFETY GATE ERROR] {_sg_err}", flush=True)

                    # ── Evidence provenance fix ───────────────────────────────────────
                    # BUG FIX: source_files must ALWAYS reflect the Excel-mapped file.
                    # Previously: only overrode source_files when it was empty, allowing
                    # the validator to write the WRONG file (e.g. MFA doc for Capacity
                    # Management) when a fallback-pool search happened.
                    # Fix: if Excel strictly mapped this control to specific files, ALWAYS
                    # set source_files to those mapped files — ignore whatever the validator
                    # may have written from searching the wrong-pool fallback.
                    if target_evidence_files:
                        # Excel scoping is active → enforce the mapped file unconditionally.
                        result["source_files"] = ", ".join(target_evidence_files)
                    else:
                        # No Excel scoping → use whatever the validator set (or leave empty).
                        existing_src = result.get("source_files") or ""
                        if not existing_src.strip():
                            result["source_files"] = ""
                    all_results.append(result)
                ctrl_duration = time.time() - control_start_time
                res_status = result.get("status", "Unknown") if result else "None"

                c_mins = int(ctrl_duration // 60)
                c_secs = round(ctrl_duration % 60, 1)
                c_lat_str = f"{c_mins}m {c_secs}s" if c_mins > 0 else f"0m {c_secs}s"

                _real_token_stats = state_output.get("token_stats") or {}
                ctrl_p_toks = _real_token_stats.get("prompt_tokens", 0)
                ctrl_c_toks = _real_token_stats.get("completion_tokens", 0)
                ctrl_t_toks = ctrl_p_toks + ctrl_c_toks
                _audit_real_prompt_toks += ctrl_p_toks
                _audit_real_comp_toks += ctrl_c_toks

                print(f"[{time.strftime('%H:%M:%S')}] [CONTROL EVALUATED] {c['control']} ({c['label']}) | Status: {res_status} | Latency: {c_lat_str} ({ctrl_duration:.1f}s) | Tokens Used: {ctrl_t_toks:,} (Prompt: {ctrl_p_toks:,}, Completion: {ctrl_c_toks:,})", flush=True)
                log_dev_latency(f"[{idx + 1}/{total}] [SUCCESS] Control {c['control']} {c['label']} completed in {ctrl_duration:.2f}s ({c_lat_str}) | Tokens: {ctrl_t_toks:,}")
                # ── Redis: push per-control metrics live ─────────────────────────
                try:
                    _rm.push_control_metrics(
                        session_id=checkpoint_session_id or bg_key or _sid,
                        prompt_tokens=ctrl_p_toks,
                        comp_tokens=ctrl_c_toks,
                        latency_sec=ctrl_duration
                    )
                except Exception as _rpm_err:
                    pass  # Redis write failures never break an audit
            except Exception as e:
                print(f"[AUDIT ERROR] Error evaluating control {c['control']}: {e}", flush=True)
                log_dev_latency(f"ERROR: Control {c['control']} failed: {e}")
                # ── Redis: push error signal ─────────────────────────────────────
                try:
                    _rm.push_error(session_id=checkpoint_session_id or bg_key or _sid)
                except Exception:
                    pass

        # ── PER-CONTROL CHECKPOINT ─────────────────────────────────────────────
        # Save after EVERY control (~3ms). On crash, at most 1 control is re-run.
        if checkpoint_session_id:
            _checkpoint_update_per_control(
                checkpoint_session_id,
                c.get("control", ""),
                all_results
            )

        # Update progress bar
        if bg_key:
            pct = int(((idx + 1) / total) * 100)
            with _bg_lock:
                _bg_store["progress"][bg_key] = {
                    "text": f"Scanning: {idx + 1}/{total} controls...",
                    "percent": pct,
                    "warning": _busy_warning,
                }

        # Legacy batch checkpoint for backward compat (kept but superseded by per-control)
        if checkpoint_session_id and batch_size and (idx + 1) % batch_size == 0:
            completed_batches = (idx + 1) // batch_size
            _checkpoint_update(checkpoint_session_id, completed_batches, all_results)


    resolved_list = [r["control_id"] for r in all_results if (r.get("status") or "").upper() in ("COMPLIANT", "ACCEPTED", "PASS")]
    findings_list = [r for r in all_results if (r.get("status") or "").upper() not in ("COMPLIANT", "ACCEPTED", "PASS")]
    
    total_audit_time = time.time() - overall_start_time
    tot_mins = int(total_audit_time // 60)
    tot_secs = round(total_audit_time % 60, 1)
    tot_lat_str = f"{tot_mins}m {tot_secs}s" if tot_mins > 0 else f"0m {tot_secs}s"

    end_msg = f"[AUDIT COMPLETE] Evaluated {total} controls in {tot_lat_str} ({total_audit_time:.1f}s). Compliant: {len(resolved_list)}, Gaps: {len(findings_list)}"
    print(f"[{time.strftime('%H:%M:%S')}] {end_msg}\n", flush=True)
    log_dev_latency(end_msg)

    # Record benchmark metrics for Excel tracker & Terminal Summary Box
    try:
        from src.core.token_tracker import record_token_metrics
        text_chars = len(str(context or ""))
        total_file_bytes = 0
        file_details = []
        file_types_summary = {}

        if file_registry:
            for fname, fmeta in file_registry.items():
                sz = 0
                txt_c = 0
                if isinstance(fmeta, dict):
                    sz = fmeta.get("size_bytes", 0)
                    txt_c = len(fmeta.get("text", ""))
                elif isinstance(fmeta, str):
                    txt_c = len(fmeta)
                    sz = max(512, txt_c * 2)

                total_file_bytes += sz
                ext = os.path.splitext(str(fname))[1].lower().replace('.', '') or 'doc'
                file_types_summary[ext] = file_types_summary.get(ext, 0) + 1
                file_details.append({
                    "name": fname,
                    "ext": ext,
                    "size_bytes": sz,
                    "size_kb": round(sz / 1024, 1),
                    "char_count": txt_c
                })

        if not file_types_summary and file_names_list:
            for fn in file_names_list:
                ext = os.path.splitext(str(fn))[1].lower().replace('.', '') or 'doc'
                file_types_summary[ext] = file_types_summary.get(ext, 0) + 1

        if total_file_bytes == 0:
            total_file_bytes = max(1024, text_chars * 2)

        cpu_cores_cnt = os.cpu_count() or 4

        prompt_toks = _audit_real_prompt_toks
        comp_toks = _audit_real_comp_toks
        tot_tokens_all = prompt_toks + comp_toks
        avg_tokens_ctrl = round(tot_tokens_all / max(1, total), 1)

        avg_lat_sec = total_audit_time / max(1, total)
        avg_mins = int(avg_lat_sec // 60)
        avg_secs = round(avg_lat_sec % 60, 1)
        avg_lat_str = f"{avg_mins}m {avg_secs}s" if avg_mins > 0 else f"0m {avg_secs}s"
        
        mode_str = str(audit_mode).lower()
        if "excel" in mode_str or "manual" in mode_str:
            scoping_label = "Excel / Manual Scoping"
        elif "auto" in mode_str or "quick" in mode_str:
            scoping_label = "AI Auto-Scoping"
        else:
            scoping_label = "Excel / Manual Scoping"

        record_token_metrics(
            session_id=checkpoint_session_id or bg_key or "SESSION-LATEST",
            scoping_mode=scoping_label,
            file_names=file_names_list or ["Uploaded Evidence Documents"],
            total_file_size_bytes=total_file_bytes,
            extracted_text_chars=text_chars,
            controls_count=total,
            prompt_tokens=prompt_toks,
            completion_tokens=comp_toks,
            total_latency_sec=total_audit_time,
            compliant_count=len(resolved_list),
            non_compliant_count=len(findings_list),
            out_of_scope_count=len(out_of_scope_results) if 'out_of_scope_results' in locals() else 0,
            folder_name="Audit Evidence Package",
            cpu_cores=cpu_cores_cnt,
            file_details=file_details,
            file_types_summary=file_types_summary
        )

        total_files_cnt = len(file_names_list) if file_names_list else 0
        file_size_mb = round(total_file_bytes / (1024 * 1024), 2)
        file_size_kb = round(total_file_bytes / 1024, 1)
        total_text_chunks = len([c for c in str(context or "").split("\n\n") if len(c.strip()) > 20])
        if total_text_chunks == 0:
            total_text_chunks = max(1, int(text_chars / 500))

        file_types_str = ", ".join([f"{ext.upper()}: {cnt}" for ext, cnt in file_types_summary.items()]) if file_types_summary else "N/A"
        # Previously: getattr(locals().get("req", None), "auditor_username", None) or
        # os.environ.get("CURRENT_AUDITOR", "rk1@gmail.com") -- this function has no
        # local named "req" and CURRENT_AUDITOR is never set anywhere in the codebase,
        # so that always evaluated to the literal hardcoded fallback regardless of who
        # actually ran the audit. `username` is now a real parameter threaded down from
        # the authenticated request (api_start_audit -> _run_ollama_bg -> here).
        auditor_user = username or "Unknown Auditor"

        summary_box = f"""====================================================================================
 • Session ID                      : {checkpoint_session_id or bg_key or 'SESSION-LATEST'}
 • Auditor Username                : {auditor_user}
 • Scoping Detection Mode          : {scoping_label}
 • System CPU Hardware Specs       : {cpu_cores_cnt} Logical CPU Cores
 • Total Evidence Files Count      : {total_files_cnt} Files
 • File Extensions Breakdown       : {file_types_str}
 • Total Evidence File Size        : {file_size_mb} MB ({file_size_kb:,} KB)
 • Total Text Chunks Analyzed      : {total_text_chunks} Chunks ({text_chars:,} Chars)
 • Total Controls Evaluated        : {total}
 • Compliant Controls              : {len(resolved_list)}
 • Non-Compliant Gaps              : {len(findings_list)}
 • Prompt Input Tokens             : {prompt_toks:,} Tokens
 • Completion Output Tokens        : {comp_toks:,} Tokens
 • Total Audit Tokens Used         : {tot_tokens_all:,} Tokens
 • Average Tokens per Control      : {avg_tokens_ctrl:,} Tokens/Control
 • Overall Audit Latency           : {tot_lat_str} ({total_audit_time:.1f} seconds)
 • Average Latency per Control     : {avg_lat_str} ({avg_lat_sec:.1f} seconds/control)
====================================================================================
"""
        print("\n" + summary_box, flush=True)
        log_dev_latency(summary_box)

        # Write audit completion metrics to SystemEvent for Privacy-Safe Log Trail
        log_system_event(
            "AUDIT_COMPLETED", "INFO",
            f"Audit completed: {total} controls evaluated, "
            f"{len(resolved_list)} compliant, {len(findings_list)} non-compliant | "
            f"Tokens: {tot_tokens_all:,} (prompt: {prompt_toks:,}, completion: {comp_toks:,}) | "
            f"Latency: {tot_lat_str} | Files: {total_files_cnt} ({file_size_mb} MB) | "
            f"Scoping: {scoping_label}",
            session_id=checkpoint_session_id or bg_key or _sid,
            actor=auditor_user
        )

    except Exception as _bm_err:
        print(f"[BENCHMARK ERROR] Failed to record token metrics: {_bm_err}", flush=True)

    # ── Redis: mark session as done / paused ─────────────────────────────────
    try:
        _rm.session_done(session_id=checkpoint_session_id or bg_key or _sid, status="paused" if was_resource_paused else "done")
    except Exception:
        pass

    return resolved_list, findings_list, all_results, was_resource_paused

# No concurrency queue — audits run freely without waiting in line.
# The resource guard's check_memory_pressure() (called in /audit/start before
# this thread is even spawned) is the only gate: it refuses new audits when
# RAM is genuinely critically low (< 8% available), preventing OOM crashes.
# Without --mlock, the OS manages memory like a normal app (swap to disk when
# tight), so queuing is unnecessary — worst case is slower, never a crash.

def _run_ollama_bg(bg_key, files_data, selected_sls_copy, ai_model, session_id=None, audit_mode="Deep", custom_docs=None, custom_evidence=None, file_registry=None, already_done_ids=None, username=None):
    print(f"[_run_ollama_bg] Starting thread for key {bg_key} with model {ai_model}...", flush=True)
    _sid = session_id or bg_key
    try:


        # ── Pre-flight: verify LLM server is reachable (3s timeout) ──────────
        import os as _os
        import requests as _req
        from src.core.llm_client import get_llm_backend, _resolve_host, _ensure_llama_server_running
        _backend = get_llm_backend()
        _is_llamacpp = _backend in ("llama.cpp", "llamacpp")
        _llm_host = _resolve_host()
        _health_url = f"{_llm_host}/health" if _is_llamacpp else f"{_llm_host}/api/tags"
        _healthy = False
        try:
            _hr = _req.get(_health_url, timeout=3)
            if _hr.status_code in (200, 201):
                _healthy = True
                print(f"[_run_ollama_bg] LLM server health check OK ({_health_url}): {_hr.status_code}", flush=True)
        except Exception:
            pass

        if not _healthy and _is_llamacpp:
            _ensure_llama_server_running(11434)
            try:
                _hr = _req.get(_health_url, timeout=5)
                if _hr.status_code in (200, 201):
                    _healthy = True
                    print(f"[_run_ollama_bg] LLM server self-healed and online ({_health_url}): {_hr.status_code}", flush=True)
            except Exception:
                pass

        if not _healthy:
            _backend_label = "llama.cpp" if _is_llamacpp else "Ollama"
            _err_msg = (
                f"Cannot connect to {_backend_label} server at {_llm_host}. "
                "Please start the service before running audits."
            )
            print(f"[_run_ollama_bg ERROR] {_err_msg}", flush=True)
            log_system_event("LLM_OFFLINE_ERROR", "ERROR", _err_msg, session_id=_sid)
            with _bg_lock:
                _bg_store["progress"][bg_key] = {"text": f"Error: {_backend_label} offline", "percent": 0}
            _checkpoint_finish(_sid, "failed")
            return

        print(f"[_run_ollama_bg] Pipeline executing for session {_sid}...", flush=True)
        with _bg_lock:
            _bg_store["progress"][bg_key] = {
                "text": "🔍 Scanning file security...",
                "percent": 0
            }

        # Resolved once here and reused below -- scopes this session's chunk
        # ingestion so a same-named file uploaded under a different session
        # never collides with (deletes/overwrites) this session's own chunks.
        _report_id_for_ingest = None
        try:
            with force_master():
                _rid_session2 = SessionLocal()
                _rid_report2 = _rid_session2.query(AuditReport).filter(
                    AuditReport.session_id == _sid
                ).first()
                _report_id_for_ingest = _rid_report2.id if _rid_report2 else None
                _rid_session2.close()
        except Exception as _rid_err2:
            print(f"[REPORT ID RESOLVE] Failed to resolve report_id for {_sid}: {_rid_err2}", flush=True)

        ctx = ""
        file_names_list = []
        if file_registry is None:
            file_registry = {}
        for f_data in files_data:
            name = f_data["name"]
            file_bytes = f_data["bytes"]
            f_like = io.BytesIO(file_bytes)
            f_like.name = name
            # Full 4-layer scan — text is already extracted at this point (unlike the
            # upload-time scan), so Layer 4 (null-byte/oversized text) is also covered.
            is_clean, reason = scan_document(name, file_bytes, f_data.get("text") or "")
            if not is_clean:
                print(f"[_run_ollama_bg] Security alert! Malware scan failed for file {name}: {reason}", flush=True)
                log_system_event("MALWARE_BLOCKED", "CRITICAL", f"File blocked by security scan: {name} ({reason})", session_id=_sid)
                with _bg_lock:
                    _bg_results[bg_key] = {"error": f"🚨 SECURITY ALERT: '{name}' BLOCKED! {reason}"}
                    _bg_store["progress"].pop(bg_key, None)
                _checkpoint_finish(_sid, "failed")
                return

            text = f_data.get("text")
            if not text:
                text = extract_text(f_like)
                f_data["text"] = text
            file_registry[name] = text

            ctx += f"--- FILE: {name} ---\n{text}\n\n"
            save_document_chunks(name, text, report_id=_report_id_for_ingest)
            file_names_list.append(name)
        context_str = ctx.strip()

        # ── Redis: register session as started ───────────────────────────────
        try:
            _total_file_bytes_pre = sum(
                f_data.get("size_bytes", max(512, len(f_data.get("text", "")) * 2))
                for f_data in files_data
            )
            _file_mb_pre = round(_total_file_bytes_pre / (1024 * 1024), 3)
            _auditor_pre = username or "Unknown Auditor"
            _rm.session_start(
                session_id=_sid,
                auditor=_auditor_pre,
                files_count=len(file_names_list),
                file_mb=_file_mb_pre
            )
        except Exception as _rs_err:
            print(f"[Redis session_start ignored] {_rs_err}", flush=True)

        # Update scanned files to "Reviewing" in database
        try:
            with force_master():
                db_write = SessionLocal()
                db_write.query(EvidenceFile).filter(
                    EvidenceFile.filename.in_(file_names_list)
                ).update({EvidenceFile.status: "Processing"}, synchronize_session=False)
                db_write.commit()
                db_write.close()
        except Exception as e:
            print(f"[PIPELINE] Failed to update active files status to Reviewing: {e}", flush=True)

        # Was len(selected_sls_copy) -- the count of unique selected control IDs.
        # In Excel-scoping mode, one control ID can span multiple checklist rows
        # (e.g. two separate questions both filed under "8.5"), and the audit
        # loop (inside generate_ollama_findings) iterates per ROW via
        # _build_controls_for_audit(), not per unique control ID. Using the
        # unique-ID count here instead produced checkpoint displays like
        # "(7/6 done)" once more rows than the stated total had completed.
        # Purely a display value -- never used in any resume/completion
        # decision -- but confusing and worth matching reality. Re-derives the
        # same list generate_ollama_findings will build (cheap: no LLM calls,
        # just dict construction) so the two totals agree.
        # PERF: Build controls list once and take its len -- previously called
        # _build_controls_for_audit() a second time here solely for the count,
        # rebuilding the entire list just to get a display number.
        _controls_for_count = _build_controls_for_audit(selected_sls_copy, custom_evidence)
        _total_ctrl_count = len(_controls_for_count)
        _batch_sz = 1 if ("7B" in ai_model or "8B" in ai_model or "9B" in ai_model or "Escalation" in ai_model) else 4

        # On fresh start: create a new checkpoint.
        # On RESUME (already_done_ids provided): the checkpoint already exists — skip re-creation.
        _is_resume = bool(already_done_ids)
        if not _is_resume:
            _checkpoint_create(
                _sid, bg_key, ai_model,
                selected_sls_copy, file_names_list, context_str,
                _total_ctrl_count, _batch_sz
            )
        else:
            print(
                f"[RESUME] Checkpoint exists — skipping _checkpoint_create, "
                f"resuming from {len(already_done_ids)} already-done controls.",
                flush=True
            )

        with _bg_lock:
            _bg_store["progress"][bg_key] = {
                "text": f"Scanning controls with {ai_model.split(' - ')[0]}...",
                "percent": 0
            }

        res = generate_ollama_findings(
            context_str, file_names_list, selected_sls_copy, ai_model, bg_key=bg_key,
            checkpoint_session_id=_sid, audit_mode=audit_mode,
            custom_docs=custom_docs, custom_evidence=custom_evidence, file_registry=file_registry,
            already_done_ids=already_done_ids or [], username=username
        )
        if len(res) == 4:
            resolved_combined, findings_combined, all_results_combined, is_resource_paused = res
        else:
            resolved_combined, findings_combined, all_results_combined = res
            is_resource_paused = False

        resolved_mapping = {}
        for ctrl in resolved_combined:
            resolved_mapping[ctrl] = file_names_list
        for finding in findings_combined:
            finding["status"] = finding.get("status", "Non-Compliant")
            finding["comment"] = ""
            finding["editing"] = False
            
        with _bg_lock:
            _bg_results[bg_key] = {
                "findings": findings_combined,
                "resolved_list": resolved_combined,
                "resolved_count": len(resolved_mapping),
                "resolved_controls": set(resolved_mapping.keys()),
                "context": context_str
            }

        # Update scanned files to "Completed" and save results in database
        try:
            with force_master():
                db_write = SessionLocal()
                
                # 1. Update Evidence File statuses
                db_write.query(EvidenceFile).filter(
                    EvidenceFile.filename.in_(file_names_list)
                ).update({EvidenceFile.status: "Completed"}, synchronize_session=False)
                
                # 2. Retrieve report and insert findings (auto-create report if missing so findings are ALWAYS saved)
                report = db_write.query(AuditReport).filter(AuditReport.session_id == _sid).first()
                if not report:
                    report = AuditReport(
                        session_id=_sid,
                        session_title=f"Audit Scan {_sid[:14]}",
                        framework="ISO/IEC 27001:2022",
                        status="Pending Review"
                    )
                    db_write.add(report)
                    db_write.flush()


                # Clear existing findings for this report
                db_write.query(Finding).filter(Finding.report_id == report.id).delete()
                for f in all_results_combined:
                    f_desc = f.get("description") or f.get("finding") or f.get("gap_detected") or f.get("reasoning") or "Evaluated against ISO 27001 / VAPT compliance standards."
                    f_status = f.get("status", "Non-Compliant")
                    is_comp = (f_status or "").upper() in ("COMPLIANT", "ACCEPTED", "PASS")
                    f_recom = f.get("recommendation") or f.get("remediation") or (f"Maintain current documented policies and verification procedures for {f.get('control_id')}." if is_comp else f"Establish formal policy documentation, access controls, and logging evidence for {f.get('control_id')}.")

                    ev_loc = f.get("evidence_location") or f.get("evidence_source_file") or f.get("source_file") or ""
                    src_files = f.get("source_files") or ""

                    if not ev_loc and src_files:
                        ev_loc = src_files.split(",")[0].strip()

                    # If evidence location is a child image file, include parent document name
                    if ev_loc and src_files and ev_loc != src_files:
                        if ev_loc.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff")) and src_files not in ev_loc:
                            ev_loc = f"{src_files} ({ev_loc})"

                    raw_cid = str(f.get("control_id") or "")
                    raw_cname = str(f.get("control_label") or f.get("control") or raw_cid)

                    db_write.add(Finding(
                        report_id=report.id,
                        control_id=raw_cid[:98] if raw_cid else "ISO_CONTROL",
                        control_name=raw_cname[:198] if raw_cname else "ISO Control",
                        severity="N/A" if is_comp else f.get("severity", "P3 Medium"),
                        description=f_desc,
                        gap_detected=f_desc,
                        relevance_score=f.get("relevance_score", 0),
                        evidence_found=f.get("evidence_found", ""),
                        evidence_snippet=f.get("evidence_snippet", ""),
                        evidence_location=ev_loc,
                        evidence_source_file=ev_loc,
                        recommendation=f_recom,
                        reasoning=f.get("reasoning") or f_desc or "",
                        status="COMPLIANT" if is_comp else f_status,
                        policy_present=f.get("policy_present") or ("Compliant" if is_comp else "No"),
                        evidence_present=f.get("evidence_present") or ("Compliant" if is_comp else "No"),
                        source_files=f.get("source_files", ""),
                        # Policy vs Evidence split (RAG accuracy overhaul, Phase 5/6/7)
                        policy_status=f.get("policy_status"),
                        policy_assessment=f.get("policy_assessment"),
                        policy_name=f.get("policy_name"),
                        policy_version=f.get("policy_version"),
                        policy_clause=f.get("policy_clause"),
                        policy_effective_date=f.get("policy_effective_date"),
                        policy_review_date=f.get("policy_review_date"),
                        policy_expiry_date=f.get("policy_expiry_date"),
                        policy_validity=f.get("policy_validity"),
                        policy_finding=f.get("policy_finding"),
                        policy_gap=f.get("policy_gap"),
                        evidence_status=f.get("evidence_status"),
                        evidence_assessment=f.get("evidence_assessment"),
                        evidence_date=f.get("evidence_date"),
                        evidence_freshness=f.get("evidence_freshness"),
                        evidence_finding=f.get("evidence_finding"),
                        evidence_gap=f.get("evidence_gap"),
                        evidence_relevance=f.get("evidence_relevance"),
                        final_result=f.get("final_result"),
                        final_reason=f.get("final_reason")
                    ))

                # 3. Calculate score and update ComplianceScore
                db_write.query(ComplianceScore).filter(ComplianceScore.report_id == report.id).delete()
                in_scope = [f for f in all_results_combined if f.get("status")]
                compliant = [f for f in in_scope if (f.get("status") or "").upper() in ("COMPLIANT", "ACCEPTED", "PASS")]
                score_pct = int(len(compliant) / max(len(in_scope), 1) * 100) if in_scope else 0
                db_write.add(ComplianceScore(
                    report_id=report.id,
                    framework=report.framework,
                    score_percent=score_pct
                ))
                
                report.status = "Pending Review"
                # Commit and close INSIDE force_master() so writes go to the primary
                db_write.commit()
                db_write.close()

        except Exception as e:
            print(f"[PIPELINE] Failed to save findings and complete files update: {e}", flush=True)
            
        _checkpoint_finish(_sid, "paused" if is_resource_paused else "completed")
    except Exception as e:
        print(f"[_run_ollama_bg] Exception raised in background thread: {str(e)}", flush=True)
        log_system_event("AUDIT_EXCEPTION", "CRITICAL", f"Background audit thread exception: {str(e)}", session_id=_sid)
        with _bg_lock:
            _bg_results[bg_key] = {"error": f"Error contacting {BACKEND_NAME}: {str(e)}"}
        _checkpoint_finish(_sid, "failed")
    finally:
        with _bg_lock:
            _bg_running.discard(bg_key)
            _bg_store["progress"].pop(bg_key, None)
            _bg_stop_flags.pop(bg_key, None)  # Clear stop flag on thread exit

def _run_fast_technical_vapt_bg(bg_key, files_data, selected_sls, file_registry=None):
    all_findings = []
    resolved_ctrls = set()
    _seen_dedup_keys = set()
    try:
        from src.core.parsers import parse_tool_file, map_finding_to_control

        # Pre-seed dedup keys from whatever this session already saved in a PREVIOUS
        # run -- without this, re-running a scan on the same session (e.g. after
        # uploading more evidence) re-inserted every finding from files that were
        # already scanned before, since in-memory dedup alone only sees the current run.
        try:
            with force_master():
                _db_seed = SessionLocal()
                _existing_report = _db_seed.query(AuditReport).filter(AuditReport.session_id == bg_key).first()
                if _existing_report:
                    _existing_keys = _db_seed.query(Finding.dedup_key).filter(
                        Finding.report_id == _existing_report.id,
                        Finding.dedup_key.isnot(None)
                    ).all()
                    for (_ek,) in _existing_keys:
                        if _ek:
                            _seen_dedup_keys.add(_ek)
                _db_seed.close()
        except Exception as _seed_err:
            print(f"[VAPT DEDUP] Failed to pre-seed existing dedup keys: {_seed_err}", flush=True)

        for fd in files_data:
            fname = fd.get("name", "")
            ftext = fd.get("text", "")
            fname_lower = fname.lower()
            if fname_lower.endswith((".html", ".htm")) and fd.get("bytes"):
                try:
                    ftext = fd.get("bytes").decode("utf-8", errors="ignore")
                except Exception:
                    pass
            elif not ftext and fd.get("bytes"):
                try:
                    ftext = fd.get("bytes").decode("utf-8", errors="ignore")
                except Exception:
                    ftext = ""

            reg_text = (file_registry or {}).get(fname, "")
            if reg_text and len(reg_text) > len(ftext or ""):
                ftext = reg_text

            actionable, info = parse_tool_file(fname, ftext or "")
            combined_tool_findings = actionable + (info or [])

            for f in combined_tool_findings:
                # Skip exact-duplicate findings (same CVE, or same tool+plugin_id, or
                # same tool+normalized title — see Finding.dedup_key()) before they're
                # ever written to the report. Checks both this run's findings-so-far
                # AND whatever a previous run on this session already saved (pre-seeded
                # above), so re-scanning after uploading more evidence doesn't duplicate
                # findings from files that were already scanned before.
                _dedup_key_val = None
                if hasattr(f, "dedup_key"):
                    _dedup_key_val = f.dedup_key()
                    if _dedup_key_val in _seen_dedup_keys:
                        continue
                    _seen_dedup_keys.add(_dedup_key_val)

                c_id = map_finding_to_control(f)
                f_dict = f.to_dict() if hasattr(f, "to_dict") else dict(f)
                f_dict["dedup_key"] = _dedup_key_val
                f_dict["control_id"] = c_id
                f_dict["control"] = f_dict.get("control") or c_id
                f_dict["status"] = "Non-Compliant" if f_dict.get("severity") != "INFO" else "Informational"
                f_dict["display_status"] = "Open"
                f_dict["source_files"] = fname   # Scan FILE name, not host IP
                # ── Build structured evidence snippet (Proof of Concept block) ──
                # This is what auditors see as "Evidence". It must show:
                #   Host/IP, Port, CVE, Plugin Output — not just the Nessus plugin description.
                _target = f_dict.get("target") or ""
                _cves = f_dict.get("cve_list") or []
                _cve_str = ", ".join(_cves) if _cves else "No CVE assigned"
                _plugin_id = f_dict.get("plugin_id") or ""
                _plugin_out = str(f_dict.get("evidence") or f_dict.get("evidence_snippet") or f_dict.get("evidence_quote") or "").strip()
                _desc_text = str(f_dict.get("description") or f_dict.get("title") or "").strip()
                _tool = f_dict.get("source_tool") or "Scanner"
                # Structured PoC block
                poc_lines = []
                if _target:
                    poc_lines.append(f"Target Host: {_target}")
                if _plugin_id:
                    poc_lines.append(f"Plugin ID:   {_plugin_id}")
                if _cves:
                    poc_lines.append(f"CVE(s):      {_cve_str}")
                poc_lines.append(f"Scanner:     {_tool}")
                if _plugin_out and "Not available in scan report" not in _plugin_out:
                    poc_lines.append(f"Plugin Output:\n{_plugin_out[:1200]}")
                elif _desc_text:
                    poc_lines.append(f"Plugin Output:\n{_desc_text[:1200]}")
                else:
                    poc_lines.append(f"Plugin Output:\nTarget endpoint verified: {_target}")
                poc_block = "\n".join(poc_lines)
                f_dict["evidence_snippet"] = poc_block
                all_findings.append(f_dict)
                resolved_ctrls.add(c_id)

        # Update database with VAPT findings
        try:
            with force_master():
                db_write = SessionLocal()
                report = db_write.query(AuditReport).filter(AuditReport.session_id == bg_key).first()
                if report:
                    for f in all_findings:
                        db_write.add(Finding(
                            report_id=report.id,
                            control_id=f.get("control_id"),
                            control_name=f.get("title") or f.get("finding") or f.get("control") or f.get("control_id"),
                            severity=f.get("severity", "P3 Medium"),
                            description=f.get("description") or f.get("finding") or "",
                            gap_detected=f.get("finding") or f.get("description") or "",
                            relevance_score=f.get("relevance_score", 0),
                            evidence_found=str(f.get("severity_score", 0.0)),
                            evidence_snippet=f.get("evidence_snippet") or f.get("evidence") or "",
                            recommendation=f.get("remediation") or f.get("recommendation", ""),
                            reasoning=f.get("reasoning", ""),
                            status=f.get("status", "Non-Compliant"),
                            source_files=f.get("source_files", ""),  # Now = scan filename, NOT host IP
                            # VAPT enrichment fields -- previously computed by map_findings_list()
                            # then silently dropped here (no columns existed to persist them into),
                            # so every saved VAPT finding lost this data the moment the scan finished.
                            category=f.get("category") or "",
                            cia_impact=f.get("cia_impact") or "",
                            is_pii_exposed=bool(f.get("is_pii_exposed") or False),
                            remediation_actionable=f.get("remediation_actionable") or "",
                            dedup_key=f.get("dedup_key"),
                        ))
                    
                    # Update Compliance Score
                    db_write.query(ComplianceScore).filter(ComplianceScore.report_id == report.id).delete()
                    in_scope = [f for f in all_findings if f.get("status") in ("Compliant", "Partially Compliant", "Non-Compliant")]
                    compliant = [f for f in in_scope if f.get("status") == "Compliant"]
                    score_pct = int(len(compliant) / max(len(in_scope), 1) * 100) if in_scope else 0
                    db_write.add(ComplianceScore(
                        report_id=report.id,
                        framework=report.framework,
                        score_percent=score_pct
                    ))
                    
                    report.status = "Pending Review"
                    db_write.commit()
                db_write.close()
        except Exception as e:
            print(f"[PIPELINE-VAPT] Failed to write findings: {e}", flush=True)

        with _bg_lock:
            _bg_results[bg_key] = {
                "findings": all_findings,
                "resolved_list": list(resolved_ctrls),
                "resolved_count": len(resolved_ctrls),
                "resolved_controls": resolved_ctrls,
                "error": None,
                "completed": True
            }
        with _bg_lock:
            _bg_running.discard(bg_key)
    except Exception as e:
        with _bg_lock:
            _bg_results[bg_key] = {
                "findings": [],
                "error": str(e),
                "completed": True
            }
        with _bg_lock:
            _bg_running.discard(bg_key)
