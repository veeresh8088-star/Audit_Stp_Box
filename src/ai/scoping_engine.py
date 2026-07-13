import json
import requests
import re
import time
from src.core.controls_data import USE_CASES

# ── DOC TYPE → ISO 27001:2022 CONTROL MAPPINGS ───────────────────────────────
DOC_TYPE_MAPPINGS = {
    "Access Control Policy": [
        "5.15 Access Control", "5.16 Identity Management",
        "5.17 Authentication Information", "5.18 Access Rights",
        "8.2 Privileged Access Rights", "8.3 Information Access Restriction",
        "8.5 Secure Authentication"
    ],
    "Asset Management Policy": [
        "5.9 Inventory of Information and Other Associated Assets",
        "5.10 Acceptable Use of Information and Other Associated Assets",
        "5.11 Return of Assets", "5.12 Classification of Information",
        "5.13 Labelling of Information", "5.14 Information Transfer"
    ],
    "Risk Assessment": [
        "5.1 Policies for Information Security",
        "5.2 Information Security Roles and Responsibilities",
        "5.3 Segregation of Duties", "5.4 Management Responsibilities",
        "5.5 Contact with Authorities", "5.6 Contact with Special Interest Groups",
        "5.7 Threat Intelligence", "5.8 Information Security in Project Management",
        "5.35 Independent Review of Information Security",
        "5.36 Compliance with Policies and Standards for Information Security",
        "5.37 Documented Operating Procedures"
    ],
    "Incident Management Policy": [
        "5.24 Information Security Incident Management Planning and Preparation",
        "5.25 Assessment and Decision on Information Security Events",
        "5.26 Response to Information Security Incidents",
        "5.27 Learning from Information Security Incidents",
        "5.28 Collection of Evidence"
    ],
    "Business Continuity Plan": [
        "5.29 Information Security During Disruption",
        "5.30 Ict Readiness for Business Continuity",
        "8.13 Information Backup",
        "8.14 Redundancy of Information Processing Facilities"
    ],
    "General Security Policy": [
        "5.1 Policies for Information Security",
        "5.2 Information Security Roles and Responsibilities",
        "5.3 Segregation of Duties", "5.4 Management Responsibilities",
        "5.5 Contact with Authorities", "5.6 Contact with Special Interest Groups",
        "5.7 Threat Intelligence", "5.8 Information Security in Project Management",
        "5.35 Independent Review of Information Security",
        "5.36 Compliance with Policies and Standards for Information Security",
        "5.37 Documented Operating Procedures"
    ],
    "HR / People Security Policy": [
        "6.1 Screening", "6.2 Terms and Conditions of Employment",
        "6.3 Information Security Awareness, Education and Training",
        "6.4 Disciplinary Process",
        "6.5 Responsibilities after Termination or Change of Employment",
        "6.6 Confidentiality or Non-disclosure Agreements",
        "6.7 Remote Working", "6.8 Information Security Event Reporting"
    ],
    "Physical Security Policy": [
        "5.15 Access Control",
        "7.1 Physical Security Perimeters", "7.2 Physical Entry",
        "7.3 Securing Offices, Rooms and Facilities", "7.4 Physical Security Monitoring",
        "7.5 Protecting against Physical and Environmental Threats",
        "7.6 Working in Secure Areas", "7.7 Clear Desk and Clear Screen",
        "7.8 Equipment Siting and Protection", "7.9 Security of Assets Off-premises",
        "7.10 Storage Media", "7.11 Supporting Utilities", "7.12 Cabling Security",
        "7.13 Equipment Maintenance", "7.14 Secure Disposal or Re-use of Equipment"
    ],
    "Technology / IT Security Policy": [
        "8.1 User Endpoint Devices", "8.2 Privileged Access Rights",
        "8.3 Information Access Restriction", "8.4 Access to Source Code",
        "8.5 Secure Authentication", "8.6 Capacity Management",
        "8.7 Protection against Malware", "8.8 Management of Technical Vulnerabilities",
        "8.9 Configuration Management", "8.10 Information Deletion", "8.11 Data Masking",
        "8.12 Data Leakage Prevention", "8.13 Information Backup",
        "8.14 Redundancy of Information Processing Facilities", "8.15 Logging",
        "8.16 Monitoring Activities", "8.17 Clock Synchronization",
        "8.18 Use of Privileged Utility Programs",
        "8.19 Installation of Software on Operational Systems",
        "8.20 Network Security", "8.21 Security of Network Services",
        "8.22 Segregation of Networks", "8.23 Web Filtering",
        "8.24 Use of Cryptography", "8.25 Secure Development Life Cycle",
        "8.26 Application Security Requirements",
        "8.27 Secure System Architecture and Engineering Principles",
        "8.28 Secure Coding", "8.29 Security Testing in Development and Acceptance",
        "8.30 Outsourced Development",
        "8.31 Separation of Development, Testing and Production Environments",
        "8.32 Change Management", "8.33 Test Information",
        "8.34 Protection of Information Systems during Audit Testing"
    ],
    "Supplier / Third Party Policy": [
        "5.19 Information Security in Supplier Relationships",
        "5.20 Addressing Information Security Within Supplier Agreements",
        "5.21 Managing Information Security in The Ict Supply Chain",
        "5.22 Monitoring, Review and Change Management of Supplier Services",
        "5.23 Information Security for Use of Cloud Services"
    ],
    "Development / Secure Coding Policy": [
        "8.25 Secure Development Life Cycle", "8.26 Application Security Requirements",
        "8.27 Secure System Architecture and Engineering Principles", "8.28 Secure Coding",
        "8.29 Security Testing in Development and Acceptance", "8.30 Outsourced Development",
        "8.31 Separation of Development, Testing and Production Environments",
        "8.32 Change Management", "8.33 Test Information",
        "8.34 Protection of Information Systems during Audit Testing"
    ],
    "Compliance / Legal Policy": [
        "5.31 Legal, Statutory, Regulatory and Contractual Requirements",
        "5.32 Intellectual Property Rights", "5.33 Protection of Records",
        "5.34 Privacy and Protection of Personally Identifiable Information (Pii)",
        "5.36 Compliance with Policies and Standards for Information Security"
    ]
}

# ── CONTENT-BASED KEYWORD SIGNALS → Doc Types ────────────────────────────────
# If these keywords appear in document content, always add the corresponding type
CONTENT_SIGNALS = {
    "HR / People Security Policy": [
        "screening", "pre-employment", "onboarding", "termination of employment",
        "awareness training", "disciplinary", "confidentiality agreement", "remote working",
        "nda", "non-disclosure", "background check", "joiner", "leaver"
    ],
    "Physical Security Policy": [
        "badge", "physical access", "secure area", "clean desk", "visitor",
        "cctv", "tailgating", "piggyback", "reception", "keycard", "facility access",
        "physical security", "equipment disposal", "secure room"
    ],
    "Incident Management Policy": [
        "incident response", "security incident", "breach notification", "containment",
        "eradication", "forensic", "evidence collection", "incident severity",
        "soc ", "security operations"
    ],
    "Access Control Policy": [
        "logical access", "user account", "privilege", "authentication", "password",
        "identity management", "access rights", "role-based", "rbac", "mfa",
        "multi-factor", "single sign", "sso", "least privilege", "user credential",
        "system account", "login credential"
    ],
    "Technology / IT Security Policy": [
        "endpoint", "antivirus", "malware", "firewall", "encryption", "patch",
        "vulnerability", "network security", "logging", "monitoring", "backup",
        "cryptography", "configuration management", "data loss prevention"
    ],
    "Supplier / Third Party Policy": [
        "supplier", "vendor", "third party", "outsourc", "service provider",
        "cloud service", "supply chain", "contractor agreement", "sla"
    ],
    "Risk Assessment": [
        "risk register", "risk assessment", "threat", "vulnerability assessment",
        "risk treatment", "residual risk", "risk owner", "risk appetite"
    ],
    "Business Continuity Plan": [
        "business continuity", "disaster recovery", "bcp", "drp", "rto", "rpo",
        "recovery time", "recovery point", "resilience", "failover"
    ],
    "Compliance / Legal Policy": [
        "gdpr", "pii", "personal data", "data privacy", "legal requirement",
        "regulatory", "intellectual property", "data protection", "privacy"
    ],
    "General Security Policy": [
        "information security policy", "iprotect", "information protection policy",
        "security policy", "isms", "iso 27001"
    ],
    "Asset Management Policy": [
        "asset inventory", "asset register", "asset classification", "asset owner",
        "information asset", "data classification", "asset management"
    ],
    "Development / Secure Coding Policy": [
        "secure coding", "sdlc", "development lifecycle", "code review",
        "penetration test", "security testing", "devops", "ci/cd"
    ]
}

# ── UMBRELLA POLICY DETECTION ─────────────────────────────────────────────────
# These doc types should ALWAYS trigger multi-clause expansion
UMBRELLA_POLICY_KEYWORDS = [
    "information protection policy", "iprotect", "information security policy",
    "security policy", "master security", "isms policy"
]

UMBRELLA_EXPANDS_TO = [
    "General Security Policy",
    "Access Control Policy",
    "HR / People Security Policy",
    "Physical Security Policy",
    "Technology / IT Security Policy",
    "Incident Management Policy",
    "Supplier / Third Party Policy",
    "Risk Assessment",
    "Compliance / Legal Policy"
]


def _apply_content_signals(context_lower: str, doc_types: list) -> list:
    """
    Scan document content for keyword signals and add missing doc types.
    Enforces word boundaries for short abbreviations (<= 4 chars) to prevent substring false matches.
    """
    doc_types_set = set(doc_types)
    for dtype, keywords in CONTENT_SIGNALS.items():
        for kw in keywords:
            # Enforce word boundaries for abbreviations or short terms to prevent matching within words like 'purpose'
            if len(kw) <= 4 or kw in ["bcp", "drp", "rto", "rpo", "nda", "mfa", "sso", "rbac", "soc"]:
                pattern = r"\b" + re.escape(kw) + r"\b"
                if re.search(pattern, context_lower):
                    doc_types_set.add(dtype)
                    break
            else:
                if kw in context_lower:
                    doc_types_set.add(dtype)
                    break
    return list(doc_types_set)


def _check_umbrella_policy(context_lower: str, doc_types: list) -> list:
    """
    If document looks like a master/umbrella policy, expand to all relevant types.
    Fixes the iProtect false-narrow-scoping problem.
    """
    is_umbrella = any(kw in context_lower[:5000] for kw in UMBRELLA_POLICY_KEYWORDS)
    if is_umbrella:
        doc_types_set = set(doc_types)
        for dt in UMBRELLA_EXPANDS_TO:
            doc_types_set.add(dt)
        return list(doc_types_set)
    return doc_types


def _get_candidate_controls(doc_types):
    """Retrieve candidate control names based on identified document types."""
    candidates = set()
    for dt in doc_types:
        for c in DOC_TYPE_MAPPINGS.get(dt, []):
            candidates.add(c)

    if not candidates:
        for dt, controls in DOC_TYPE_MAPPINGS.items():
            for c in controls:
                candidates.add(c)

    return list(candidates)


SCOPE_DESCRIPTIONS = {
    "Access Control Policy": "Logical user access control, login accounts, password policy, multi-factor authentication MFA, single sign-on SSO, role-based access RBAC, privileged accounts",
    "Asset Management Policy": "Inventory of assets, acceptable use policy AUP, classification of information, data labelling, media disposal, device return, asset lifecycle",
    "Risk Assessment": "Information security risk assessment, threat identification, vulnerability management, risk treatment plans, management oversight",
    "Incident Management Policy": "Information security incident management, security events, reporting incident tickets, breach containment, logs, forensic evidence, lessons learned",
    "Business Continuity Plan": "Business continuity plans, disaster recovery plans, ICT readiness, backup restoration testing, systems redundancy, disruptions",
    "General Security Policy": "High level information security policy, ISMS framework, roles and responsibilities, management commitment",
    "HR / People Security Policy": "Background screening, employment terms and conditions, nda confidentiality agreements, awareness training, disciplinary actions, offboarding termination",
    "Physical Security Policy": "Physical security perimeters, physical entry control, visitor logs, secure offices, camera monitoring, environmental threats, clean desk clear screen",
    "Technology / IT Security Policy": "Technical IT security, endpoint protection, antivirus malware, firewalls, logs, network segmentation, web filtering, patch management, cryptography encryption",
    "Supplier / Third Party Policy": "Vendor relationships, supplier contracts, supply chain security, monitoring supplier services, cloud services security",
    "Development / Secure Coding Policy": "Secure development lifecycle SDLC, secure coding standards, security testing, source code protection, separate dev test prod environments",
    "Compliance / Legal Policy": "Legal statutory regulatory compliance, intellectual property protection, records retention policy, PII privacy protection, audits"
}

_category_embeddings_cache = {}


def cosine_similarity(v1, v2):
    """Calculates cosine similarity between two vectors."""
    if not v1 or not v2:
        return 0.0
    dot = sum(a * b for a, b in zip(v1, v2))
    norm_a = sum(a * a for a in v1) ** 0.5
    norm_b = sum(b * b for b in v2) ** 0.5
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def detect_scope_and_controls(context, ollama_model=None):
    """
    Zero-LLM deterministic + semantic scope detection.
    Combines direct keyword signals with fast Nomic embeddings (Option A).
    """
    start_time = time.time()
    print(f"\n[{time.strftime('%H:%M:%S')}] [INFO] Starting Dual-Layer Scope Detection (Option A)...")

    context_lower = context.lower()
    doc_types_set = set()
    ollama_offline = False

    # ── LAYER 1: Python Keyword Signals (Instant) ─────────────────────────────
    doc_types_list = _apply_content_signals(context_lower, [])
    for dt in doc_types_list:
        doc_types_set.add(dt)

    # ── LAYER 2: Semantic Embedding Match (~50ms) ────────────────────────────
    # Convert first 800 chars of document to vector
    doc_snippet = context[:800].strip()
    if doc_snippet:
        try:
            from src.core.llm_client import get_embedding
            
            # 1. Warm up category embeddings cache if empty
            for cat, desc in SCOPE_DESCRIPTIONS.items():
                if cat not in _category_embeddings_cache:
                    _category_embeddings_cache[cat] = get_embedding(desc)

            # 2. Get document vector
            doc_vector = get_embedding(doc_snippet)

            # 3. Calculate cosine similarity
            if doc_vector:
                print(f"[{time.strftime('%H:%M:%S')}] [INFO] Computing semantic scope matches...")
                for cat, cat_vector in _category_embeddings_cache.items():
                    if cat_vector:
                        sim = cosine_similarity(doc_vector, cat_vector)
                        if sim >= 0.645:
                            print(f"   * Semantic Match: {cat} (Similarity: {sim:.3f})")
                            doc_types_set.add(cat)
        except Exception as embed_err:
            print(f"[{time.strftime('%H:%M:%S')}] [WARNING] Semantic scoping failed: {embed_err}")

    doc_types = list(doc_types_set)

    # ── LAYER 3: Umbrella Policy Expansion ────────────────────────────────────
    before_umbrella = set(doc_types)
    doc_types = _check_umbrella_policy(context_lower, doc_types)
    added_by_umbrella = set(doc_types) - before_umbrella
    if added_by_umbrella:
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Umbrella expansion added: {list(added_by_umbrella)}")

    # ── LAYER 4: Map doc types to standard controls ──────────────────────────
    selected_controls = _get_candidate_controls(doc_types)

    # ── LAYER 5: Fallback if empty ────────────────────────────────────────────
    if not doc_types:
        doc_types = list(DOC_TYPE_MAPPINGS.keys())
        selected_controls = _get_candidate_controls(doc_types)
        print(f"[{time.strftime('%H:%M:%S')}] [WARN] No scopes detected — falling back to ALL scopes")

    elapsed = time.time() - start_time
    print(f"[{time.strftime('%H:%M:%S')}] [SUCCESS] Scope Detection completed in {elapsed:.4f}s")
    print(f"   Final Doc Types ({len(doc_types)}): {doc_types}")

    return selected_controls, None, doc_types, ollama_offline
