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
        "access control", "user account", "privilege", "authentication", "password",
        "identity management", "access rights", "role-based", "rbac", "mfa",
        "multi-factor", "single sign", "sso", "least privilege"
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
    This is the key fix — catches types the LLM misses from title alone.
    """
    doc_types_set = set(doc_types)
    for dtype, keywords in CONTENT_SIGNALS.items():
        for kw in keywords:
            if kw in context_lower:
                doc_types_set.add(dtype)
                break  # one match is enough to add the type
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


def detect_scope_and_controls(context, ollama_model="qwen2.5:7b"):
    """
    Intelligent LLM-driven scope detection with content-signal fallback.

    Pipeline:
      1. LLM reads first 3000 chars → returns doc_types list
      2. Content-signal scan of full document → adds any missed types
      3. Umbrella-policy check → expands scope if master policy detected
      4. Returns merged, deduplicated doc_types

    Returns:
       selected_controls (list): Always empty — app.py applies fallback logic.
       warning (str): A warning message or None.
       doc_types (list of strings): The identified document types.
       ollama_offline (bool): True if Ollama could not be reached.
     """
    start_time = time.time()
    print(f"\n[{time.strftime('%H:%M:%S')}] [INFO] Starting LLM Scope Detection (model: {ollama_model})...")

    context_lower = context.lower()

    # Use first 3000 chars for LLM — enough to identify document purpose quickly
    context_chunk = context[:3000]

    doc_types = []
    selected_controls = []
    ollama_offline = False

    # ── STEP 1: LLM identifies Document Type(s) and specific controls ─────────
    scopes_and_controls_str = ""
    for dtype, controls in DOC_TYPE_MAPPINGS.items():
        scopes_and_controls_str += f"- {dtype}:\n"
        for ctrl in controls:
            scopes_and_controls_str += f"  * {ctrl}\n"

    step1_prompt = f"""You are an ISO 27001:2022 Cybersecurity Auditor performing document scope classification.

Read the document excerpt below carefully and identify the applicable document scope types and specific controls.

AVAILABLE SCOPES AND THEIR ASSOCIATED CONTROLS:
{scopes_and_controls_str}

DOCUMENT EXCERPT:
\"\"\"
{context_chunk}
\"\"\"

CLASSIFICATION RULES:
1. Read the FULL excerpt before deciding — do not stop at the title
2. A single document can and often does match MULTIPLE scopes and controls
3. Match based on CONTENT, not just the document title
4. Be precise: only select a control if the document content directly provides evidence or configuration details for it. Do not select a control if it is only a minor mention or OCR noise.
5. If the document is about Multi-Factor Authentication (MFA), passwords, or user logins, select "Access Control Policy" as the scope, but only select the specific authentication controls (e.g., "8.5 Secure Authentication", "5.17 Authentication Information") as the controls. Do NOT select physical access controls (e.g. "7.1", "7.2") or source code controls (e.g. "8.4") unless the document explicitly covers them.
6. CRITICAL: Ignore browser window chrome/UI elements, open browser tab names, URL/search bar texts, search queries, or background desktop icons that may appear in OCR-extracted text (e.g., text like "open Ports on Linux", "What is the comma", "youtube", "signin.aws.amazon.com/oauth"). Focus ONLY on the actual main document text, policy headings, or the core user-interface settings shown in the screenshots.

Return ONLY valid JSON — no explanation, no markdown:
{{
  "doc_types": ["scope name 1", "scope name 2"],
  "selected_controls": ["control name 1", "control name 2"]
}}"""

    try:
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Step 1: LLM detecting document type and controls...")
        import os as _os
        base_url = _os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").strip()
        if base_url and not base_url.startswith("http://") and not base_url.startswith("https://"):
            base_url = f"http://{base_url}" if ":" in base_url else f"http://{base_url}:11434"
        r1 = requests.post(
            f"{base_url}/api/generate",
            json={
                "model": ollama_model,
                "prompt": step1_prompt,
                "stream": False,
                "format": "json",
                "options": {
                    "temperature": 0.0,
                    "num_ctx": 4096,
                    "num_thread": 8
                },
                "keep_alive": "15m"
            },
            timeout=120
        )
        if r1.status_code == 200:
            res1 = r1.json().get("response", "{}")
            try:
                first_brace = res1.find('{')
                last_brace = res1.rfind('}')
                json_str1 = res1[first_brace:last_brace+1] if first_brace != -1 else res1
                data1 = json.loads(json_str1)
                dt_list = data1.get("doc_types", [])
                doc_types = [dt for dt in dt_list if dt in DOC_TYPE_MAPPINGS]
                
                # Extract and validate selected controls
                ctrl_list = data1.get("selected_controls", [])
                all_allowed_controls = set()
                for ctrls in DOC_TYPE_MAPPINGS.values():
                    all_allowed_controls.update(ctrls)
                selected_controls = [c for c in ctrl_list if c in all_allowed_controls]
                
                print(f"[{time.strftime('%H:%M:%S')}] [INFO] Step 1 LLM result: {doc_types}, controls: {selected_controls}")
            except Exception as parse_err:
                print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Step 1 JSON parse failed: {parse_err}. Raw: {res1}")
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Step 1 HTTP error: {r1.status_code}")
    except Exception as e:
        ollama_offline = True
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Step 1 LLM call failed: {e}")

    # Before content signals/umbrella, remember what LLM detected
    llm_doc_types = set(doc_types)

    # ── STEP 2: Content-signal scan (catches what LLM missed) ─────────────────
    before_signals = set(doc_types)
    doc_types = _apply_content_signals(context_lower, doc_types)
    added_by_signals = set(doc_types) - before_signals
    if added_by_signals:
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Step 2 Content signals added: {list(added_by_signals)}")

    # ── STEP 3: Umbrella policy expansion ─────────────────────────────────────
    before_umbrella = set(doc_types)
    doc_types = _check_umbrella_policy(context_lower, doc_types)
    added_by_umbrella = set(doc_types) - before_umbrella
    if added_by_umbrella:
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Step 3 Umbrella expansion added: {list(added_by_umbrella)}")

    # If the LLM returned specific controls, we merge in the candidate controls
    # of any newly added doc types that the LLM missed.
    newly_added_types = set(doc_types) - llm_doc_types
    if newly_added_types and selected_controls:
        for dt in newly_added_types:
            for c in DOC_TYPE_MAPPINGS.get(dt, []):
                if c not in selected_controls:
                    selected_controls.append(c)

    # ── STEP 4: Final fallback — if still empty, use all scopes ───────────────
    if not doc_types:
        doc_types = list(DOC_TYPE_MAPPINGS.keys())
        print(f"[{time.strftime('%H:%M:%S')}] [WARN] No scopes detected — falling back to ALL scopes")

    elapsed = time.time() - start_time
    print(f"[{time.strftime('%H:%M:%S')}] [SUCCESS] Scope Detection completed in {elapsed:.2f}s")
    print(f"   Final Doc Types ({len(doc_types)}): {doc_types}")
    print(f"   Final Selected Controls ({len(selected_controls)}): {selected_controls}")

    return selected_controls, None, doc_types, ollama_offline
