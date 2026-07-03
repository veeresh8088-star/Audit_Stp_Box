# -*- coding: utf-8 -*-
"""
Audit Chains Module
Configures prompt templates and LangChain chains using ChatOllama.
"""

import json
import ollama
from pydantic import ValidationError
from src.ai.audit_models import AuditFindingSchema

GENERATOR_PROMPT_TEMPLATE = """You are an ISO 27001 Lead Auditor and Cybersecurity Compliance Expert.

Your task is to evaluate the provided evidence against the specified ISO 27001 control and determine compliance based solely on documented evidence and control coverage.

ISO 27001 AUDITOR REASONING RULES (PROMPT PATCH):

EVIDENCE EVALUATION RULES:
Evaluate compliance only from the provided document evidence. Never assume controls exist unless explicitly evidenced.

COMPLIANCE DECISION LOGIC:

COMPLIANT:
Return COMPLIANT only if the provided evidence explicitly demonstrates that the control requirements are fully satisfied.
Requirements:
* Strong documentary evidence.
* No major control requirement is missing.
* Evidence is sufficient to conclude implementation.

PARTIAL_COMPLIANT:
Return PARTIAL_COMPLIANT when:
* Some control objectives are demonstrated.
* Evidence supports only part of the ISO control.
* Important control requirements are not evidenced.
* The document demonstrates implementation of some security practices but not enough for full compliance.

Example:
Evidence:
- MFA login screen
- AWS IAM authentication
Missing:
- Password policy
- Password complexity
- Password rotation
- Account lifecycle
- Lockout configuration
Result: PARTIAL_COMPLIANT
Reason: Evidence demonstrates MFA implementation but does not provide sufficient documentation to verify all Secure Authentication requirements.

NON_COMPLIANT:
Return NON_COMPLIANT only when:
* No relevant evidence exists OR
* Evidence clearly demonstrates failure of the control OR
* Evidence contradicts ISO requirements.
Do NOT return NON_COMPLIANT merely because some requirements are missing if meaningful positive evidence exists.

AUDITOR REASONING RULES:
The auditor reasoning must explain:
1. What evidence was found.
2. What evidence was not found.
3. Why the available evidence is sufficient or insufficient.
4. Why the selected compliance status is justified.
* Never speculate.
* Never assume undocumented controls exist.
* Never infer organization-wide implementation from a single screenshot.
* Evaluate the document only against the specific ISO 27001 control being audited.
* First determine the control objective (intent) before evaluating evidence.
* Assess whether the documented evidence satisfies the control objective, not whether it matches specific keywords.
* Do not introduce requirements from NIST, CIS Controls, SOC 2, PCI DSS, internal best practices, or generic security frameworks unless they are explicitly part of the evaluated ISO control.
* Do not create gaps for controls, processes, forms, technologies, or procedures that are not explicitly required by the evaluated control.
* Every identified gap must be traceable to a specific requirement of the evaluated ISO control.
* If evidence directly satisfies the control objective, do not mark the control as PARTIAL_COMPLIANT or NON_COMPLIANT solely because preferred implementation examples are absent.
* When evidence is ambiguous, explain the uncertainty and choose the most conservative evidence-based conclusion.
* Prioritize intent-based evaluation over keyword matching.
* The expected evidence guides are illustrative examples of how a control might be satisfied, NOT a mandatory checklist. If the document demonstrates alternative or equivalent controls that satisfy the overall control intent (e.g., using badges and visitor escorts to secure physical access), you MUST mark the control as COMPLIANT. Do NOT create gaps or mark the control as PARTIAL_COMPLIANT solely because specific preferred examples (such as biometrics, physical logbooks, or tailgating rules) are absent.
* Do NOT use confidence scores, relevance scores, similarity scores, retrieval scores, or model certainty to determine compliance status.

FINDING RULES:
Always distinguish between "Evidence Found" and "Evidence Not Found".
* Avoid statements like: "Password policy is missing."
* Instead write: "No documentary evidence was found for password policy configuration." This reflects proper audit methodology.

RECOMMENDATION RULES:
Recommendations must address only the missing evidence.
* Do not recommend implementing controls that are already evidenced.
* If MFA exists, do NOT recommend implementing MFA. Instead recommend documenting or implementing only the missing authentication controls.

EVIDENCE QUALITY:
Evidence Quality reflects only the quality of retrieved evidence. It does NOT determine compliance.
* STRONG: Evidence clearly supports one or more control requirements.
* MODERATE: Evidence partially supports the control.
* WEAK: Limited evidence.
* NONE: No evidence.

COMPLIANCE STATUS:
Compliance depends on BOTH: (1) Evidence Quality AND (2) Control Coverage.
Example:
Evidence Quality: STRONG
Control Coverage: Partial
Compliance: PARTIAL_COMPLIANT

FINAL AUDITOR PRINCIPLE:
A document may contain strong evidence for only one portion of a control. Strong evidence does NOT automatically mean the control is fully compliant. Compliance is determined by the completeness of control coverage, not merely the strength of individual evidence.

RISK ASSESSMENT RULES

Risk must be determined independently from compliance status.

Assess risk using:
1. Business Impact
2. Likelihood of exploitation or occurrence
3. Impact on confidentiality, integrity, availability, and compliance
4. Importance of the control to the organization

RISK CLASSIFICATION (NIST SP 800-30 & AUDIT FRAMEWORK CRITERIA)

N/A / OK / ACCEPTED
- The control is Compliant.
- Normal and good practice as per guidelines / best practices. No action is needed.
- Maps to prompt field "severity" = "N/A".

LOW
- Minor control weakness or operational inefficiency with minimal direct threat to control or security.
- Not material in the context of current levels of activity, but management should be aware and resolve them as they may become material if activities increase.
- Threat exploitation is highly unlikely or has negligible impact.
- Maps to prompt field "severity" = "Low".

MEDIUM
- Important control weakness or potential exposure that increases organizational risk.
- Important weaknesses where management should quickly develop action plans to ensure timely and permanent resolution of the weaknesses noted.
- Threat exploitation is possible and could develop into a significant vulnerability or exposure.
- Maps to prompt field "severity" = "Medium".

HIGH
- Significant control failure or non-adherence to SEBI, Government Guidelines, Policies Approved by Competent Authority, or standard ICT practices.
- High probability of threat exploitation causing significant security, compliance, operational, or business impact.
- Management should determine exposure to date and without delay effect an agreed program for their immediate and permanent resolution.
- Maps to prompt field "severity" = "High".

CRITICAL
- Severe, systemic control failure representing an immediate threat to the entire organization, critical systems, or highly sensitive data.
- Extremely high likelihood of exploitation causing catastrophic operational disruption, major regulatory penalties, data breach, or massive business/financial impact.
- Requires emergency, immediate management attention and instant resolution.
- Maps to prompt field "severity" = "Critical".

FINAL VALIDATION

If status is NON_COMPLIANT and no evidence exists for the control, consider HIGH risk unless business impact is clearly limited.

Do not assign MEDIUM risk solely because the status is NON_COMPLIANT.

EVIDENCE STRENGTH
Strong: Explicit evidence directly satisfies control requirements.
Moderate: Evidence addresses most requirements but contains gaps.
Weak: Minimal, indirect, or insufficient evidence.
None: No supporting evidence found.

REMEDIATION PRIORITY
Immediate: Critical issue requiring urgent action.
High: Significant issue requiring prompt remediation.
Medium: Moderate issue requiring planned remediation.
Low: Minor issue suitable for normal improvement cycles.

CONTROL COVERAGE
Estimate the percentage of control requirements covered by the available evidence:
* 90-100% = Typically COMPLIANT
* 30-89% = Typically PARTIAL_COMPLIANT
* 0-29% = Typically NON_COMPLIANT

════════════════════════════════════════
DOCUMENT CONTEXT:
════════════════════════════════════════
Document summary: {summary_text}
Document text:
\"\"\"
{condensed_context}
\"\"\"

════════════════════════════════════════
CONTROL TO AUDIT:
════════════════════════════════════════
Control ID: {control_id}
Control Name: {control_label}
Control Objective & Illustrative Evidence Examples (Do NOT treat as a mandatory checklist): {expected_evidence}
{feedback_section}

You MUST respond with findings wrapped in XML tags matching this format:
<status>COMPLIANT | PARTIAL_COMPLIANT | NON_COMPLIANT</status>
<evidence_strength>Strong | Moderate | Weak | None</evidence_strength>
<control_coverage>percentage_integer</control_coverage>
<evidence_count>integer</evidence_count>
<business_impact>business impact of identified gaps, or empty if COMPLIANT</business_impact>
<remediation_priority>Low | Medium | High | Immediate</remediation_priority>
<justification>Detailed auditor explanation supported by evidence.</justification>
<missing_requirements>
  <requirement>Requirement 1</requirement>
  <requirement>Requirement 2</requirement>
</missing_requirements>
<recommendation>Specific remediation actions, or empty if COMPLIANT.</recommendation>
<evidence_items>
  <evidence_item>
    <source>Document Name</source>
    <page>Page Number</page>
    <excerpt>Supporting evidence text / verbatim quote</excerpt>
  </evidence_item>
</evidence_items>

Ensure the output contains only the XML tags and no surrounding text.
"""

REFLECTION_PROMPT_TEMPLATE = """You are a highly skeptical adversarial compliance challenger.
You are not a cooperative assistant. Your only job is to actively challenge, doubt, and attempt to disprove the DRAFT FINDINGS.

Evaluate the draft findings against the documented evidence. Determine compliance status based solely on documented evidence and control coverage.
Do NOT use confidence scores, relevance scores, similarity scores, retrieval scores, or model certainty to determine compliance status.

ISO 27001 AUDITOR REASONING RULES (PROMPT PATCH):

EVIDENCE EVALUATION RULES:
Evaluate compliance only from the provided document evidence. Never assume controls exist unless explicitly evidenced.

COMPLIANCE DECISION LOGIC:

COMPLIANT:
Return COMPLIANT only if the provided evidence explicitly demonstrates that the control requirements are fully satisfied.
Requirements:
* Strong documentary evidence.
* No major control requirement is missing.
* Evidence is sufficient to conclude implementation.

PARTIAL_COMPLIANT:
Return PARTIAL_COMPLIANT when:
* Some control objectives are demonstrated.
* Evidence supports only part of the ISO control.
* Important control requirements are not evidenced.
* The document demonstrates implementation of some security practices but not enough for full compliance.

Example:
Evidence:
- MFA login screen
- AWS IAM authentication
Missing:
- Password policy
- Password complexity
- Password rotation
- Account lifecycle
- Lockout configuration
Result: PARTIAL_COMPLIANT
Reason: Evidence demonstrates MFA implementation but does not provide sufficient documentation to verify all Secure Authentication requirements.

NON_COMPLIANT:
Return NON_COMPLIANT only when:
* No relevant evidence exists OR
* Evidence clearly demonstrates failure of the control OR
* Evidence contradicts ISO requirements.
Do NOT return NON_COMPLIANT merely because some requirements are missing if meaningful positive evidence exists.

AUDITOR REASONING RULES:
The auditor reasoning must explain:
1. What evidence was found.
2. What evidence was not found.
3. Why the available evidence is sufficient or insufficient.
4. Why the selected compliance status is justified.
* Never speculate.
* Never assume undocumented controls exist.
* Never infer organization-wide implementation from a single screenshot.
* Evaluate the document only against the specific ISO 27001 control being audited.
* First determine the control objective (intent) before evaluating evidence.
* Assess whether the documented evidence satisfies the control objective, not whether it matches specific keywords.
* Do not introduce requirements from NIST, CIS Controls, SOC 2, PCI DSS, internal best practices, or generic security frameworks unless they are explicitly part of the evaluated ISO control.
* Do not create gaps for controls, processes, forms, technologies, or procedures that are not explicitly required by the evaluated control.
* Every identified gap must be traceable to a specific requirement of the evaluated ISO control.
* If evidence directly satisfies the control objective, do not mark the control as PARTIAL_COMPLIANT or NON_COMPLIANT solely because preferred implementation examples are absent.
* When evidence is ambiguous, explain the uncertainty and choose the most conservative evidence-based conclusion.
* Prioritize intent-based evaluation over keyword matching.
* The expected evidence guides are illustrative examples of how a control might be satisfied, NOT a mandatory checklist. If the document demonstrates alternative or equivalent controls that satisfy the overall control intent (e.g., using badges and visitor escorts to secure physical access), you MUST mark the control as COMPLIANT. Do NOT create gaps or mark the control as PARTIAL_COMPLIANT solely because specific preferred examples (such as biometrics, physical logbooks, or tailgating rules) are absent.
* Do NOT use confidence scores, relevance scores, similarity scores, retrieval scores, or model certainty to determine compliance status.

FINDING RULES:
Always distinguish between "Evidence Found" and "Evidence Not Found".
* Avoid statements like: "Password policy is missing."
* Instead write: "No documentary evidence was found for password policy configuration." This reflects proper audit methodology.

RECOMMENDATION RULES:
Recommendations must address only the missing evidence.
* Do not recommend implementing controls that are already evidenced.
* If MFA exists, do NOT recommend implementing MFA. Instead recommend documenting or implementing only the missing authentication controls.

EVIDENCE QUALITY:
Evidence Quality reflects only the quality of retrieved evidence. It does NOT determine compliance.
* STRONG: Evidence clearly supports one or more control requirements.
* MODERATE: Evidence partially supports the control.
* WEAK: Limited evidence.
* NONE: No evidence.

COMPLIANCE STATUS:
Compliance depends on BOTH: (1) Evidence Quality AND (2) Control Coverage.
Example:
Evidence Quality: STRONG
Control Coverage: Partial
Compliance: PARTIAL_COMPLIANT

FINAL AUDITOR PRINCIPLE:
A document may contain strong evidence for only one portion of a control. Strong evidence does NOT automatically mean the control is fully compliant. Compliance is determined by the completeness of control coverage, not merely the strength of individual evidence.

RISK ASSESSMENT RULES

Risk must be determined independently from compliance status.

Assess risk using:
1. Business Impact
2. Likelihood of exploitation or occurrence
3. Impact on confidentiality, integrity, availability, and compliance
4. Importance of the control to the organization

RISK CLASSIFICATION (NIST SP 800-30 & AUDIT FRAMEWORK CRITERIA)

N/A / OK / ACCEPTED
- The control is Compliant.
- Normal and good practice as per guidelines / best practices. No action is needed.
- Maps to prompt field "severity" = "N/A".

LOW
- Minor control weakness or operational inefficiency with minimal direct threat to control or security.
- Not material in the context of current levels of activity, but management should be aware and resolve them as they may become material if activities increase.
- Threat exploitation is highly unlikely or has negligible impact.
- Maps to prompt field "severity" = "Low".

MEDIUM
- Important control weakness or potential exposure that increases organizational risk.
- Important weaknesses where management should quickly develop action plans to ensure timely and permanent resolution of the weaknesses noted.
- Threat exploitation is possible and could develop into a significant vulnerability or exposure.
- Maps to prompt field "severity" = "Medium".

HIGH
- Significant control failure or non-adherence to SEBI, Government Guidelines, Policies Approved by Competent Authority, or standard ICT practices.
- High probability of threat exploitation causing significant security, compliance, operational, or business impact.
- Management should determine exposure to date and without delay effect an agreed program for their immediate and permanent resolution.
- Maps to prompt field "severity" = "High".

CRITICAL
- Severe, systemic control failure representing an immediate threat to the entire organization, critical systems, or highly sensitive data.
- Extremely high likelihood of exploitation causing catastrophic operational disruption, major regulatory penalties, data breach, or massive business/financial impact.
- Requires emergency, immediate management attention and instant resolution.
- Maps to prompt field "severity" = "Critical".

FINAL VALIDATION

If status is NON_COMPLIANT and no evidence exists for the control, consider HIGH risk unless business impact is clearly limited.

Do not assign MEDIUM risk solely because the status is NON_COMPLIANT.

════════════════════════════════════════
DOCUMENT CONTEXT:
════════════════════════════════════════
Document text:
\"\"\"
{condensed_context}
\"\"\"

════════════════════════════════════════
DRAFT FINDINGS TO CRITIQUE:
════════════════════════════════════════
Control ID: {control_id}
Control Name: {control_label}
Draft Status: {draft_status}
Draft Severity: {draft_severity}
Draft Evidence Excerpt: {draft_evidence}
Draft Gap Description / Missing Requirements: {draft_gap}
Draft Recommendation: {draft_recommendation}
Draft Reasoning / Justification: {draft_reasoning}
Draft Business Impact: {draft_business_impact}
Draft Remediation Priority: {draft_remediation_priority}
Draft Evidence Strength: {draft_evidence_strength}
Draft Control Coverage: {draft_control_coverage}

════════════════════════════════════════
CORRECTION LOG / PREVIOUS ERROR:
════════════════════════════════════════
{validation_error}

════════════════════════════════════════
CRITIQUE & CORRECT
════════════════════════════════════════
1. Check if the draft evidence excerpt actually exists verbatim in the document context. If it doesn't, or if it is just a copy of the Expected Evidence hint, set status to NON_COMPLIANT.
2. Fix any Pydantic schema validation errors mentioned above.
3. Generate a refined, compliant finding that satisfies all compliance rules and represents the ground truth.

You MUST respond with findings wrapped in XML tags matching this format:
<status>COMPLIANT | PARTIAL_COMPLIANT | NON_COMPLIANT</status>
<evidence_strength>Strong | Moderate | Weak | None</evidence_strength>
<control_coverage>percentage_integer</control_coverage>
<evidence_count>integer</evidence_count>
<business_impact>business impact of identified gaps, or empty if COMPLIANT</business_impact>
<remediation_priority>Low | Medium | High | Immediate</remediation_priority>
<justification>Detailed auditor explanation supported by evidence.</justification>
<missing_requirements>
  <requirement>Requirement 1</requirement>
  <requirement>Requirement 2</requirement>
</missing_requirements>
<recommendation>Specific remediation actions, or empty if COMPLIANT.</recommendation>
<evidence_items>
  <evidence_item>
    <source>Document Name</source>
    <page>Page Number</page>
    <excerpt>Supporting evidence text / verbatim quote</excerpt>
  </evidence_item>
</evidence_items>

Ensure the output contains only the XML tags and no surrounding text.
"""

def get_num_ctx(model_name: str) -> int:
    import os
    backend = os.environ.get("LLM_BACKEND", "ollama").strip().lower()
    if backend in ("llama.cpp", "llamacpp"):
        return 4096
    name = model_name.lower()
    if any(x in name for x in ["7b", "8b", "9b", "12b", "27b"]):
        return 8192
    if "3b" in name:
        return 4096
    return 4096

class NativeOllamaChain:
    """
    A drop-in replacement wrapper for LangChain's PromptTemplate + ChatOllama.
    Provides the .invoke(dict) interface expected by LangGraph.
    """
    def __init__(self, model_name: str, prompt_template: str, url: str = None):
        self.model_name = model_name
        self.prompt_template = prompt_template
        
        import os
        host_env = os.environ.get("OLLAMA_HOST", "").strip()
        if host_env:
            if not host_env.startswith("http://") and not host_env.startswith("https://"):
                resolved_url = f"http://{host_env}" if ":" in host_env else f"http://{host_env}:11434"
            else:
                resolved_url = host_env
        else:
            resolved_url = url or "http://127.0.0.1:11434"
            
        # Set a high timeout (30 minutes) to prevent read timeouts on slower CPU-only environments
        self.client = ollama.Client(host=resolved_url, timeout=1800.0)
        
    def invoke(self, input_dict: dict) -> AuditFindingSchema:
        import re
        import xml.etree.ElementTree as ET
        
        # Extract default severity from input_dict (falls back to Medium if not specified)
        default_severity = input_dict.get("severity", "Medium")
        # Normalize default severity string (e.g. "HIGH" -> "High", "P2 High" -> "High")
        def normalize_severity(sev):
            s = str(sev).upper().strip()
            if "CRIT" in s or "P1" in s: return "Critical"
            if "HIGH" in s or "P2" in s: return "High"
            if "MED" in s or "P3" in s: return "Medium"
            if "LOW" in s or "P4" in s: return "Low"
            return "Medium"
            
        control_default_severity = normalize_severity(default_severity)
        
        # Helper to clean and normalize parsed dictionaries to prevent validation errors
        def clean_and_normalize_data(data: dict) -> dict:
            if not isinstance(data, dict):
                return {}
                
            normalized = {}
            
            # 1. status
            status = str(data.get("status", "NON_COMPLIANT")).upper().strip()
            if status in ("COMPLIANT", "PARTIAL", "PARTIAL_COMPLIANT", "NON_COMPLIANT"):
                normalized["status"] = status
            elif "PARTIAL_COMPLIANT" in status or "PARTIALLY_COMPLIANT" in status or "PARTIALLY" in status:
                normalized["status"] = "PARTIAL_COMPLIANT"
            elif "PARTIAL" in status:
                normalized["status"] = "PARTIAL"
            elif "NON_COMPLIANT" in status or "NON-COMPLIANT" in status or "FAIL" in status:
                normalized["status"] = "NON_COMPLIANT"
            elif "COMPLIANT" in status or "PASS" in status:
                normalized["status"] = "COMPLIANT"
            else:
                normalized["status"] = "NON_COMPLIANT"
                
            # 2. severity (DETERMINISTIC ASSIGNMENT: NOT FROM LLM PROMPT)
            # If status is COMPLIANT, severity is always N/A
            if normalized["status"] == "COMPLIANT":
                normalized["severity"] = "N/A"
            else:
                # Assign default control severity
                normalized["severity"] = control_default_severity
                    
            # 3. evidence_strength
            strength = str(data.get("evidence_strength", "None")).strip()
            str_upper = strength.upper()
            if str_upper in ("STRONG", "MODERATE", "WEAK", "NONE"):
                normalized["evidence_strength"] = str_upper.capitalize()
            else:
                normalized["evidence_strength"] = "None"
                
            # 4. control_coverage
            try:
                coverage = int(str(data.get("control_coverage", 0)).strip())
                normalized["control_coverage"] = max(0, min(100, coverage))
            except (TypeError, ValueError):
                # Try to extract any digits if LLM returned text like "65%"
                digits = re.findall(r'\d+', str(data.get("control_coverage", "")))
                if digits:
                    normalized["control_coverage"] = max(0, min(100, int(digits[0])))
                else:
                    normalized["control_coverage"] = 0
                
            # 5. evidence
            evidence = data.get("evidence", [])
            if not isinstance(evidence, list):
                if isinstance(evidence, dict):
                    evidence = [evidence]
                else:
                    evidence = []
                    
            root_excerpt = data.get("evidence_quote") or data.get("evidence_snippet") or data.get("excerpt") or ""
            root_source = data.get("evidence_source") or data.get("source") or "Policy Document"
            root_page = data.get("page") or data.get("page_number") or "N/A"
            
            normalized_evidence = []
            for item in evidence:
                if isinstance(item, dict):
                    src = item.get("source") or item.get("document") or root_source or "Policy Document"
                    pg = item.get("page") or item.get("page_number") or root_page or "N/A"
                    exc = item.get("excerpt") or item.get("quote") or item.get("text") or root_excerpt or ""
                    if exc:
                        normalized_evidence.append({
                            "source": str(src),
                            "page": str(pg),
                            "excerpt": str(exc)
                        })
                        
            if not normalized_evidence and root_excerpt:
                normalized_evidence.append({
                    "source": str(root_source),
                    "page": str(root_page),
                    "excerpt": str(root_excerpt)
                })
                
            normalized["evidence"] = normalized_evidence
            
            # 6. evidence_count
            try:
                count = int(str(data.get("evidence_count", len(normalized["evidence"]))).strip())
                normalized["evidence_count"] = max(0, count)
            except (TypeError, ValueError):
                normalized["evidence_count"] = len(normalized["evidence"])
                
            # 7. business_impact
            normalized["business_impact"] = str(data.get("business_impact") or data.get("impact") or "")
            
            # 8. remediation_priority
            priority = str(data.get("remediation_priority", "Medium")).strip().upper()
            if priority in ("LOW", "MEDIUM", "HIGH", "IMMEDIATE"):
                normalized["remediation_priority"] = priority.capitalize()
            else:
                if "IMM" in priority:
                    normalized["remediation_priority"] = "Immediate"
                elif "HIGH" in priority:
                    normalized["remediation_priority"] = "High"
                elif "LOW" in priority:
                    normalized["remediation_priority"] = "Low"
                else:
                    normalized["remediation_priority"] = "Medium"
                    
            # 9. justification
            normalized["justification"] = str(data.get("justification") or data.get("reasoning") or data.get("explanation") or "")
            if not normalized["justification"].strip():
                normalized["justification"] = "No compliance justification was provided by the model."
                
            # 10. missing_requirements
            missing = data.get("missing_requirements", [])
            if isinstance(missing, str):
                missing = [missing]
            elif not isinstance(missing, list):
                missing = []
            normalized["missing_requirements"] = [str(m) for m in missing]
            
            # 11. recommendation
            normalized["recommendation"] = str(data.get("recommendation") or data.get("suggested_action") or "")
            
            return normalized

        # Parse XML helper
        def parse_xml_to_dict(xml_text: str) -> dict:
            parsed_data = {}
            expected_tags = ["status", "evidence_strength", "control_coverage", "evidence_count", 
                             "business_impact", "remediation_priority", "justification", "recommendation"]
            
            # Tag Repair Logic (pre-processing unclosed tags)
            repaired_text = xml_text.strip()
            
            for tag in expected_tags:
                if f"<{tag}>" in repaired_text and f"</{tag}>" not in repaired_text:
                    start_pos = repaired_text.find(f"<{tag}>") + len(tag) + 2
                    next_tag_pos = repaired_text.find("<", start_pos)
                    if next_tag_pos != -1:
                        repaired_text = repaired_text[:next_tag_pos] + f"</{tag}>" + repaired_text[next_tag_pos:]
                    else:
                        repaired_text = repaired_text + f"</{tag}>"

            if "<requirement>" in repaired_text and "</requirement>" not in repaired_text:
                repaired_text = re.sub(r'<requirement>([^<]+)(?!</requirement>)', r'<requirement>\1</requirement>', repaired_text)
                
            # Wrap in single root tag to parse with ElementTree
            xml_body = repaired_text
            first_tag_idx = xml_body.find("<")
            if first_tag_idx != -1:
                xml_body = xml_body[first_tag_idx:]
            last_tag_idx = xml_body.rfind(">")
            if last_tag_idx != -1:
                xml_body = xml_body[:last_tag_idx+1]
                
            root_wrapped = f"<root>{xml_body}</root>"
            
            def regex_get_tag(t, txt):
                m = re.search(rf'<{t}>(.*?)</{t}>', txt, re.DOTALL)
                if m:
                    return m.group(1).strip()
                # Fallback: if closing tag is missing, match up to the next tag or end of string
                m_fallback = re.search(rf'<{t}>(.*?)(?:<|\Z)', txt, re.DOTALL)
                if m_fallback:
                    return m_fallback.group(1).strip()
                return ""
                
            parsed_successfully = False
            try:
                root_el = ET.fromstring(root_wrapped)
                parsed_successfully = True
                
                for tag in expected_tags:
                    el = root_el.find(tag)
                    parsed_data[tag] = el.text.strip() if (el is not None and el.text) else ""
                    
                missing_reqs = []
                mr_el = root_el.find("missing_requirements")
                if mr_el is not None:
                    for req in mr_el.findall("requirement"):
                        if req.text:
                            missing_reqs.append(req.text.strip())
                else:
                    for req in root_el.findall("requirement"):
                        if req.text:
                            missing_reqs.append(req.text.strip())
                parsed_data["missing_requirements"] = missing_reqs
                
                evidence_items = []
                ei_el = root_el.find("evidence_items")
                targets = ei_el.findall("evidence_item") if ei_el is not None else root_el.findall("evidence_item")
                for item in targets:
                    src = item.find("source")
                    pg = item.find("page")
                    exc = item.find("excerpt")
                    if exc is None:
                        exc = item.find("quote")
                    src_txt = src.text.strip() if (src is not None and src.text) else ""
                    pg_txt = pg.text.strip() if (pg is not None and pg.text) else ""
                    exc_txt = exc.text.strip() if (exc is not None and exc.text) else ""
                    if exc_txt:
                        evidence_items.append({
                            "source": src_txt,
                            "page": pg_txt,
                            "excerpt": exc_txt
                        })
                parsed_data["evidence"] = evidence_items
                
            except Exception as e:
                print(f"[XML PARSER WARNING] ElementTree failed ({e}). Falling back to pure regex parser...", flush=True)
                
            if not parsed_successfully or not any(parsed_data.values()):
                for tag in expected_tags:
                    parsed_data[tag] = regex_get_tag(tag, repaired_text)
                    
                missing_reqs = re.findall(r'<requirement>(.*?)</requirement>', repaired_text, re.DOTALL)
                parsed_data["missing_requirements"] = [r.strip() for r in missing_reqs]
                
                evidence_items = []
                items_raw = re.findall(r'<evidence_item>(.*?)</evidence_item>', repaired_text, re.DOTALL)
                for item in items_raw:
                    src = regex_get_tag("source", item)
                    pg = regex_get_tag("page", item)
                    exc = regex_get_tag("excerpt", item) or regex_get_tag("quote", item)
                    if exc:
                        evidence_items.append({
                            "source": src,
                            "page": pg,
                            "excerpt": exc
                        })
                parsed_data["evidence"] = evidence_items
                
            return parsed_data

        # Format the prompt using standard python string formatting
        # This replaces '{var}' with values and '{{' / '}}' with literal '{' / '}'
        prompt = self.prompt_template.format(**input_dict)
        
        import os
        backend = os.environ.get("LLM_BACKEND", "ollama").strip().lower()
        print(f"[{backend.upper()} CHAIN] Querying '{self.model_name}' for {input_dict.get('control_id', 'unknown')}...", flush=True)
        try:
            from src.core.llm_client import query_llm
            content = query_llm(
                prompt=prompt,
                model=self.model_name,
                num_ctx=get_num_ctx(self.model_name),
                temperature=0.0
            )
            if not content or not content.strip():
                raise ValueError("Backend returned an empty response.")
                
            content_clean = content.strip()
            
            # Check if response is JSON (fallback support)
            if content_clean.startswith("{") or (content_clean.startswith("```json") and "{" in content_clean):
                print(f"[OLLAMA CHAIN] Model returned JSON instead of XML. Parsing as JSON...", flush=True)
                json_str = content_clean
                if "```" in json_str:
                    blocks = re.findall(r'```(?:json)?\s*(.*?)\s*```', json_str, re.DOTALL)
                    if blocks:
                        json_str = blocks[0]
                if not (json_str.startswith("{") and json_str.endswith("}")):
                    start_idx = json_str.find("{")
                    end_idx = json_str.rfind("}")
                    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                        json_str = json_str[start_idx:end_idx+1]
                data = json.loads(json_str)
            else:
                # Parse as XML (primary strategy)
                data = parse_xml_to_dict(content_clean)
                
            normalized_data = clean_and_normalize_data(data)
            return AuditFindingSchema(**normalized_data)
            
        except Exception as e:
            print(f"[OLLAMA CHAIN ERROR] Parse failed for {input_dict.get('control_id', 'unknown')}: {e}", flush=True)
            # Return a default NON_COMPLIANT finding schema to prevent crashes
            return AuditFindingSchema(
                status="NON_COMPLIANT",
                severity=control_default_severity,
                evidence_strength="None",
                control_coverage=0,
                evidence_count=0,
                business_impact="Potential security exposure or compliance gap due to unparseable model response.",
                remediation_priority="High" if control_default_severity in ("High", "Critical") else "Medium",
                justification=f"Auditor engine fell back to non-compliant: model output was completely unparseable. Technical details: {str(e)}",
                missing_requirements=[f"Verify control requirements for {input_dict.get('control_id', 'unknown')}"],
                recommendation=f"Establish, document, and implement procedures to satisfy {input_dict.get('control_id', 'unknown')}.",
                evidence=[]
            )

def get_generator_chain(model_name: str, url: str = None):
    """
    Returns a native Ollama chain for generating the initial draft finding.
    """
    return NativeOllamaChain(model_name, GENERATOR_PROMPT_TEMPLATE, url)

def get_reflection_chain(model_name: str, url: str = None):
    """
    Returns a native Ollama chain for critique and self-correction reflection.
    """
    return NativeOllamaChain(model_name, REFLECTION_PROMPT_TEMPLATE, url)
