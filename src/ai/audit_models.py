# -*- coding: utf-8 -*-
"""
Audit Models Module
Defines the Pydantic schemas used for structured LLM outputs and validation rules.
"""

from pydantic import BaseModel, Field, model_validator
from typing import Literal, List, Optional

class EvidenceItem(BaseModel):
    """
    Pydantic schema representing a single cited evidence item.
    """
    source: str = Field(description="Document Name")
    page: str = Field(description="Page Number")
    excerpt: str = Field(description="Supporting evidence text")

class AuditFindingSchema(BaseModel):
    """
    Pydantic schema representing a structured compliance audit finding.
    Determines compliance status based solely on documented evidence and control coverage.
    """
    status: Literal["COMPLIANT", "NON_COMPLIANT", "FALSE_POSITIVE"] = Field(
        description="The compliance status of the control based on the evidence."
    )
    severity: Literal["N/A", "Low", "Medium", "High", "Critical"] = Field(
        description="The severity level of the finding."
    )
    evidence_strength: Literal["Strong", "Moderate", "Weak", "None", "STRONG", "MODERATE", "WEAK", "NONE"] = Field(
        description="Strength of the documented evidence."
    )
    control_coverage: int = Field(
        ge=0,
        le=100,
        description="Estimated percentage of control requirements covered (0-100)."
    )
    evidence_count: int = Field(
        ge=0,
        description="Count of distinct evidence items cited."
    )
    business_impact: str = Field(
        default="",
        description="Potential impact of the identified gaps."
    )
    remediation_priority: Literal["Low", "Medium", "High", "Immediate"] = Field(
        description="Remediation priority for addressing gaps."
    )
    justification: str = Field(
        description="Detailed auditor explanation supported by evidence."
    )
    missing_requirements: List[str] = Field(
        default=[],
        description="Key requirements missing (required for NON_COMPLIANT, empty for COMPLIANT)."
    )
    recommendation: str = Field(
        default="",
        description="Specific remediation actions."
    )
    evidence: List[EvidenceItem] = Field(
        default=[],
        description="List of supporting evidence items."
    )
    policy_present: Literal["Yes", "No", "Partial", "YES", "NO", "PARTIAL"] = Field(
        default="No",
        description="Is a documented policy present for this control?"
    )
    evidence_present: Literal["Yes", "No", "Partial", "YES", "NO", "PARTIAL"] = Field(
        default="No",
        description="Is implementation evidence present for this control?"
    )
    severity_score: float = Field(
        default=0.0,
        description="Vulnerability score from 0.0 to 10.0"
    )

    @model_validator(mode='after')
    def enforce_compliance_rule_consistency(self) -> 'AuditFindingSchema':
        """
        Enforces strict compliance auditing consistency rules:
        1. If status is COMPLIANT or FALSE_POSITIVE, severity must be N/A.
        2. If status is COMPLIANT, at least one valid evidence quote must be present.
        3. If status is NON_COMPLIANT, severity cannot be N/A.
        4. Map severity based on severity_score if status is NON_COMPLIANT.
        """
        status_val = self.status
        severity_val = self.severity
        evidence_list = self.evidence or []

        # Rule 1: Compliant / False Positive rules
        if status_val in ("COMPLIANT", "FALSE_POSITIVE"):
            if severity_val != "N/A":
                object.__setattr__(self, 'severity', 'N/A')
            if status_val == "COMPLIANT":
                if not evidence_list:
                    raise ValueError("Compliance status cannot be set to 'COMPLIANT' if no evidence is found.")
                # Ensure at least one evidence has a valid quote
                has_valid_quote = any(e.excerpt and e.excerpt.strip() != "NOT_FOUND" for e in evidence_list)
                if not has_valid_quote:
                    raise ValueError("Compliance status cannot be set to 'COMPLIANT' if no verbatim evidence quote was found in the evidence excerpts.")

        # Rule 2: Gaps rules (Non-Compliant)
        elif status_val == "NON_COMPLIANT":
            # Map severity according to user's defined ranges, respecting explicit severity label
            sev_input = str(self.severity or "").strip().capitalize()
            score = self.severity_score

            if "Critical" in sev_input or "Crit" in sev_input:
                if score < 9.0:
                    score = 9.5
                mapped_sev = "Critical"
            elif "High" in sev_input or "P2" in sev_input:
                if score < 7.0 or score >= 9.0:
                    score = 8.5
                mapped_sev = "High"
            elif "Medium" in sev_input or "Med" in sev_input or "P3" in sev_input:
                if score < 4.0 or score >= 7.0:
                    score = 5.5
                mapped_sev = "Medium"
            elif "Low" in sev_input or "P4" in sev_input:
                if score < 0.1 or score >= 4.0:
                    score = 2.0
                mapped_sev = "Low"
            else:
                # Default to score-based mapping
                mapped_sev = "Medium"
                if score >= 9.0:
                    mapped_sev = "Critical"
                elif score >= 7.0:
                    mapped_sev = "High"
                elif score >= 4.0:
                    mapped_sev = "Medium"
                elif score >= 0.1:
                    mapped_sev = "Low"
                else:
                    score = 5.5
                    mapped_sev = "Medium"

            object.__setattr__(self, 'severity_score', score)
            object.__setattr__(self, 'severity', mapped_sev)


            if not self.business_impact or self.business_impact.strip() in ("", "NOT_FOUND"):
                object.__setattr__(self, 'business_impact', 'Potential security exposure or compliance gap due to missing controls.')
            if not self.recommendation or self.recommendation.strip() in ("", "NOT_FOUND"):
                object.__setattr__(self, 'recommendation', 'Establish and implement documented procedures to satisfy the control requirements.')

        return self
