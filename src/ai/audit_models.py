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
    status: Literal["COMPLIANT", "PARTIAL", "NON_COMPLIANT"] = Field(
        description="The compliance status of the control based on the evidence."
    )
    severity: Literal["N/A", "Low", "Medium", "High", "Critical"] = Field(
        description="The severity level of the finding."
    )
    evidence_strength: Literal["Strong", "Moderate", "Weak", "None"] = Field(
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
        description="Key requirements missing (required for PARTIAL or NON_COMPLIANT, empty for COMPLIANT)."
    )
    recommendation: str = Field(
        default="",
        description="Specific remediation actions."
    )
    evidence: List[EvidenceItem] = Field(
        default=[],
        description="List of supporting evidence items."
    )

    @model_validator(mode='after')
    def enforce_compliance_rule_consistency(self) -> 'AuditFindingSchema':
        """
        Enforces strict compliance auditing consistency rules:
        1. If status is COMPLIANT, severity must be N/A, and at least one evidence item must be present.
        2. If status is PARTIAL or NON_COMPLIANT, severity cannot be N/A.
        """
        status_val = self.status
        severity_val = self.severity
        evidence_list = self.evidence or []

        # Rule 1: Compliant rules
        if status_val == "COMPLIANT":
            if severity_val != "N/A":
                object.__setattr__(self, 'severity', 'N/A')
            if not evidence_list:
                raise ValueError("Compliance status cannot be set to 'COMPLIANT' if no evidence is found.")
            # Ensure at least one evidence has a valid quote
            has_valid_quote = any(e.excerpt and e.excerpt.strip() != "NOT_FOUND" for e in evidence_list)
            if not has_valid_quote:
                raise ValueError("Compliance status cannot be set to 'COMPLIANT' if no verbatim evidence quote was found in the evidence excerpts.")

        # Rule 2: Gaps rules (Non-Compliant or Partial)
        elif status_val in ("NON_COMPLIANT", "PARTIAL"):
            if severity_val == "N/A":
                object.__setattr__(self, 'severity', 'Medium')
            if not self.business_impact or self.business_impact.strip() in ("", "NOT_FOUND"):
                object.__setattr__(self, 'business_impact', 'Potential security exposure or compliance gap due to missing controls.')
            if not self.recommendation or self.recommendation.strip() in ("", "NOT_FOUND"):
                object.__setattr__(self, 'recommendation', 'Establish and implement documented procedures to satisfy the control requirements.')

        return self
