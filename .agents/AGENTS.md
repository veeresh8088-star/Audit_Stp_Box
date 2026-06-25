# Workspace Audit Reasoning Rules

All audit findings and evaluations in this workspace must follow these reasoning rules:

1. **Specific Control Scope**: Evaluate the document only against the specific ISO 27001 control being audited.
2. **Intent Determination**: First determine the control objective (intent) before evaluating evidence.
3. **Intent-Based Assessment**: Assess whether the documented evidence satisfies the control objective, not whether it matches specific keywords.
4. **No Framework Creep**: Do not introduce requirements from NIST, CIS Controls, SOC 2, PCI DSS, internal best practices, or generic security frameworks unless they are explicitly part of the evaluated ISO control.
5. **No Hallucinated Gaps**: Do not create gaps for controls, processes, forms, technologies, or procedures that are not explicitly required by the evaluated control.
6. **Equivalent Terms**: A requirement may be satisfied through equivalent controls, processes, or documented procedures even if different terminology is used.
7. **Traceable Gaps**: Every identified gap must be traceable to a specific requirement of the evaluated ISO control.
8. **Conservative Acceptability**: If evidence directly satisfies the control objective, do not mark the control as PARTIAL or NON_COMPLIANT solely because preferred implementation examples are absent.
9. **Ambiguity Resolution**: When evidence is ambiguous, explain the uncertainty and choose the most conservative evidence-based conclusion.
10. **Evidence Grounding**: Auditor reasoning must reference documented evidence and explain how it supports or fails to support the control objective.
11. **Substantiated Absences**: Missing requirements must be supported by evidence showing that the requirement is absent, not merely that a specific keyword was not found.
12. **Intent Over Keywords**: Prioritize intent-based evaluation over keyword matching.

### Example (ISO 27001 5.15 Access Control)
* **Intent**: Ensure access to facilities, systems, information, and assets is authorized and controlled.
* If the document demonstrates badge controls, visitor management, escort procedures, access authorization, and physical access restrictions, the control objective may be satisfied even if specific terms such as RBAC, PAM, access request forms, or access recertification are not present.
