# -*- coding: utf-8 -*-
"""
Forwarding module to src.core.validator
"""
from src.core.validator import (
    check_grounding,
    check_prompt_leakage,
    apply_confidence_gate,
    check_consistency,
    calculate_real_accuracy,
    potential_evidence_exists,
    validate_only,
    post_process,
    validate_findings,
    validate_cross_control_duplicates
)
