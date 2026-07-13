# -*- coding: utf-8 -*-
"""
pii_redactor.py
Pure-regex PII sanitizer for audit report exports.
Applied only at DOCX/PDF export time — never touches DB records or Streamlit UI.

Patterns redacted:
  - Email addresses         → [EMAIL REDACTED]
  - IPv4 addresses          → [IP REDACTED]
  - Phone numbers (IN/UK)   → [PHONE REDACTED]
"""

import re

# ── Compiled patterns (compiled once at import time) ──────────────────────────

_EMAIL_PATTERN = re.compile(
    r'[\w.+\-]+@[\w\-]+\.(?:[a-zA-Z]{2,})',
    re.IGNORECASE
)

_IPV4_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

# Covers +91-XXXXXXXXXX, 91-XXXXXXXXXX, 0XXXXXXXXXX, +44-XXXXXXXXXX formats
_PHONE_PATTERN = re.compile(
    r'(?<!\d)'                        # not preceded by digit
    r'(?:\+?(?:91|44|1)[\s\-]?)?'    # optional country code
    r'(?:0)?'                          # optional leading zero
    r'[\d][\d\s\-]{8,12}[\d]'        # 8-12 digits with optional spaces/dashes
    r'(?!\d)',                         # not followed by digit
    re.IGNORECASE
)


def redact_pii(text: str) -> str:
    """
    Replaces PII patterns in text with redaction tokens.
    Returns the sanitized string. Input is unchanged if no patterns match.

    Args:
        text: The raw string to sanitize.

    Returns:
        Sanitized string with PII replaced by redaction tokens.
    """
    if not text or not isinstance(text, str):
        return text

    # Order matters: email before phone (emails contain @ which won't match phone)
    text = _EMAIL_PATTERN.sub("[EMAIL REDACTED]", text)
    text = _IPV4_PATTERN.sub("[IP REDACTED]", text)
    text = _PHONE_PATTERN.sub("[PHONE REDACTED]", text)

    return text
