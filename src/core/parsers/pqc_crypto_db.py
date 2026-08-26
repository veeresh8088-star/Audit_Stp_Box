# -*- coding: utf-8 -*-
"""
pqc_crypto_db.py -- Offline Cryptographic Algorithm Registry for PQC Fast Parser.

Three data sources (100% offline, no internet required):
  1. X509_OID_DB        -- NIST / ITU-T X.509 Object Identifier to algorithm map
  2. IANA_CIPHER_DB     -- IANA TLS Cipher Suite registry: name, 2-byte hex code,
                           key exchange, bulk cipher, quantum status, CWE ID
  3. LIBOQS_ALGO_DB     -- Open Quantum Safe (liboqs) algorithm catalogue,
                           including NIST Round 4 candidates and OQS experiments

Usage in pqc_parser.py:
    from .pqc_crypto_db import scan_oids_in_text, scan_iana_hex_in_text, scan_liboqs_in_text

Sources:
  - IANA: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
  - NIST OIDs: FIPS 203/204/205, NIST IR 8413, RFC 8032/8422
  - liboqs: https://openquantumsafe.org/liboqs/algorithms/
  - CWE-1240 / CWE-327: https://cwe.mitre.org/
"""
from __future__ import annotations
import re as _re
from typing import Optional

# ============================================================================
# SECTION 1 -- X.509 OID REGISTRY
# ============================================================================
# Format: { "OID_string": { name, category, quantum_status, severity,
#                           nist_ref, cwe } }
# quantum_status: "VULNERABLE" | "WEAK" | "SAFE"

X509_OID_DB: dict = {

    # -- Classical Asymmetric -- QUANTUM-VULNERABLE ---------------------------
    "1.2.840.113549.1.1.1":  {"name": "RSA",               "category": "Asymmetric Encryption (RSA)",          "quantum_status": "VULNERABLE", "severity": "CRITICAL", "nist_ref": "NIST SP 800-131A Rev 2", "cwe": "CWE-1240"},
    "1.2.840.113549.1.1.4":  {"name": "MD5withRSA",         "category": "Asymmetric Encryption (RSA)",          "quantum_status": "VULNERABLE", "severity": "CRITICAL", "nist_ref": "MD5 broken + RSA quantum-vulnerable", "cwe": "CWE-327"},
    "1.2.840.113549.1.1.5":  {"name": "SHA1withRSA",        "category": "Asymmetric Encryption (RSA)",          "quantum_status": "VULNERABLE", "severity": "CRITICAL", "nist_ref": "SHA-1 broken + RSA quantum-vulnerable", "cwe": "CWE-327"},
    "1.2.840.113549.1.1.11": {"name": "SHA256withRSA",      "category": "Asymmetric Encryption (RSA)",          "quantum_status": "VULNERABLE", "severity": "HIGH",     "nist_ref": "NIST SP 800-131A Rev 2", "cwe": "CWE-1240"},
    "1.2.840.113549.1.1.12": {"name": "SHA384withRSA",      "category": "Asymmetric Encryption (RSA)",          "quantum_status": "VULNERABLE", "severity": "HIGH",     "nist_ref": "NIST SP 800-131A Rev 2", "cwe": "CWE-1240"},
    "1.2.840.113549.1.1.13": {"name": "SHA512withRSA",      "category": "Asymmetric Encryption (RSA)",          "quantum_status": "VULNERABLE", "severity": "HIGH",     "nist_ref": "NIST SP 800-131A Rev 2", "cwe": "CWE-1240"},
    # DSA
    "1.2.840.10040.4.1":     {"name": "DSA",                "category": "Asymmetric Digital Signature (DSA)",   "quantum_status": "VULNERABLE", "severity": "CRITICAL", "nist_ref": "NIST SP 800-131A Rev 2 -- DSA disallowed", "cwe": "CWE-1240"},
    "1.2.840.10040.4.3":     {"name": "SHA1withDSA",        "category": "Asymmetric Digital Signature (DSA)",   "quantum_status": "VULNERABLE", "severity": "CRITICAL", "nist_ref": "SHA-1 broken + DSA quantum-vulnerable", "cwe": "CWE-327"},
    # Diffie-Hellman
    "1.2.840.113549.1.3.1":  {"name": "Diffie-Hellman Key Exchange", "category": "Key Exchange (Diffie-Hellman)", "quantum_status": "VULNERABLE", "severity": "HIGH", "nist_ref": "NIST SP 800-56A Rev 3 -- DH deprecated", "cwe": "CWE-1240"},
    # ECC -- Quantum Vulnerable
    "1.2.840.10045.2.1":     {"name": "EC Public Key",       "category": "Elliptic Curve Cryptography (ECC)",   "quantum_status": "VULNERABLE", "severity": "HIGH",     "nist_ref": "NIST SP 800-186", "cwe": "CWE-1240"},
    "1.2.840.10045.4.3.2":   {"name": "ECDSA with SHA-256",  "category": "Elliptic Curve Cryptography (ECC)",   "quantum_status": "VULNERABLE", "severity": "HIGH",     "nist_ref": "FIPS 204 -- migrate to ML-DSA", "cwe": "CWE-1240"},
    "1.2.840.10045.4.3.3":   {"name": "ECDSA with SHA-384",  "category": "Elliptic Curve Cryptography (ECC)",   "quantum_status": "VULNERABLE", "severity": "HIGH",     "nist_ref": "FIPS 204 -- migrate to ML-DSA", "cwe": "CWE-1240"},
    "1.2.840.10045.4.3.4":   {"name": "ECDSA with SHA-512",  "category": "Elliptic Curve Cryptography (ECC)",   "quantum_status": "VULNERABLE", "severity": "HIGH",     "nist_ref": "FIPS 204 -- migrate to ML-DSA", "cwe": "CWE-1240"},
    # Named curves
    "1.2.840.10045.3.1.7":   {"name": "P-256 / secp256r1",   "category": "Elliptic Curve Cryptography (ECC)",   "quantum_status": "VULNERABLE", "severity": "HIGH",     "nist_ref": "NIST SP 800-186", "cwe": "CWE-1240"},
    "1.3.132.0.34":          {"name": "P-384 / secp384r1",   "category": "Elliptic Curve Cryptography (ECC)",   "quantum_status": "VULNERABLE", "severity": "HIGH",     "nist_ref": "NIST SP 800-186", "cwe": "CWE-1240"},
    "1.3.132.0.35":          {"name": "P-521 / secp521r1",   "category": "Elliptic Curve Cryptography (ECC)",   "quantum_status": "VULNERABLE", "severity": "HIGH",     "nist_ref": "NIST SP 800-186", "cwe": "CWE-1240"},
    "1.3.132.0.10":          {"name": "secp256k1",            "category": "Elliptic Curve Cryptography (ECC)",   "quantum_status": "VULNERABLE", "severity": "HIGH",     "nist_ref": "NIST SP 800-186", "cwe": "CWE-1240"},
    "1.3.132.0.33":          {"name": "P-224 / secp224r1",   "category": "Elliptic Curve Cryptography (ECC)",   "quantum_status": "VULNERABLE", "severity": "CRITICAL", "nist_ref": "NIST SP 800-131A Rev 2 -- deprecated", "cwe": "CWE-1240"},
    # EdDSA / X25519
    "1.3.101.110":           {"name": "X25519 (key agreement)",  "category": "Elliptic Curve Cryptography (ECC)", "quantum_status": "VULNERABLE", "severity": "HIGH", "nist_ref": "Upgrade to X25519MLKEM768 hybrid -- FIPS 203", "cwe": "CWE-1240"},
    "1.3.101.111":           {"name": "X448 (key agreement)",    "category": "Elliptic Curve Cryptography (ECC)", "quantum_status": "VULNERABLE", "severity": "HIGH", "nist_ref": "Migrate to ML-KEM -- FIPS 203", "cwe": "CWE-1240"},
    "1.3.101.112":           {"name": "Ed25519",                  "category": "Elliptic Curve Cryptography (ECC)", "quantum_status": "VULNERABLE", "severity": "HIGH", "nist_ref": "Migrate to ML-DSA-44 or ML-DSA-65 -- FIPS 204", "cwe": "CWE-1240"},
    "1.3.101.113":           {"name": "Ed448",                    "category": "Elliptic Curve Cryptography (ECC)", "quantum_status": "VULNERABLE", "severity": "HIGH", "nist_ref": "Migrate to ML-DSA -- FIPS 204", "cwe": "CWE-1240"},

    # -- NIST PQC-SELECTED -- QUANTUM-SAFE ------------------------------------
    # ML-KEM (FIPS 203)
    "2.16.840.1.101.3.4.4.1": {"name": "ML-KEM-512 (Kyber512)",  "category": "PQC Key Encapsulation (NIST FIPS 203)", "quantum_status": "SAFE", "severity": "INFO", "nist_ref": "FIPS 203 -- security level 1", "cwe": None},
    "2.16.840.1.101.3.4.4.2": {"name": "ML-KEM-768 (Kyber768)",  "category": "PQC Key Encapsulation (NIST FIPS 203)", "quantum_status": "SAFE", "severity": "INFO", "nist_ref": "FIPS 203 -- security level 3 (recommended)", "cwe": None},
    "2.16.840.1.101.3.4.4.3": {"name": "ML-KEM-1024 (Kyber1024)","category": "PQC Key Encapsulation (NIST FIPS 203)", "quantum_status": "SAFE", "severity": "INFO", "nist_ref": "FIPS 203 -- security level 5", "cwe": None},
    # ML-DSA (FIPS 204)
    "2.16.840.1.101.3.4.3.17": {"name": "ML-DSA-44 (Dilithium2)", "category": "PQC Digital Signature (NIST FIPS 204)", "quantum_status": "SAFE", "severity": "INFO", "nist_ref": "FIPS 204 -- security level 2", "cwe": None},
    "2.16.840.1.101.3.4.3.18": {"name": "ML-DSA-65 (Dilithium3)", "category": "PQC Digital Signature (NIST FIPS 204)", "quantum_status": "SAFE", "severity": "INFO", "nist_ref": "FIPS 204 -- security level 3 (recommended)", "cwe": None},
    "2.16.840.1.101.3.4.3.19": {"name": "ML-DSA-87 (Dilithium5)", "category": "PQC Digital Signature (NIST FIPS 204)", "quantum_status": "SAFE", "severity": "INFO", "nist_ref": "FIPS 204 -- security level 5", "cwe": None},
    # SLH-DSA (FIPS 205)
    "2.16.840.1.101.3.4.3.20": {"name": "SLH-DSA-SHA2-128s",  "category": "PQC Digital Signature (NIST FIPS 205)", "quantum_status": "SAFE", "severity": "INFO", "nist_ref": "FIPS 205", "cwe": None},
    "2.16.840.1.101.3.4.3.21": {"name": "SLH-DSA-SHA2-128f",  "category": "PQC Digital Signature (NIST FIPS 205)", "quantum_status": "SAFE", "severity": "INFO", "nist_ref": "FIPS 205", "cwe": None},
    "2.16.840.1.101.3.4.3.22": {"name": "SLH-DSA-SHA2-192s",  "category": "PQC Digital Signature (NIST FIPS 205)", "quantum_status": "SAFE", "severity": "INFO", "nist_ref": "FIPS 205", "cwe": None},
    "2.16.840.1.101.3.4.3.27": {"name": "SLH-DSA-SHAKE-128s", "category": "PQC Digital Signature (NIST FIPS 205)", "quantum_status": "SAFE", "severity": "INFO", "nist_ref": "FIPS 205", "cwe": None},
    # FN-DSA / Falcon
    "1.3.9999.3.6": {"name": "Falcon-512 / FN-DSA-512",   "category": "PQC Digital Signature (NIST IR 8413)", "quantum_status": "SAFE", "severity": "INFO", "nist_ref": "NIST IR 8413", "cwe": None},
    "1.3.9999.3.9": {"name": "Falcon-1024 / FN-DSA-1024", "category": "PQC Digital Signature (NIST IR 8413)", "quantum_status": "SAFE", "severity": "INFO", "nist_ref": "NIST IR 8413", "cwe": None},
    # Early liboqs OIDs (pre-FIPS, used in OQS test deployments)
    "1.3.6.1.4.1.2.267.7.4.4":   {"name": "Kyber768 (pre-FIPS OID, liboqs)", "category": "PQC Key Encapsulation (NIST FIPS 203)", "quantum_status": "SAFE", "severity": "INFO", "nist_ref": "Use FIPS OID 2.16.840.1.101.3.4.4.2 in production", "cwe": None},
    "1.3.6.1.4.1.2.267.7.6.5":   {"name": "Dilithium3 (pre-FIPS OID, liboqs)", "category": "PQC Digital Signature (NIST FIPS 204)", "quantum_status": "SAFE", "severity": "INFO", "nist_ref": "Use FIPS OID 2.16.840.1.101.3.4.3.18 in production", "cwe": None},
}


# ============================================================================
# SECTION 2 -- IANA TLS CIPHER SUITE DATABASE
# ============================================================================
# Format: { "XXXX": { name, kex, auth, bulk, mac, quantum_status, severity,
#                     tls_version, cwe } }
# hex_code: 4-char uppercase hex, e.g. "0035" = 0x00,0x35

IANA_CIPHER_DB: dict = {
    # TLS 1.3 suites (classical KEX -- key exchange still quantum-vulnerable)
    "1301": {"name": "TLS_AES_128_GCM_SHA256",              "kex": "TLS1.3 negotiated", "auth": "cert", "bulk": "AES-128-GCM",      "mac": "SHA-256", "quantum_status": "VULNERABLE", "severity": "HIGH",     "tls_version": "TLS1.3", "cwe": "CWE-1240"},
    "1302": {"name": "TLS_AES_256_GCM_SHA384",              "kex": "TLS1.3 negotiated", "auth": "cert", "bulk": "AES-256-GCM",      "mac": "SHA-384", "quantum_status": "VULNERABLE", "severity": "HIGH",     "tls_version": "TLS1.3", "cwe": "CWE-1240"},
    "1303": {"name": "TLS_CHACHA20_POLY1305_SHA256",         "kex": "TLS1.3 negotiated", "auth": "cert", "bulk": "ChaCha20-Poly1305","mac": "SHA-256", "quantum_status": "VULNERABLE", "severity": "HIGH",     "tls_version": "TLS1.3", "cwe": "CWE-1240"},
    # X25519MLKEM768 -- safe hybrid PQC KEM NamedGroup
    "6399": {"name": "X25519MLKEM768 (TLS1.3 NamedGroup)",  "kex": "X25519+ML-KEM-768 hybrid", "auth": "cert", "bulk": "N/A", "mac": "N/A", "quantum_status": "SAFE", "severity": "INFO", "tls_version": "TLS1.3", "cwe": None},
    # NULL / Anon -- critically weak
    "0000": {"name": "TLS_NULL_WITH_NULL_NULL",              "kex": "None",  "auth": "None",  "bulk": "None",       "mac": "None",    "quantum_status": "WEAK",       "severity": "CRITICAL", "tls_version": "ALL",    "cwe": "CWE-327"},
    "0001": {"name": "TLS_RSA_WITH_NULL_MD5",               "kex": "RSA",   "auth": "RSA",   "bulk": "None",       "mac": "MD5",     "quantum_status": "VULNERABLE", "severity": "CRITICAL", "tls_version": "TLS1.2", "cwe": "CWE-327"},
    "0002": {"name": "TLS_RSA_WITH_NULL_SHA",               "kex": "RSA",   "auth": "RSA",   "bulk": "None",       "mac": "SHA-1",   "quantum_status": "VULNERABLE", "severity": "CRITICAL", "tls_version": "TLS1.2", "cwe": "CWE-327"},
    # Static RSA -- no PFS, quantum-vulnerable
    "0004": {"name": "TLS_RSA_WITH_RC4_128_MD5",            "kex": "RSA",   "auth": "RSA",   "bulk": "RC4-128",    "mac": "MD5",     "quantum_status": "VULNERABLE", "severity": "CRITICAL", "tls_version": "TLS1.2", "cwe": "CWE-327"},
    "0005": {"name": "TLS_RSA_WITH_RC4_128_SHA",            "kex": "RSA",   "auth": "RSA",   "bulk": "RC4-128",    "mac": "SHA-1",   "quantum_status": "VULNERABLE", "severity": "CRITICAL", "tls_version": "TLS1.2", "cwe": "CWE-327"},
    "000A": {"name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",       "kex": "RSA",   "auth": "RSA",   "bulk": "3DES-EDE",   "mac": "SHA-1",   "quantum_status": "VULNERABLE", "severity": "CRITICAL", "tls_version": "TLS1.2", "cwe": "CWE-327"},
    "002F": {"name": "TLS_RSA_WITH_AES_128_CBC_SHA",        "kex": "RSA",   "auth": "RSA",   "bulk": "AES-128-CBC","mac": "SHA-1",   "quantum_status": "VULNERABLE", "severity": "CRITICAL", "tls_version": "TLS1.2", "cwe": "CWE-1240"},
    "0035": {"name": "TLS_RSA_WITH_AES_256_CBC_SHA",        "kex": "RSA",   "auth": "RSA",   "bulk": "AES-256-CBC","mac": "SHA-1",   "quantum_status": "VULNERABLE", "severity": "CRITICAL", "tls_version": "TLS1.2", "cwe": "CWE-1240"},
    "003C": {"name": "TLS_RSA_WITH_AES_128_CBC_SHA256",     "kex": "RSA",   "auth": "RSA",   "bulk": "AES-128-CBC","mac": "SHA-256", "quantum_status": "VULNERABLE", "severity": "HIGH",     "tls_version": "TLS1.2", "cwe": "CWE-1240"},
    "003D": {"name": "TLS_RSA_WITH_AES_256_CBC_SHA256",     "kex": "RSA",   "auth": "RSA",   "bulk": "AES-256-CBC","mac": "SHA-256", "quantum_status": "VULNERABLE", "severity": "HIGH",     "tls_version": "TLS1.2", "cwe": "CWE-1240"},
    "009C": {"name": "TLS_RSA_WITH_AES_128_GCM_SHA256",    "kex": "RSA",   "auth": "RSA",   "bulk": "AES-128-GCM","mac": "SHA-256", "quantum_status": "VULNERABLE", "severity": "HIGH",     "tls_version": "TLS1.2", "cwe": "CWE-1240"},
    "009D": {"name": "TLS_RSA_WITH_AES_256_GCM_SHA384",    "kex": "RSA",   "auth": "RSA",   "bulk": "AES-256-GCM","mac": "SHA-384", "quantum_status": "VULNERABLE", "severity": "HIGH",     "tls_version": "TLS1.2", "cwe": "CWE-1240"},
    # DHE-RSA -- PFS but quantum-vulnerable KEX
    "0016": {"name": "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",  "kex": "DHE",   "auth": "RSA",   "bulk": "3DES",       "mac": "SHA-1",   "quantum_status": "VULNERABLE", "severity": "CRITICAL", "tls_version": "TLS1.2", "cwe": "CWE-1240"},
    "0033": {"name": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",   "kex": "DHE",   "auth": "RSA",   "bulk": "AES-128-CBC","mac": "SHA-1",   "quantum_status": "VULNERABLE", "severity": "HIGH",     "tls_version": "TLS1.2", "cwe": "CWE-1240"},
    "0039": {"name": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",   "kex": "DHE",   "auth": "RSA",   "bulk": "AES-256-CBC","mac": "SHA-1",   "quantum_status": "VULNERABLE", "severity": "HIGH",     "tls_version": "TLS1.2", "cwe": "CWE-1240"},
    "009E": {"name": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256","kex": "DHE",   "auth": "RSA",   "bulk": "AES-128-GCM","mac": "SHA-256", "quantum_status": "VULNERABLE", "severity": "HIGH",     "tls_version": "TLS1.2", "cwe": "CWE-1240"},
    "009F": {"name": "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384","kex": "DHE",   "auth": "RSA",   "bulk": "AES-256-GCM","mac": "SHA-384", "quantum_status": "VULNERABLE", "severity": "HIGH",     "tls_version": "TLS1.2", "cwe": "CWE-1240"},
    # ECDHE-RSA -- PFS, quantum-vulnerable ECC KEX
    "C013": {"name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",    "kex": "ECDHE","auth": "RSA",   "bulk": "AES-128-CBC","mac": "SHA-1",   "quantum_status": "VULNERABLE", "severity": "HIGH", "tls_version": "TLS1.2", "cwe": "CWE-1240"},
    "C014": {"name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",    "kex": "ECDHE","auth": "RSA",   "bulk": "AES-256-CBC","mac": "SHA-1",   "quantum_status": "VULNERABLE", "severity": "HIGH", "tls_version": "TLS1.2", "cwe": "CWE-1240"},
    "C02F": {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "kex": "ECDHE","auth": "RSA",   "bulk": "AES-128-GCM","mac": "SHA-256", "quantum_status": "VULNERABLE", "severity": "HIGH", "tls_version": "TLS1.2", "cwe": "CWE-1240"},
    "C030": {"name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "kex": "ECDHE","auth": "RSA",   "bulk": "AES-256-GCM","mac": "SHA-384", "quantum_status": "VULNERABLE", "severity": "HIGH", "tls_version": "TLS1.2", "cwe": "CWE-1240"},
    "CCA8": {"name": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",  "kex": "ECDHE","auth": "RSA",   "bulk": "ChaCha20",   "mac": "SHA-256", "quantum_status": "VULNERABLE", "severity": "HIGH", "tls_version": "TLS1.2", "cwe": "CWE-1240"},
    # ECDHE-ECDSA -- PFS, quantum-vulnerable ECC KEX+Auth
    "C009": {"name": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",    "kex": "ECDHE","auth": "ECDSA","bulk": "AES-128-CBC","mac": "SHA-1",   "quantum_status": "VULNERABLE", "severity": "HIGH", "tls_version": "TLS1.2", "cwe": "CWE-1240"},
    "C00A": {"name": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",    "kex": "ECDHE","auth": "ECDSA","bulk": "AES-256-CBC","mac": "SHA-1",   "quantum_status": "VULNERABLE", "severity": "HIGH", "tls_version": "TLS1.2", "cwe": "CWE-1240"},
    "C02B": {"name": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "kex": "ECDHE","auth": "ECDSA","bulk": "AES-128-GCM","mac": "SHA-256", "quantum_status": "VULNERABLE", "severity": "HIGH", "tls_version": "TLS1.2", "cwe": "CWE-1240"},
    "C02C": {"name": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "kex": "ECDHE","auth": "ECDSA","bulk": "AES-256-GCM","mac": "SHA-384", "quantum_status": "VULNERABLE", "severity": "HIGH", "tls_version": "TLS1.2", "cwe": "CWE-1240"},
    "CCA9": {"name": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",  "kex": "ECDHE","auth": "ECDSA","bulk": "ChaCha20",   "mac": "SHA-256", "quantum_status": "VULNERABLE", "severity": "HIGH", "tls_version": "TLS1.2", "cwe": "CWE-1240"},
}


# ============================================================================
# SECTION 3 -- OPEN QUANTUM SAFE (liboqs) EXTENDED ALGORITHM CATALOGUE
# ============================================================================
# Includes NIST Round 4 candidates and OQS experimental algorithms.
# Format: { "keyword": { name, type, nist_round, security_level, nist_ref,
#                        quantum_status } }

LIBOQS_ALGO_DB: dict = {
    # NIST-Selected (Final Standards)
    "ml-kem":           {"name": "ML-KEM (CRYSTALS-Kyber)",           "type": "KEM", "nist_round": "Final",    "security_level": "1/3/5", "nist_ref": "FIPS 203",     "quantum_status": "SAFE"},
    "kyber":            {"name": "CRYSTALS-Kyber",                     "type": "KEM", "nist_round": "Final",    "security_level": "1/3/5", "nist_ref": "FIPS 203",     "quantum_status": "SAFE"},
    "kyber512":         {"name": "CRYSTALS-Kyber-512",                 "type": "KEM", "nist_round": "Final",    "security_level": "1",     "nist_ref": "FIPS 203",     "quantum_status": "SAFE"},
    "kyber768":         {"name": "CRYSTALS-Kyber-768",                 "type": "KEM", "nist_round": "Final",    "security_level": "3",     "nist_ref": "FIPS 203",     "quantum_status": "SAFE"},
    "kyber1024":        {"name": "CRYSTALS-Kyber-1024",                "type": "KEM", "nist_round": "Final",    "security_level": "5",     "nist_ref": "FIPS 203",     "quantum_status": "SAFE"},
    "ml-dsa":           {"name": "ML-DSA (CRYSTALS-Dilithium)",        "type": "SIG", "nist_round": "Final",    "security_level": "2/3/5", "nist_ref": "FIPS 204",     "quantum_status": "SAFE"},
    "dilithium":        {"name": "CRYSTALS-Dilithium",                 "type": "SIG", "nist_round": "Final",    "security_level": "2/3/5", "nist_ref": "FIPS 204",     "quantum_status": "SAFE"},
    "dilithium2":       {"name": "CRYSTALS-Dilithium-2 (ML-DSA-44)",   "type": "SIG", "nist_round": "Final",    "security_level": "2",     "nist_ref": "FIPS 204",     "quantum_status": "SAFE"},
    "dilithium3":       {"name": "CRYSTALS-Dilithium-3 (ML-DSA-65)",   "type": "SIG", "nist_round": "Final",    "security_level": "3",     "nist_ref": "FIPS 204",     "quantum_status": "SAFE"},
    "dilithium5":       {"name": "CRYSTALS-Dilithium-5 (ML-DSA-87)",   "type": "SIG", "nist_round": "Final",    "security_level": "5",     "nist_ref": "FIPS 204",     "quantum_status": "SAFE"},
    "slh-dsa":          {"name": "SLH-DSA (SPHINCS+)",                 "type": "SIG", "nist_round": "Final",    "security_level": "1/3/5", "nist_ref": "FIPS 205",     "quantum_status": "SAFE"},
    "sphincs":          {"name": "SPHINCS+",                           "type": "SIG", "nist_round": "Final",    "security_level": "1/3/5", "nist_ref": "FIPS 205",     "quantum_status": "SAFE"},
    "falcon":           {"name": "Falcon / FN-DSA",                   "type": "SIG", "nist_round": "Final",    "security_level": "1/5",   "nist_ref": "NIST IR 8413", "quantum_status": "SAFE"},
    "falcon-512":       {"name": "Falcon-512 / FN-DSA-512",           "type": "SIG", "nist_round": "Final",    "security_level": "1",     "nist_ref": "NIST IR 8413", "quantum_status": "SAFE"},
    "falcon-1024":      {"name": "Falcon-1024 / FN-DSA-1024",         "type": "SIG", "nist_round": "Final",    "security_level": "5",     "nist_ref": "NIST IR 8413", "quantum_status": "SAFE"},
    "fn-dsa":           {"name": "FN-DSA (Falcon)",                   "type": "SIG", "nist_round": "Final",    "security_level": "1/5",   "nist_ref": "NIST IR 8413", "quantum_status": "SAFE"},
    # NIST Round 4 KEM Candidates
    "frodokem":         {"name": "FrodoKEM",                           "type": "KEM", "nist_round": "Round 4",  "security_level": "1/3/5", "nist_ref": "NIST Round 4", "quantum_status": "SAFE"},
    "frodo640aes":      {"name": "FrodoKEM-640-AES",                  "type": "KEM", "nist_round": "Round 4",  "security_level": "1",     "nist_ref": "NIST Round 4", "quantum_status": "SAFE"},
    "frodo976aes":      {"name": "FrodoKEM-976-AES",                  "type": "KEM", "nist_round": "Round 4",  "security_level": "3",     "nist_ref": "NIST Round 4", "quantum_status": "SAFE"},
    "hqc":              {"name": "HQC (Hamming Quasi-Cyclic)",         "type": "KEM", "nist_round": "Round 4",  "security_level": "1/3/5", "nist_ref": "NIST Round 4", "quantum_status": "SAFE"},
    "bike":             {"name": "BIKE (Bit Flipping Key Encapsulation)", "type": "KEM", "nist_round": "Round 4", "security_level": "1/3", "nist_ref": "NIST Round 4", "quantum_status": "SAFE"},
    "classic-mceliece": {"name": "Classic McEliece",                  "type": "KEM", "nist_round": "Round 4",  "security_level": "1/3/5", "nist_ref": "NIST Round 4 (large key size)", "quantum_status": "SAFE"},
    "mceliece":         {"name": "Classic McEliece",                  "type": "KEM", "nist_round": "Round 4",  "security_level": "1/3/5", "nist_ref": "NIST Round 4", "quantum_status": "SAFE"},
    # OQS Experimental / Round 3
    "ntruprime":        {"name": "NTRU Prime",                         "type": "KEM", "nist_round": "Round 3",  "security_level": "1/3/5", "nist_ref": "OQS liboqs",   "quantum_status": "SAFE"},
    "saber":            {"name": "SABER",                              "type": "KEM", "nist_round": "Round 3",  "security_level": "1/3/5", "nist_ref": "OQS liboqs",   "quantum_status": "SAFE"},
    "picnic":           {"name": "Picnic",                             "type": "SIG", "nist_round": "Round 3",  "security_level": "1/3/5", "nist_ref": "OQS liboqs",   "quantum_status": "SAFE"},
    # Withdrawn / Broken -- flag these if seen
    "rainbow":          {"name": "Rainbow (WITHDRAWN -- classical attack found)", "type": "SIG", "nist_round": "Withdrawn", "security_level": "N/A", "nist_ref": "Withdrawn by NIST", "quantum_status": "WEAK"},
    "gemss":            {"name": "GeMSS (WITHDRAWN -- classical attack found)",   "type": "SIG", "nist_round": "Withdrawn", "security_level": "N/A", "nist_ref": "Withdrawn by NIST", "quantum_status": "WEAK"},
}


# ============================================================================
# SECTION 4 -- COMPILED REGEX PATTERNS (auto-built from DBs)
# ============================================================================

# OID regex -- matches dotted-decimal OID strings anywhere in text
_OID_PATTERN = _re.compile(
    r'\b(' + '|'.join(_re.escape(o) for o in X509_OID_DB if '.' in o) + r')\b'
)

# IANA hex -- matches 0xNN,0xNN  or  0xNNNN  or  raw hex pair NN,NN in TLS dumps
_IANA_HEX_PATTERN = _re.compile(
    r'(?:0[xX]([0-9A-Fa-f]{2})[,\s]+0[xX]([0-9A-Fa-f]{2})'  # 0x13,0x01
    r'|0[xX]([0-9A-Fa-f]{4}))',                                # 0x1301
    _re.IGNORECASE,
)

# liboqs keyword regex -- word-boundary matched to avoid false positives
_LIBOQS_PATTERN = _re.compile(
    r'\b(' + '|'.join(_re.escape(k) for k in LIBOQS_ALGO_DB) + r')\b',
    _re.IGNORECASE,
)


# ============================================================================
# SECTION 5 -- PUBLIC LOOKUP FUNCTIONS
# ============================================================================

def lookup_oid(oid_str: str) -> Optional[dict]:
    """Return OID metadata dict or None if not in X509_OID_DB."""
    return X509_OID_DB.get(oid_str.strip())


def lookup_iana_hex(hex_code: str) -> Optional[dict]:
    """
    Return IANA cipher suite metadata dict or None.
    hex_code accepts: '0035', '00,35', '0x00,0x35', '0x0035'.
    Normalizes to 4-char uppercase hex before lookup.
    """
    code = hex_code.upper().replace("0X", "").replace(",", "").replace(" ", "")
    if len(code) == 2:
        code = "00" + code
    return IANA_CIPHER_DB.get(code[:4])


def lookup_liboqs_algo(keyword: str) -> Optional[dict]:
    """Return liboqs algorithm metadata dict or None (case-insensitive)."""
    return LIBOQS_ALGO_DB.get(keyword.lower().strip())


def scan_oids_in_text(text: str) -> list:
    """
    Scan raw text for X.509 OID strings.
    Returns list of (oid_str, metadata_dict) tuples, deduped by OID.
    """
    seen = set()
    results = []
    for m in _OID_PATTERN.finditer(text):
        oid = m.group(1)
        if oid not in seen:
            seen.add(oid)
            meta = X509_OID_DB.get(oid)
            if meta:
                results.append((oid, meta))
    return results


def scan_iana_hex_in_text(text: str) -> list:
    """
    Scan raw text for IANA TLS cipher suite hex codes.
    Returns list of (hex_code_str, metadata_dict) tuples, deduped by code.
    """
    seen = set()
    results = []
    for m in _IANA_HEX_PATTERN.finditer(text):
        if m.group(1) and m.group(2):
            code = (m.group(1) + m.group(2)).upper()
        elif m.group(3):
            code = m.group(3).upper()
        else:
            continue
        if code not in seen:
            seen.add(code)
            meta = IANA_CIPHER_DB.get(code)
            if meta:
                results.append((code, meta))
    return results


def scan_liboqs_in_text(text: str) -> list:
    """
    Scan raw text for liboqs/OQS algorithm keywords.
    Returns list of (keyword_str, metadata_dict) tuples, deduped by keyword.
    """
    seen = set()
    results = []
    for m in _LIBOQS_PATTERN.finditer(text):
        kw = m.group(1).lower()
        if kw not in seen:
            seen.add(kw)
            meta = LIBOQS_ALGO_DB.get(kw)
            if meta:
                results.append((kw, meta))
    return results
