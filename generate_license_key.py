# -*- coding: utf-8 -*-
"""
AICyberAuditBox - License Key Generator CLI Tool
Generates signed activation keys for STPI Auditors, VAPT Teams, and Enterprise Customers.
"""

import sys
import hashlib
import json
import argparse
from datetime import datetime, timedelta, timezone

SECRET_SALT = "AICyberAuditBox_Master_Secret_2026"

def generate_signed_license_key(group="STPI / VAPT Auditor", days=30, audits=20, credit=2000.0, key_prefix="STPI"):
    """
    Generates a cryptographically signed license key string containing encoded parameters.
    """
    params = f"{key_prefix}:{group}:{days}:{audits}:{credit}:{SECRET_SALT}"
    sig = hashlib.sha256(params.encode("utf-8")).hexdigest()[:8].upper()
    
    # Format: PREFIX-DAYS-AUDITS-CREDIT-SIGNATURE
    license_key = f"{key_prefix.upper()}-{days}D-{audits}A-{int(credit)}INR-{sig}"
    
    print("=" * 65)
    print(" 🔑 AICyberAuditBox - Admin License Key Generator")
    print("=" * 65)
    print(f" Auditor Group  : {group}")
    print(f" Trial Validity : {days} Days")
    print(f" Audits Allowed : {audits} Full Audits")
    print(f" Token Credit   : ₹{credit:.2f}")
    print("-" * 65)
    print(f" GENERATED KEY  :  {license_key}")
    print("=" * 65)
    print("\n👉 Share this GENERATED KEY with your customer/auditor.")
    print("   They can paste it into the 'Activate Enterprise License' modal to unlock.\n")
    return license_key

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate AICyberAuditBox License Keys")
    parser.add_argument("--days", type=int, default=30, help="Trial validity in days (default: 30)")
    parser.add_argument("--audits", type=int, default=20, help="Allowed full audit runs (default: 20)")
    parser.add_argument("--credit", type=float, default=2000.0, help="Rupee credit balance (default: 2000)")
    parser.add_argument("--prefix", type=str, default="STPI", help="Key prefix e.g. STPI, VAPT, PRO (default: STPI)")
    parser.add_argument("--group", type=str, default="STPI / VAPT Auditor", help="Auditor group name")

    args = parser.parse_args()
    generate_signed_license_key(group=args.group, days=args.days, audits=args.audits, credit=args.credit, key_prefix=args.prefix)
