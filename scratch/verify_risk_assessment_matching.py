import os
import sys
import urllib.request
import re

# Add project root to sys.path
sys.path.insert(0, os.path.abspath("."))

from src.core.parsers.burp_parser import BurpParser
from src.core.parsers.nessus_parser import NessusParser

url = "https://portswigger.net/burp/samplereport/burpscannersamplereport"
print(f"Fetching Burp Scanner Sample Report from {url}...")

req = urllib.request.Request(
    url, 
    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
)

try:
    with urllib.request.urlopen(req) as response:
        html_content = response.read().decode('utf-8', errors='ignore')
except Exception as e:
    print(f"Direct fetch error: {e}, reading local cached file...")
    cached_path = r"C:\Users\HP\.gemini\antigravity-ide\brain\0eb0fae6-f236-432b-96a9-40899968c404\.system_generated\steps\3777\content.md"
    with open(cached_path, 'r', encoding='utf-8') as f:
        html_content = f.read()

print(f"Successfully retrieved HTML report ({len(html_content)} bytes).")

parser = BurpParser()
can_p = parser.can_parse("burpscannersamplereport.html", html_content)
print(f"\n[1] BurpParser can_parse test: {can_p}")

actionable, info = parser.parse("burpscannersamplereport.html", html_content)

print(f"\n[2] Parsed Findings Results:")
print(f" - Actionable Technical Findings (High/Medium/Low): {len(actionable)}")
print(f" - Informational Findings: {len(info)}")

print("\n[3] Actionable Findings Details & Risk Assessment Matching:")
print("="*80)
for i, f in enumerate(actionable, 1):
    cve_str = ", ".join(f.cve_list) if f.cve_list else "Non-CVE (CWE/Scanner Confidence Based)"
    print(f"{i}. Title: {f.title}")
    print(f"   Severity: {f.severity} | Score: {f.severity_score:.1f} | Target: {f.target}")
    print(f"   CVE Mapping: {cve_str}")
    print(f"   Control Mapping: {f.control_id}")
    print(f"   Source Tool: {f.source_tool}")
    print("-" * 80)

print("\n[4] Sample Informational Findings (First 3):")
for i, f in enumerate(info[:3], 1):
    print(f"{i}. Title: {f.title} | Sev: {f.severity} | Target: {f.target}")

print("\nTEST COMPLETED SUCCESSFULLY!")
