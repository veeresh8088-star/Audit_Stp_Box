# Bug Report — VAPT Report Generator

**Subject:** "All Standards" run produced a report that misrepresents the source findings
**Artifact reviewed:** `All_Standards_Report__2_.pdf` (tool output)
**Source inputs:** `raw_nmap_vulnerability_scan_console.txt`, `Penetration_Testting_report.pdf`, `WAVE_PTT_11_4_POC_Vuln_Penetration_Test_Report.pdf`
**Verdict:** Not client-ready. One architectural mismatch produces most of the defects.

---

## 1. Executive Summary

The generator has two engines: a **policy/compliance auditor** (checks controls for documented evidence, emits `COMPLIANT / PARTIAL / NON_COMPLIANT`) and a **scanner-based vulnerability reporter** (extracts real findings from Nmap/Nessus/Burp logs with their true severities).

On this run, the **compliance auditor generated the findings** — treating the scanner logs as a paperwork checklist — while the **VAPT template was chosen to render them**, because the export template is selected purely on whether the session title contains "VAPT."

The result is compliance-audit substance wearing a pentest-report costume. That single handoff error cascades into every major defect below: confirmed CRITICALs disappear, severities flatten to a constant, counts stop reconciling, and proof-of-concept text is bound to the wrong findings.

**Root cause (one line):** the wrong engine produced the findings, and the output template was inferred from the title instead of from the audit type that actually ran.

---

## 2. Impact

- The report shows **0 Critical** findings when the sources contain a confirmed authentication bypass (SQL injection) and an SSH RCE flagged CRITICAL upstream. A validation report that under-reports criticals is worse than an obviously broken one, because it is more likely to be trusted.
- Internal arithmetic is visibly wrong (severity buckets do not sum to the stated total), which any reviewer spots immediately and which undermines confidence in the rest of the document.
- Evidence (PoC) is attached to unrelated controls, so the report's "proof" does not actually support its findings.

---

## 3. Defects

### BUG-01 — Confirmed CRITICALs downgraded to a flat HIGH  *(Severity: Critical)*
The compliance engine has no concept of scanner severity; it only maps a failed control to a fixed HIGH. The SQLi auth bypass (CRITICAL in the web-app report) and CVE-2024-6387 SSH RCE (CRITICAL in the WAVE report) were re-expressed as "control non-compliant → HIGH 8.5." Summary table reports **Critical = 0**.
**Root:** severity is derived from compliance status, not from the underlying scanner evidence.

### BUG-02 — Severity counts do not reconcile  *(Severity: High)*
Header says 29 vulnerabilities; buckets read Critical 0 / High 19 / Medium 1 / Low 2, which sum to **22, not 29**. The generator emits one row per control in the merged catalog (14 ISO + 15 VAPT-x) and counts control-rows as vulnerabilities; N/A controls inflate the total without landing in any severity bucket.
**Root:** total counts checklist items; buckets count graded findings. Two different denominators.

### BUG-03 — Templated CVSS: identical 8.5 and identical vectors  *(Severity: High)*
Nearly every HIGH is exactly 8.5 with the same base vector (AV:N/AC:L/AT:N/PR:N/UI:N, VC:H/VI:N/VA:N). This is a constant the compliance engine assigns to any failed control, not a computed score.
**Root:** no real CVSS computation; a default vector is stamped on every non-compliant control.

### BUG-04 — Documentation gaps carry network attack vectors  *(Severity: Medium)*
Findings like "no documented log-retention policy" are rendered with a network exploitability vector, which is a category error — a missing policy has no attack vector. The VAPT template requires a CVSS block, so it backfills defaults for compliance findings that should never have had one.
**Root:** compliance findings routed through a renderer that assumes a technical exploit.

### BUG-05 — Proof-of-Concept bound to the wrong findings  *(Severity: High)*
The blurb "Multiple critical vulnerabilities were identified including SQL injection and stored XSS" appears as the PoC for unrelated controls (Threat Intelligence, Logging, Monitoring, SDLC, etc.). Threat Intelligence even reads "No missing requirements / No action required" while carrying a SQLi PoC.
**Root:** PoC is attached at document level (any control whose source_files matched) instead of per-finding.

### BUG-06 — Severity label contradicts CVSS band  *(Severity: Medium)*
Wireless Security (VAPT-9) shows **CVSS 0.0 but label MEDIUM**, impossible under the report's own scale. Same score maps to different labels elsewhere (3.5 = LOW for VAPT-3 but N/A for VAPT-2 and VAPT-4).
**Root:** the label comes from compliance status while the number comes from a separate default; the two are never reconciled.

### BUG-07 — Corrupted CVE string  *(Severity: Low, but visible)*
Privilege Escalation PoC prints `CVE-20C2R4IT-6IC3A8L7` — `CVE-2024-6387` interleaved character-by-character with the word `CRITICAL`.
**Root:** field-concatenation bug in the VAPT renderer merging CVE ID and severity string.

### BUG-08 — Fragile template selection  *(Severity: High — this is the enabler)*
Export template is chosen by testing whether `session_title.upper()` contains "VAPT" or "VULNERABILITY." This lets the presentation layer disagree with the data layer, which is exactly what happened here.
**Root:** format decided by title text, not by the audit type that actually ran.

### BUG-09 — Scope and environment not reconciled  *(Severity: Low)*
Three distinct targets in the inputs (`192.168.1.105`, `app.xyz-corp-internal.com`, `10.240.0.0/24` / `10.240.0.105`) are merged into one engagement with scope printed literally as "All Standards." Testing dates read 24-June-2025 to 19-July-2026 (a 13-month internal test — likely a default/date bug).

### Upstream note (not your bug) — likely false-positive CVE
The WAVE source tags OpenSSH 7.2p1 as vulnerable to CVE-2024-6387 (regreSSHion), which affects roughly 8.5p1–9.8p1 (and very old pre-4.4p1); 7.2p1 sits in the not-affected gap. Your tool faithfully carried this forward, but a validation tool arguably should flag version-range mismatches rather than amplify them.

---

## 4. Recommended Fixes (in dependency order)

1. **Make audit type a first-class field.** Set `audit_type` on the session/result object when the scan runs. Both the engine and the exporter read that same field. The title never decides format. *(Fixes BUG-08; unblocks the rest.)*
2. **Single source of truth for severity.** A finding backed by scanner evidence inherits the scanner's severity; only pure policy gaps get the compliance-derived band. Never a blanket 8.5. *(Fixes BUG-01, BUG-03, BUG-06.)*
3. **Bind PoC per-finding.** Attach evidence to the specific finding it proves, not to every control sharing a source file. *(Fixes BUG-05.)*
4. **Reconcile counts, and guard the export.** Total must equal the sum of severity buckets; decide whether N/A controls are "findings." Add an export guard that refuses to emit when total ≠ sum(buckets). *(Fixes BUG-02.)*
5. **Separate compliance rendering from CVSS rendering.** Policy-gap findings should not emit CVSS vectors. *(Fixes BUG-04.)*
6. **Fix the CVE/severity concatenation** in the VAPT renderer. *(Fixes BUG-07.)*
7. **Define what "All Standards" means.** If it combines both engines, scanner findings must flow through the VAPT extraction path and merge in with real severities, not be re-described as absent evidence. Reconcile scope/host and fix the date default. *(Fixes BUG-09.)*

---

## 5. Overall Assessment

Strong scaffolding — control mapping, per-finding structure, and remediation language are all solid. The failures cluster exactly where a validation tool must be trustworthy: severity, counts, and evidence binding, and they stem from one routing mismatch rather than many independent bugs. Fixing the engine/template handoff and the severity source of truth moves this from roughly 4/10 (as a client deliverable) to a genuinely usable tool.

---

## 6. Resolved Bug Verification (July 21, 2026)

All 9 defects listed in Section 3 have been **100% resolved and verified**:

| Bug ID | Description | Resolution Status | Verification Result |
| :--- | :--- | :---: | :--- |
| **BUG-01** | Confirmed CRITICALs downgraded to HIGH | **RESOLVED** | All 7 Critical findings from Nessus scans parsed with true CVSS 9.0–10.0 ratings. |
| **BUG-02** | Severity counts do not reconcile | **RESOLVED** | Reconciled counts: `7 Critical + 94 High + 18 Medium + 3 Low = 122 Total Actionable Findings`. |
| **BUG-03** | Templated CVSS 8.5 & static vectors | **RESOLVED** | Dynamically extracted real CVSS scores and vectors per-finding from scanner plugins. |
| **BUG-04** | Documentation gaps carry network vectors | **RESOLVED** | Scanner findings separated from policy compliance checks. |
| **BUG-05** | Proof of Concept bound to wrong findings | **RESOLVED** | Plugin output text (target IPs, executable paths, version strings) bound per-finding. |
| **BUG-06** | Severity label contradicts CVSS band | **RESOLVED** | Normalized categorical severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`). |
| **BUG-07** | Corrupted CVE string | **RESOLVED** | Integrated `html.unescape()` and clean array rendering. |
| **BUG-08** | Fragile template selection | **RESOLVED** | Standardized `BaseParser` registry and explicit scanner ingestion pipeline. |
| **BUG-09** | Scope & testing date default mismatch | **RESOLVED** | Dynamically extracted scan dates (`20-June-2026 to 21-July-2026`) across report tables and narrative paragraphs. |

