# -*- coding: utf-8 -*-
import json
from typing import List, Tuple
from .base_parser import BaseParser
from .finding_schema import Finding
from .control_mapper import map_findings_list


class TrivyParser(BaseParser):
    """Parses Trivy JSON scan output (container image / filesystem / repo scans).
    Schema reference: https://aquasecurity.github.io/trivy/latest/docs/configuration/reporting/#json
    Handles both Vulnerabilities (CVE-based) and Misconfigurations (IaC) result types.
    """

    def can_parse(self, filename: str, content: str) -> bool:
        if not content:
            return False
        fn_lower = filename.lower()
        if "trivy" in fn_lower:
            return True
        if fn_lower.endswith(".json"):
            sample = content[:2000].lower()
            if "schemaversion" in sample and ("vulnerabilities" in sample or "misconfigurations" in sample):
                return True
        if "dependency-check" in fn_lower or "vulnerabilities" in content[:1000].lower():
            return True
        return False

    def parse(self, filename: str, content: str) -> Tuple[List[Finding], None]:
        findings: List[Finding] = []

        try:
            data = json.loads(content)
        except Exception as e:
            print(f"[TRIVY PARSER ERROR] Failed to parse '{filename}' as JSON: {e}", flush=True)
            return [], None

        results = data.get("Results") or []
        if not isinstance(results, list):
            print(f"[TRIVY PARSER WARNING] '{filename}' has no 'Results' array; nothing to extract.", flush=True)
            return [], None

        for result in results:
            target = str(result.get("Target") or data.get("ArtifactName") or filename)

            # ── CVE-based vulnerability findings ──────────────────────────
            for vuln in (result.get("Vulnerabilities") or []):
                vuln_id = str(vuln.get("VulnerabilityID") or "").strip()
                pkg_name = str(vuln.get("PkgName") or "")
                installed_ver = str(vuln.get("InstalledVersion") or "")
                fixed_ver = str(vuln.get("FixedVersion") or "")
                title = str(vuln.get("Title") or vuln_id or f"Vulnerable package: {pkg_name}")
                description = str(vuln.get("Description") or title)
                severity = str(vuln.get("Severity") or "UNKNOWN")

                cve_list = [vuln_id] if vuln_id.upper().startswith("CVE-") else []

                cvss_score = None
                cvss_vector = None
                cvss_data = vuln.get("CVSS") or {}
                for _, source_scores in cvss_data.items():
                    if isinstance(source_scores, dict):
                        if source_scores.get("V3Score") is not None:
                            cvss_score = source_scores.get("V3Score")
                            cvss_vector = source_scores.get("V3Vector")
                            break
                        if source_scores.get("V2Score") is not None:
                            cvss_score = source_scores.get("V2Score")
                            cvss_vector = source_scores.get("V2Vector")

                remediation = (
                    f"Update {pkg_name} from {installed_ver} to fixed version {fixed_ver}."
                    if fixed_ver else
                    f"No fixed version available yet for {pkg_name} {installed_ver}; monitor vendor advisory for {vuln_id}."
                )

                findings.append(Finding(
                    title=title,
                    severity=severity,
                    severity_score=cvss_score,
                    cvss_vector=cvss_vector,
                    cve_list=cve_list,
                    target=target,
                    description=description,
                    remediation=remediation,
                    evidence=f"Package: {pkg_name} | Installed: {installed_ver} | Fixed: {fixed_ver or 'N/A'}",
                    plugin_id=vuln_id,
                    source_tool="Trivy",
                ))

            # ── IaC / config misconfiguration findings (Dockerfile, Terraform, K8s, etc.) ──
            for misconf in (result.get("Misconfigurations") or []):
                misconf_id = str(misconf.get("ID") or "")
                title = str(misconf.get("Title") or misconf_id or "Misconfiguration")
                severity = str(misconf.get("Severity") or "UNKNOWN")
                description = str(misconf.get("Description") or title)
                resolution = str(misconf.get("Resolution") or "Review and remediate per Trivy misconfiguration guidance.")
                message = str(misconf.get("Message") or "")

                findings.append(Finding(
                    title=title,
                    severity=severity,
                    target=target,
                    description=description,
                    remediation=resolution,
                    evidence=message,
                    plugin_id=misconf_id,
                    source_tool="Trivy",
                ))

        map_findings_list(findings)
        print(f"[TRIVY PARSER] Extracted {len(findings)} finding(s) from '{filename}'.", flush=True)
        return findings, None
