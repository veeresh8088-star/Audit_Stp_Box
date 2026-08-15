# -*- coding: utf-8 -*-
"""Throwaway seed: one AuditReport + one Finding for the live edit->export
verification. Not part of the QA suite -- delete after use."""
import os
import sys
import json

sys.path.append(os.getcwd())

from src.db.database import SessionLocal, AuditReport, Finding, force_master

SESSION_ID = "editreporttest-001"
USERNAME = "e2e-verify-report@test.local"

with force_master():
    db = SessionLocal()
    existing = db.query(AuditReport).filter(AuditReport.session_id == SESSION_ID).first()
    if existing:
        db.query(Finding).filter(Finding.report_id == existing.id).delete()
        db.delete(existing)
        db.commit()

    report = AuditReport(
        session_id=SESSION_ID,
        session_title="Edit-to-Report Verification Session",
        created_by=USERNAME,
        framework="ISO 27001",
        controls_selected=json.dumps([1]),
        status="Draft",
    )
    db.add(report)
    db.commit()

    finding = Finding(
        report_id=report.id,
        control_id="5.1",
        control_name="5.1 Policies for Information Security",
        status="Non-Compliant",
        severity="P3 Medium",
        description="ORIGINAL_UNEDITED_TEXT_BEFORE_AUDITOR_REVIEW",
        evidence_snippet="original evidence snippet",
        recommendation="original recommendation",
        source_files="seed.docx",
        policy_present="Not Found",
        evidence_present="Not Found",
        is_saved_to_shakthi=False,
        human_verified=False,
    )
    db.add(finding)
    db.commit()
    print("Seeded report_id:", report.id, "finding_id:", finding.id)
    db.close()
