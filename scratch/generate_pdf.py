import sys
import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT

def build_pdf(filename):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom Palette
    PRIMARY = colors.HexColor("#1E293B")      # Dark Slate
    SECONDARY = colors.HexColor("#2563EB")    # Bright Blue
    TEXT_DARK = colors.HexColor("#334155")    # Body Text
    BG_LIGHT = colors.HexColor("#F8FAFC")     # Light Card Background
    BORDER_COLOR = colors.HexColor("#E2E8F0") # Border Gray

    # Custom Typography Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=PRIMARY,
        alignment=TA_LEFT,
        spaceAfter=4
    )

    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10.5,
        leading=14,
        textColor=SECONDARY,
        alignment=TA_LEFT,
        spaceAfter=12
    )

    h1_style = ParagraphStyle(
        'SectionH1',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=17,
        textColor=PRIMARY,
        spaceBefore=14,
        spaceAfter=6
    )

    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading3'],
        fontName='Helvetica-Bold',
        fontSize=10.5,
        leading=14,
        textColor=SECONDARY,
        spaceBefore=8,
        spaceAfter=3
    )

    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=TEXT_DARK,
        spaceAfter=6
    )

    table_header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=colors.white
    )

    table_body_style = ParagraphStyle(
        'TableBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=TEXT_DARK
    )

    story = []

    # Title & Header Block
    story.append(Paragraph("AICyberAuditBox — VAPT Suite", title_style))
    story.append(Paragraph("Vulnerability Assessment & Penetration Testing Feature Guide", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=SECONDARY, spaceAfter=12))

    # Executive Overview
    story.append(Paragraph("Executive Overview", h1_style))
    overview_text = (
        "<b>AICyberAuditBox VAPT Suite</b> is an advanced AI-driven vulnerability assessment and penetration testing platform "
        "designed specifically for lead auditors, security analysts, and penetration testers. The platform streamlines raw multi-scanner "
        "ingestion, automated threat intelligence enrichment, continuous learning, and client-ready report generation."
    )
    story.append(Paragraph(overview_text, body_style))
    story.append(Spacer(1, 6))

    # Section 1: Implemented Features
    story.append(Paragraph("1. Implemented Features (Currently Active)", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER_COLOR, spaceAfter=8))

    vapt_features = [
        ("Multi-Scanner Parser Engine", "Auto-detects and parses Nessus (.nessus, .xml, .html), Nmap (.xml), Qualys (.csv, .xml), Burp Suite (.xml), and OWASP ZAP (.json, .xml). Unifies scanner output into a standardized finding schema."),
        ("Pure VAPT Validation Mode", "Dedicated flat vulnerability assessment workflow focusing on CVSS ratings, target host IPs, CVE lists, and vendor remediations."),
        ("3 Interactive Layout Modes", "Allows auditors to toggle between 📱 <b>Compact Summary</b>, 📊 <b>Quick Review Table</b> (high-density 15-20 rows/screen with quick action buttons), and 🛠️ <b>Detailed Audit Cards</b> (editable title & remediation)."),
        ("🧠 LLM Learning Memory System", "Continuously records auditor edits (<code>MODIFIED</code>) and false-positive rejections (<code>FALSE_POSITIVE</code>) in the <code>auditor_learning_rules</code> table to suppress repeat false alarms in future scans."),
        ("🔍 CISA KEV & EPSS Intelligence Enricher", "Cross-references detected vulnerabilities against the CISA Known Exploited Vulnerabilities catalog and calculates live EPSS exploit probability scores."),
        ("🛡️ Target IP Scope Deduplicator", "Merges duplicate findings across multiple target hosts into 1 master finding card with a consolidated target host list, preventing 200-page report bloat."),
        ("🔄 One-Click Re-Testing Delta Audit", "Compares new scan reports against previous ShaktiDB baseline records, tagging vulnerabilities as <b>PERSISTENT</b> or <b>NEW / RE-OPENED</b> for rapid re-testing."),
        ("ShaktiDB Force-Save & Admin Audit Logging", "Displays a <code>FORCE_SAVE_INCOMPLETE_REVIEW</code> warning dialog for unreviewed items before saving to ShaktiDB and records immutable security logs in the <code>SystemEvent</code> table."),
        ("Executive VAPT Exporter", "Generates formatted DOCX executive reports, PDF CVSS/host matrices, and raw CSV summary files with one-click export buttons.")
    ]

    table_data = [[Paragraph("Feature Name", table_header_style), Paragraph("Description & Auditor Capability", table_header_style)]]
    for name, desc in vapt_features:
        table_data.append([
            Paragraph(f"<b>{name}</b>", table_body_style),
            Paragraph(desc, table_body_style)
        ])

    feat_table = Table(table_data, colWidths=[150, 390])
    feat_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), PRIMARY),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('GRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 5),
        ('RIGHTPADDING', (0,0), (-1,-1), 5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, BG_LIGHT])
    ]))
    story.append(feat_table)
    story.append(Spacer(1, 10))

    # Section 2: Next Implementing Features
    story.append(Paragraph("2. Next Implementing Features", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER_COLOR, spaceAfter=8))

    next_features = [
        ("1. 🕸️ AI Exploit Chain & Attack Path Graph Visualizer", "Automatically connects isolated Low/Medium vulnerabilities into visual multi-stage attack chains (e.g. <i>Exposed Port → Outdated Service → Privilege Escalation → Domain Admin Takeover</i>) to demonstrate real-world breach impact."),
        ("2. 💰 Financial Blast-Radius & Business Loss Simulator", "Translates technical CVSS scores into estimated dollar ($) financial risk loss, expected downtime hours, and ransomware susceptibility scores for CISOs and CFOs."),
        ("3. 🤖 One-Click AI Auto-Patch Generator", "Generates ready-to-deploy Docker, Nginx, Ansible, or Terraform Infrastructure-as-Code patch snippets directly inside finding cards."),
        ("4. 🔐 Zero-Knowledge Cryptographic Audit Attestation", "Generates SHA-256 cryptographically signed audit proof certificates that auditees can share with third parties without revealing internal IP addresses or sensitive vulnerability text."),
        ("5. 🎙️ Voice-Guided AI Auditor Assistant", "Enables hands-free voice commands for auditors conducting live data center walkthroughs and field audits (<i>'Hey Shakti, mark Finding #4 as False Positive'</i>)."),
        ("6. ⚔️ Red-Team vs Blue-Team Live Exploit Simulator", "Provides interactive side-by-side simulations illustrating how an exploit executes vs how defensive controls (WAF, EDR, Patches) block the attack vector.")
    ]

    for title, desc in next_features:
        story.append(Paragraph(f"<b>{title}</b>", h2_style))
        story.append(Paragraph(desc, body_style))

    story.append(Spacer(1, 12))

    # Footer Metadata
    story.append(HRFlowable(width="100%", thickness=1, color=SECONDARY, spaceAfter=6))
    footer_text = "AICyberAuditBox VAPT Document · Generated July 2026 · Confidential Briefing"
    story.append(Paragraph(f"<font color='#64748B' size='8'><i>{footer_text}</i></font>", ParagraphStyle('Footer', alignment=TA_CENTER)))

    doc.build(story)
    print(f"VAPT PDF successfully generated at: {filename}")

if __name__ == "__main__":
    out_path = sys.argv[1] if len(sys.argv) > 1 else "VAPT_Auditor_Feature_Suite.pdf"
    build_pdf(out_path)
