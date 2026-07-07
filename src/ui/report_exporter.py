import io as _io
from datetime import datetime
from docx import Document
from docx.shared import Pt, RGBColor, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
from fpdf import FPDF
from fpdf.enums import XPos, YPos

def export_docx_report(session_title, findings, resolved_list, status, comments=""):
    doc = Document()
    
    # Margins
    for section in doc.sections:
        section.top_margin    = Cm(2)
        section.bottom_margin = Cm(2)
        section.left_margin   = Cm(2.5)
        section.right_margin  = Cm(2.5)
        
        # Keep header/footer completely blank
        section.header.is_linked_to_previous = False
        for p in section.header.paragraphs:
            p.text = ""
        section.footer.is_linked_to_previous = False
        for p in section.footer.paragraphs:
            p.text = ""

    # Helpers
    def _rgb(r, g, b):
        return RGBColor(r, g, b)

    def _set_cell_bg(cell, hex_color):
        tcPr = cell._tc.get_or_add_tcPr()
        shd = OxmlElement('w:shd')
        shd.set(qn('w:val'), 'clear')
        shd.set(qn('w:color'), 'auto')
        shd.set(qn('w:fill'), hex_color)
        tcPr.append(shd)

    def _set_cell_borders(cell):
        tcPr = cell._tc.get_or_add_tcPr()
        tcBorders = OxmlElement('w:tcBorders')
        for side in ['top', 'left', 'bottom', 'right']:
            border = OxmlElement(f'w:{side}')
            border.set(qn('w:val'), 'single')
            border.set(qn('w:sz'), '4')
            border.set(qn('w:space'), '0')
            border.set(qn('w:color'), 'CCCCCC')
            tcBorders.append(border)
        tcPr.append(tcBorders)

    def _add_section_heading(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(14)
        p.paragraph_format.space_after = Pt(4)
        run = p.add_run(text)
        run.font.name = "Arial"
        run.font.size = Pt(13)
        run.bold = True
        run.font.color.rgb = _rgb(15, 23, 42)

    # ── COVER PAGE ─────────────────────────────────────────────────────────────
    # Title
    title_p = doc.add_paragraph()
    title_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title_p.paragraph_format.space_before = Pt(80)
    title_p.paragraph_format.space_after = Pt(20)
    run_title = title_p.add_run(f"IS Audit Report for {session_title}")
    run_title.font.name = "Arial"
    run_title.font.size = Pt(24)
    run_title.bold = True
    run_title.font.color.rgb = _rgb(15, 23, 42)

    # Subtitle
    sub_p = doc.add_paragraph()
    sub_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sub_p.paragraph_format.space_after = Pt(10)
    run_sub = sub_p.add_run("Engagement letter: SEBI/HO/ITD/ITD_VIAP/P/OW/2023/0000031833/1 dated 8.8.2023")
    run_sub.font.name = "Arial"
    run_sub.font.size = Pt(10)
    run_sub.font.color.rgb = _rgb(100, 116, 139)

    # Dates
    date_p1 = doc.add_paragraph()
    date_p1.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run_d1 = date_p1.add_run("Date of the Agreement: 15 September 2023.")
    run_d1.font.name = "Arial"
    run_d1.font.size = Pt(10)
    
    date_p2 = doc.add_paragraph()
    date_p2.alignment = WD_ALIGN_PARAGRAPH.CENTER
    date_p2.paragraph_format.space_after = Pt(80)
    run_d2 = date_p2.add_run(f"Date of Document: {datetime.now().strftime('%dth %B %Y')}")
    run_d2.font.name = "Arial"
    run_d2.font.size = Pt(10)

    # Audit Conducted By
    cb_p = doc.add_paragraph()
    cb_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run_cb = cb_p.add_run("Audit Conducted By:\n\n")
    run_cb.bold = True
    run_cb.font.size = Pt(11)
    
    run_aud1 = cb_p.add_run("Mr. Subhash Rao BE.MBA, CEH, CHFI, ISO 27001 LA, CEI, CND, CDPSE\n")
    run_aud1.font.size = Pt(10.5)
    run_aud2 = cb_p.add_run("Mr. Mahaveer Rajannavar BE.CEH, ISO 27001 LA\n\n\n")
    run_aud2.font.size = Pt(10.5)

    # Firm Info
    firm_p = doc.add_paragraph()
    firm_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run_firm = firm_p.add_run(
        "Digital Age Strategies Pvt Ltd\n"
        "# 28, “Om Arcade” 2nd & 3rd Floors, Thimmappa Reddy Layout,\n"
        "Hulimavu, Bannerghatta Road, Bangalore - 560076\n"
        "Ph: +91-80-26484636, 49568066, 26485148, 41503825, 41218560\n"
        "Mobile: 9448088666 / 9448055711\n"
        "Email: audit@digitalage.co.in, dinesh.shastri@digitalage.co.in"
    )
    run_firm.font.size = Pt(9.5)
    run_firm.font.color.rgb = _rgb(100, 116, 139)

    doc.add_page_break()

    # ── DOCUMENT CONTROL ───────────────────────────────────────────────────────
    _add_section_heading("Document Control:")
    
    tbl_prep = doc.add_table(rows=6, cols=2)
    tbl_prep.style = 'Table Grid'
    prep_data = [
        ("Document Title", f"Information Security Audit {session_title}"),
        ("Engagement Letter Ref", "SEBI/HO/ITD/ITD_VIAP/P/OW/2023/0000031833/1 dated 8.8.2023"),
        ("Date of the Agreement", "15 September 2023"),
        ("Date of Document", datetime.now().strftime("%dth %B %Y")),
        ("Version", "1.0"),
        ("Prepared By", "Digital Age Strategies Pvt Ltd")
    ]
    for r_idx, (label, val) in enumerate(prep_data):
        c1, c2 = tbl_prep.rows[r_idx].cells
        _set_cell_bg(c1, "F1F5F9")
        _set_cell_borders(c1)
        _set_cell_borders(c2)
        c1.paragraphs[0].add_run(label).bold = True
        c2.paragraphs[0].add_run(val)

    doc.add_paragraph()

    tbl_history = doc.add_table(rows=2, cols=3)
    tbl_history.style = 'Table Grid'
    hdr_history = tbl_history.rows[0].cells
    hdr_titles = ["Version", "Date", "Remarks / Reason of change"]
    for i, title in enumerate(hdr_titles):
        _set_cell_bg(hdr_history[i], "0F172A")
        _set_cell_borders(hdr_history[i])
        run = hdr_history[i].paragraphs[0].add_run(title)
        run.bold = True
        run.font.color.rgb = _rgb(255, 255, 255)
        
    c1, c2, c3 = tbl_history.rows[1].cells
    _set_cell_borders(c1)
    _set_cell_borders(c2)
    _set_cell_borders(c3)
    c1.paragraphs[0].add_run("1.0")
    c2.paragraphs[0].add_run(datetime.now().strftime("%dth %B %Y"))
    c3.paragraphs[0].add_run("Initial release of audit findings")

    doc.add_paragraph()

    tbl_dist = doc.add_table(rows=2, cols=4)
    tbl_dist.style = 'Table Grid'
    hdr_dist = tbl_dist.rows[0].cells
    dist_titles = ["Name", "Organization", "Designation", "Email Id"]
    for i, title in enumerate(dist_titles):
        _set_cell_bg(hdr_dist[i], "0F172A")
        _set_cell_borders(hdr_dist[i])
        run = hdr_dist[i].paragraphs[0].add_run(title)
        run.bold = True
        run.font.color.rgb = _rgb(255, 255, 255)
        
    c1, c2, c3, c4 = tbl_dist.rows[1].cells
    _set_cell_borders(c1)
    _set_cell_borders(c2)
    _set_cell_borders(c3)
    _set_cell_borders(c4)
    c1.paragraphs[0].add_run("SEBI ITD Team")
    c2.paragraphs[0].add_run("SEBI")
    c3.paragraphs[0].add_run("ITD Division Officers")
    c4.paragraphs[0].add_run("itd@sebi.gov.in")

    # ── DETAILS OF AUDITEE ─────────────────────────────────────────────────────
    _add_section_heading("Details of Auditee:")
    tbl_auditee = doc.add_table(rows=3, cols=3)
    tbl_auditee.style = 'Table Grid'
    auditee_data = [
        ("1", "Name of Organization", "Securities and Exchange Board of India"),
        ("2", "Audit Area", f"IS Audit of {session_title}"),
        ("3", "Location", "Mumbai, India")
    ]
    for r_idx, row_data in enumerate(auditee_data):
        c1, c2, c3 = tbl_auditee.rows[r_idx].cells
        _set_cell_borders(c1)
        _set_cell_borders(c2)
        _set_cell_borders(c3)
        c1.paragraphs[0].add_run(row_data[0])
        c2.paragraphs[0].add_run(row_data[1]).bold = True
        c3.paragraphs[0].add_run(row_data[2])

    doc.add_paragraph()

    # ── DETAILS OF AUDITOR ─────────────────────────────────────────────────────
    _add_section_heading("Details of Auditor:")
    tbl_auditor = doc.add_table(rows=2, cols=3)
    tbl_auditor.style = 'Table Grid'
    auditor_data = [
        ("1", "Auditor", "Mr. Subhash Rao BE.MBA, CEH, CHFI, ISO 27001 LA, CEI, CND, CDPSE"),
        ("2", "Auditor", "Mr. Mahaveer Rajannavar BE.CEH, ISO 27001 LA")
    ]
    for r_idx, row_data in enumerate(auditor_data):
        c1, c2, c3 = tbl_auditor.rows[r_idx].cells
        _set_cell_borders(c1)
        _set_cell_borders(c2)
        _set_cell_borders(c3)
        c1.paragraphs[0].add_run(row_data[0])
        c2.paragraphs[0].add_run(row_data[1]).bold = True
        c3.paragraphs[0].add_run(row_data[2])

    doc.add_paragraph()

    # ── DISCLAIMER ────────────────────────────────────────────────────────────
    _add_section_heading("Disclaimer:")
    disc_p = doc.add_paragraph()
    disc_p.add_run(
        "This document is highly confidential and sensitive and is meant for circulation only to authorized people within SEBI and Digital Age Strategies Pvt. Ltd. "
        "It is understood that disclosure in part or full of the contents or any information derived from the report to unauthorized personnel is strictly prohibited."
    ).italic = True

    doc.add_page_break()

    # ── REFERENCES ────────────────────────────────────────────────────────────
    _add_section_heading("References:")
    refs = [
        "SEBI’s RFP (Request for Proposal) no. SEBI/ITD/HO/VAPT/2023/03/01 for Certification of SEBI ISMS under ISO 27001 Standard, Conducting IT Systems Audit and Cybersecurity Audit in SEBI",
        "Information Technology Audit issued by Comptroller and Auditor General (CAG) of India",
        "Engagement Letter No SEBI/HO/ITD/ITD_VIAP/P/OW/2023/0000031833/1 dated 8.8.2023",
        "CIS_Controls_v8"
    ]
    for ref in refs:
        p = doc.add_paragraph(style='List Bullet')
        p.add_run(ref)

    # ── EVIDENCE ──────────────────────────────────────────────────────────────
    _add_section_heading("Evidence:")
    uploaded_files = list({f.get('source_files', '') for f in findings if f.get('source_files')})
    if uploaded_files:
        for uf in uploaded_files:
            for fname in str(uf).split(','):
                fname = fname.strip()
                if fname:
                    p = doc.add_paragraph(style='List Bullet')
                    p.add_run(fname)
    else:
        doc.add_paragraph("No evidence files recorded.").italic = True

    # ── TEXT SECTIONS ─────────────────────────────────────────────────────────
    _add_section_heading("Introduction:")
    doc.add_paragraph(
        "The Securities and Exchange Board of India was established on April 12, 1992 accordance with the provisions of the Securities and Exchange Board of India Act, 1992 to protect the interests of investors in securities and to promote the development of, and to regulate the securities market.\n\n"
        "As per the directions from SEBI vide PO Ref No: SEBI/ HO ITD/ ITD_VIAP/P/OW/2023/0000031833/1 dated 8.8.2023, we have conducted Audit of Attendance System Application as mentioned above. Our observations are based on situation prevailing at the time of visit, which might have undergone changes since then. Our findings are based on the scope given to us and best Our Practices."
    )

    _add_section_heading("Scope:")
    doc.add_paragraph(
        "The scope in the RFP broadly covers the major control areas against which the operations/ LOBs needs to be audited and indicative list of operations/ LOBs to be audited. The RFP Scope is reproduced in below two sections for ready reference.\n\n"
        "Control Areas that cover RFP Requirements:\n"
        "Personnel Security, Access Management, Data Backup and recovery Controls, Application Security, Network Communication Security, Business Continuity Management / BCP Controls, Implementation Audit, Fault Isolation audit (in the event of any incident), Integration compliance, Configuration Audit, Change Management, Insurance Audit, Performance Audit, Monitoring the utilization of IT resources, Capacity planning including projection of business volumes IT (S/W, H/W & N/W) Assets, Licenses & maintenance contracts, Disposal of Equipment, Media, etc., Implementation of approved IT policies of SEBI."
    )

    _add_section_heading("Audit Process:")
    doc.add_paragraph(
        "The auditor shall conduct the IT Systems and Cybersecurity Audit as per the following process: "
        "Compliance to observation is verified by document verification, observation, physical visit and sample testing."
    )

    _add_section_heading("Audit Methodology.")
    doc.add_paragraph(
        "We have conducted audit as per the broad scope given to us. Our methodology will cover, in general, IS Audit practices, RBI, CERT-In, ISACA, COBIT, IT Act 2000/2008 guidelines and the guidelines & procedures prescribed in various Circulars issued by SEBI. "
        "The objective of the audit is to verify compliance and to safeguard the interests of SEBI in connection with implementation of various technologies and related guidelines of the SEBI. Thus, findings are based on the scope given to us and best Practices to be followed."
    )

    _add_section_heading("Definition of Risk Classifications:")
    doc.add_paragraph(
        "The risk of an audit finding is determined by assessing the potential negative impact and the probability that it materializes. Audit findings are classified into four risk classifications. These risk categories assist management in identification, prioritization and implementation of audit recommendations. When the practice is normal as per the guidelines / best practices, the same has been classified as 'OK/ Complied'.\n\n"
        "High Risks: Non-adherence to SEBI and Government Guidelines, Policies Approved by Competent Authority, ICT is not as per standard, high threat probabilities. These risks are so significant that Management should determine any exposure to date and without delay effect an agreed program for their immediate and permanent resolution in order to provide assurance that they will not recur in the future.\n\n"
        "Medium Risks: These risks are important and management should quickly develop action plans that will ensure timely and permanent resolution of the weaknesses noted. These are potential weaknesses in control or security, which could develop into an exposure. This should be addressed at the earliest opportunity.\n\n"
        "Low Risk: These risks are not material in the context of current levels of activity but management should be aware of them and ensure they are resolved as soon as possible as they may become material if activities increase.\n\n"
        "OK/ ACCEPTED: This is normal and good practice. It is as per the guidelines / best practices. The observations categorized as 'ACCEPTED' need no action."
    )

    # ── SUMMARY OF FINDINGS ───────────────────────────────────────────────────
    _add_section_heading("Summary of Findings:")
    
    sev_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Accepted': 0}
    for f in findings:
        st_norm = f.get("status", "Non-Compliant")
        if st_norm == "Compliant":
            sev_counts['Accepted'] += 1
        elif st_norm == "False Positive":
            pass
        else:
            sev = f.get('severity', 'P3 Medium')
            if '1' in sev or 'Critical' in sev or 'High' in sev:
                sev_counts['High'] += 1
            elif '2' in sev or 'Medium' in sev:
                sev_counts['Medium'] += 1
            else:
                sev_counts['Low'] += 1

    tbl_summary = doc.add_table(rows=5, cols=5)
    tbl_summary.style = 'Table Grid'
    hdr_sum = tbl_summary.rows[0].cells
    hdr_sum_titles = ["Sr. No", "Risk Category Description", "No. of Observations", "Complied", "Not Complied"]
    for i, title in enumerate(hdr_sum_titles):
        _set_cell_bg(hdr_sum[i], "0F172A")
        _set_cell_borders(hdr_sum[i])
        run = hdr_sum[i].paragraphs[0].add_run(title)
        run.bold = True
        run.font.color.rgb = RGBColor(255, 255, 255)
        
    summary_rows = [
        ("1", "High Risks", str(sev_counts['High']), "0", str(sev_counts['High'])),
        ("2", "Medium Risks", str(sev_counts['Medium']), "0", str(sev_counts['Medium'])),
        ("3", "Low Risk", str(sev_counts['Low']), "0", str(sev_counts['Low'])),
        ("4", "OK / ACCEPTED", str(sev_counts['Accepted']), str(sev_counts['Accepted']), "0")
    ]
    for r_idx, row_data in enumerate(summary_rows):
        c1, c2, c3, c4, c5 = tbl_summary.rows[r_idx+1].cells
        _set_cell_borders(c1)
        _set_cell_borders(c2)
        _set_cell_borders(c3)
        _set_cell_borders(c4)
        _set_cell_borders(c5)
        c1.paragraphs[0].add_run(row_data[0])
        c2.paragraphs[0].add_run(row_data[1]).bold = True
        c3.paragraphs[0].add_run(row_data[2])
        c4.paragraphs[0].add_run(row_data[3])
        c5.paragraphs[0].add_run(row_data[4])

    doc.add_page_break()

    # ── AUDIT OBSERVATIONS TABLE (TABLE 7) ─────────────────────────────────────
    _add_section_heading("Audit conclusion/Observations:")
    
    tbl_obs = doc.add_table(rows=1, cols=8)
    tbl_obs.style = 'Table Grid'
    hdr_obs = tbl_obs.rows[0].cells
    hdr_obs_titles = ['S.No.', 'Control points', 'Policy Reference', 'Observations', 'Risk', 'Impact', 'Suggestion', 'Evidence']
    for i, title in enumerate(hdr_obs_titles):
        _set_cell_bg(hdr_obs[i], "0F172A")
        _set_cell_borders(hdr_obs[i])
        run = hdr_obs[i].paragraphs[0].add_run(title)
        run.bold = True
        run.font.color.rgb = RGBColor(255, 255, 255)
        run.font.size = Pt(9)

    active_findings = [f for f in findings if f.get("status") != "False Positive"]

    for f_idx, f in enumerate(active_findings, 1):
        row_cells = tbl_obs.add_row().cells
        for cell in row_cells:
            _set_cell_borders(cell)
            
        # Get severity/risk mapping
        st_val = f.get("status", "Non-Compliant")
        if st_val == "Compliant":
            mapped_risk = "Accepted"
        else:
            sev = f.get("severity", "P3 Medium")
            if "1" in sev or "Critical" in sev or "High" in sev:
                mapped_risk = "High"
            elif "2" in sev or "Medium" in sev:
                mapped_risk = "Medium"
            else:
                mapped_risk = "Low"

        # Shading by risk
        bg_color = {"High": "FEE2E2", "Medium": "FEFCE8", "Low": "EFF6FF", "Accepted": "F0FDF4"}.get(mapped_risk, "FFFFFF")
        for cell in row_cells:
            _set_cell_bg(cell, bg_color)

        # Content
        row_cells[0].paragraphs[0].add_run(str(f_idx))
        row_cells[1].paragraphs[0].add_run(f.get("control_id", "") + " " + f.get("control", ""))
        row_cells[2].paragraphs[0].add_run(f.get("clause", "") or "ISO 27001 Annex A")
        row_cells[3].paragraphs[0].add_run(f.get("finding") or f.get("description") or "—")
        row_cells[4].paragraphs[0].add_run(mapped_risk).bold = True
        row_cells[5].paragraphs[0].add_run(f.get("business_impact") or "NIL")
        row_cells[6].paragraphs[0].add_run(f.get("recommendation") or "NIL")
        
        ev_text = f.get("evidence_snippet") or f.get("evidence_quote") or "N/A"
        row_cells[7].paragraphs[0].add_run(ev_text)

    # Set column widths
    col_widths_cm = [1.0, 3.0, 2.5, 4.5, 2.0, 3.0, 3.5, 3.0]
    for col_i, width in enumerate(col_widths_cm):
        for cell in tbl_obs.columns[col_i].cells:
            cell.width = Cm(width)

    buf = _io.BytesIO()
    doc.save(buf)
    buf.seek(0)
    return buf.read()


def export_pdf_report(session_title, findings, resolved_list, status, comments=""):
    from fpdf.fonts import FontFace

    def clean_text(val):
        if not val:
            return "—"
        val = str(val)
        # Smart quotes
        val = val.replace("“", "\"").replace("”", "\"").replace("‘", "'").replace("’", "'")
        val = val.replace("\u201d", "\"").replace("\u201c", "\"").replace("\u2019", "'").replace("\u2018", "'")
        # Hyphens and dashes
        val = val.replace("—", "-").replace("–", "-").replace("\u2013", "-").replace("\u2014", "-")
        # Bullet symbols
        val = val.replace("\u2022", "*").replace("•", "*")
        # Fallback to Latin-1
        val = val.encode("latin-1", "replace").decode("latin-1")
        return val

    def truncate_cell_text(text, max_chars=800):
        if not text:
            return "—"
        text = str(text)
        if len(text) > max_chars:
            return text[:max_chars] + "... [Truncated for PDF]"
        return text

    class AuditPDF(FPDF):
        def header(self):
            pass
        def footer(self):
            pass

    pdf = AuditPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_margins(10, 15, 10)
    
    # FontFace helpers
    hdr_style = FontFace(emphasis="B", color=(255, 255, 255), fill_color=(15, 23, 42))
    lbl_style = FontFace(emphasis="B", fill_color=(241, 245, 249))
    bold_style = FontFace(emphasis="B")

    # ── COVER PAGE ─────────────────────────────────────────────────────────────
    pdf.add_page()
    pdf.ln(25)
    
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 12, clean_text(f"IS Audit Report for {session_title}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.ln(5)
    
    pdf.set_font("Helvetica", "I", 9.5)
    pdf.set_text_color(100, 116, 139)
    pdf.cell(0, 6, clean_text("Engagement letter: SEBI/HO/ITD/ITD_VIAP/P/OW/2023/0000031833/1 dated 8.8.2023"), new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.ln(5)
    
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 6, clean_text("Date of the Agreement: 15 September 2023."), new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.cell(0, 6, clean_text(f"Date of Document: {datetime.now().strftime('%dth %B %Y')}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.ln(25)
    
    pdf.set_font("Helvetica", "B", 10.5)
    pdf.cell(0, 6, clean_text("Audit Conducted By:"), new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 5, clean_text("Mr. Subhash Rao BE.MBA, CEH, CHFI, ISO 27001 LA, CEI, CND, CDPSE"), new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.cell(0, 5, clean_text("Mr. Mahaveer Rajannavar BE.CEH, ISO 27001 LA"), new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.ln(20)
    
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(100, 116, 139)
    pdf.multi_cell(0, 4.5, 
        clean_text(
            "Digital Age Strategies Pvt Ltd\n"
            "# 28, \"Om Arcade\" 2nd & 3rd Floors, Thimmappa Reddy Layout,\n"
            "Hulimavu, Bannerghatta Road, Bangalore - 560076\n"
            "Ph: +91-80-26484636, 49568066, 26485148, 41503825, 41218560\n"
            "Mobile: 9448088666 / 9448055711\n"
            "Email: audit@digitalage.co.in, dinesh.shastri@digitalage.co.in"
        ),
        align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT
    )
    
    # ── DOCUMENT CONTROL ───────────────────────────────────────────────────────
    pdf.add_page()
    
    def section_title(text):
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 8, clean_text(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(2)
        pdf.set_font("Helvetica", "", 9.5)

    section_title("Document Control:")
    
    prep_data = [
        ["Document Title", f"Information Security Audit {session_title}"],
        ["Engagement Letter Ref", "SEBI/HO/ITD/ITD_VIAP/P/OW/2023/0000031833/1 dated 8.8.2023"],
        ["Date of the Agreement", "15 September 2023"],
        ["Date of Document", datetime.now().strftime("%dth %B %Y")],
        ["Version", "1.0"],
        ["Prepared By", "Digital Age Strategies Pvt Ltd"]
    ]
    with pdf.table(col_widths=(60, 130), text_align="L") as table:
        for row in prep_data:
            r = table.row()
            r.cell(clean_text(row[0]), style=lbl_style)
            r.cell(clean_text(row[1]))
            
    pdf.ln(4)
    
    with pdf.table(col_widths=(30, 40, 120), text_align="L") as table:
        hdr = table.row()
        hdr.cell("Version", style=hdr_style)
        hdr.cell("Date", style=hdr_style)
        hdr.cell("Remarks / Reason of change", style=hdr_style)
        
        row = table.row()
        row.cell("1.0")
        row.cell(clean_text(datetime.now().strftime("%dth %B %Y")))
        row.cell("Initial release of audit findings")
        
    pdf.ln(4)
    
    with pdf.table(col_widths=(40, 45, 55, 50), text_align="L") as table:
        hdr = table.row()
        hdr.cell("Name", style=hdr_style)
        hdr.cell("Organization", style=hdr_style)
        hdr.cell("Designation", style=hdr_style)
        hdr.cell("Email Id", style=hdr_style)
        
        row = table.row()
        row.cell("SEBI ITD Team")
        row.cell("SEBI")
        row.cell("ITD Division Officers")
        row.cell("itd@sebi.gov.in")
        
    # Details of Auditee (Table 4)
    section_title("Details of Auditee:")
    auditee_data = [
        ["1", "Name of Organization", "Securities and Exchange Board of India"],
        ["2", "Audit Area", f"IS Audit of {session_title}"],
        ["3", "Location", "Mumbai, India"]
    ]
    with pdf.table(col_widths=(20, 60, 110), text_align="L") as table:
        for row in auditee_data:
            r = table.row()
            r.cell(clean_text(row[0]))
            r.cell(clean_text(row[1]), style=bold_style)
            r.cell(clean_text(row[2]))
            
    # Details of Auditor (Table 5)
    section_title("Details of Auditor:")
    auditor_data = [
        ["1", "Auditor", "Mr. Subhash Rao BE.MBA, CEH, CHFI, ISO 27001 LA, CEI, CND, CDPSE"],
        ["2", "Auditor", "Mr. Mahaveer Rajannavar BE.CEH, ISO 27001 LA"]
    ]
    with pdf.table(col_widths=(20, 40, 130), text_align="L") as table:
        for row in auditor_data:
            r = table.row()
            r.cell(clean_text(row[0]))
            r.cell(clean_text(row[1]), style=bold_style)
            r.cell(clean_text(row[2]))

    # Disclaimer
    section_title("Disclaimer:")
    pdf.set_font("Helvetica", "I", 9.5)
    pdf.set_text_color(51, 65, 85)
    pdf.multi_cell(0, 5, 
        clean_text(
            "This document is highly confidential and sensitive and is meant for circulation only to authorized people within SEBI and Digital Age Strategies Pvt. Ltd. "
            "It is understood that disclosure in part or full of the contents or any information derived from the report to unauthorized personnel is strictly prohibited."
        ),
        new_x=XPos.LMARGIN, new_y=YPos.NEXT
    )
    
    # References
    pdf.add_page()
    section_title("References:")
    pdf.set_font("Helvetica", "", 9.5)
    refs = [
        "SEBI’s RFP (Request for Proposal) no. SEBI/ITD/HO/VAPT/2023/03/01 for Certification of SEBI ISMS under ISO 27001 Standard, Conducting IT Systems Audit and Cybersecurity Audit in SEBI",
        "Information Technology Audit issued by Comptroller and Auditor General (CAG) of India",
        "Engagement Letter No SEBI/HO/ITD/ITD_VIAP/P/OW/2023/0000031833/1 dated 8.8.2023",
        "CIS_Controls_v8"
    ]
    for ref in refs:
        pdf.cell(5, 5, chr(149), align="R")
        pdf.multi_cell(185, 5, clean_text(ref), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(1)
        
    # Evidence
    section_title("Evidence:")
    uploaded_files = list({f.get('source_files', '') for f in findings if f.get('source_files')})
    if uploaded_files:
        for uf in uploaded_files:
            for fname in str(uf).split(','):
                fname = fname.strip()
                if fname:
                    pdf.cell(5, 5, chr(149), align="R")
                    pdf.multi_cell(185, 5, clean_text(fname), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.ln(1)
    else:
        pdf.set_font("Helvetica", "I", 9.5)
        pdf.cell(0, 5, "No evidence files recorded.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
    # Introduction
    section_title("Introduction:")
    pdf.set_font("Helvetica", "", 9.5)
    pdf.set_text_color(15, 23, 42)
    pdf.multi_cell(0, 5, 
        clean_text(
            "The Securities and Exchange Board of India was established on April 12, 1992 accordance with the provisions of the Securities and Exchange Board of India Act, 1992 to protect the interests of investors in securities and to promote the development of, and to regulate the securities market.\n\n"
            "As per the directions from SEBI vide PO Ref No: SEBI/ HO ITD/ ITD_VIAP/P/OW/2023/0000031833/1 dated 8.8.2023, we have conducted Audit of Attendance System Application as mentioned above. Our observations are based on situation prevailing at the time of visit, which might have undergone changes since then. Our findings are based on the scope given to us and best Our Practices."
        ),
        new_x=XPos.LMARGIN, new_y=YPos.NEXT
    )
    
    # Scope
    section_title("Scope:")
    pdf.multi_cell(0, 5,
        clean_text(
            "The scope in the RFP broadly covers the major control areas against which the operations/ LOBs needs to be audited and indicative list of operations/ LOBs to be audited. The RFP Scope is reproduced in below two sections for ready reference.\n\n"
            "Control Areas that cover RFP Requirements:\n"
            "Personnel Security, Access Management, Data Backup and recovery Controls, Application Security, Network Communication Security, Business Continuity Management / BCP Controls, Implementation Audit, Fault Isolation audit (in the event of any incident), Integration compliance, Configuration Audit, Change Management, Insurance Audit, Performance Audit, Monitoring the utilization of IT resources, Capacity planning including projection of business volumes IT (S/W, H/W & N/W) Assets, Licenses & maintenance contracts, Disposal of Equipment, Media, etc., Implementation of approved IT policies of SEBI."
        ),
        new_x=XPos.LMARGIN, new_y=YPos.NEXT
    )
    
    # Audit Process
    section_title("Audit Process:")
    pdf.multi_cell(0, 5,
        clean_text(
            "The auditor shall conduct the IT Systems and Cybersecurity Audit as per the following process: "
            "Compliance to observation is verified by document verification, observation, physical visit and sample testing."
        ),
        new_x=XPos.LMARGIN, new_y=YPos.NEXT
    )
    
    # Audit Methodology
    section_title("Audit Methodology.")
    pdf.multi_cell(0, 5,
        clean_text(
            "We have conducted audit as per the broad scope given to us. Our methodology will cover, in general, IS Audit practices, RBI, CERT-In, ISACA, COBIT, IT Act 2000/2008 guidelines and the guidelines & procedures prescribed in various Circulars issued by SEBI. "
            "The objective of the audit is to verify compliance and to safeguard the interests of SEBI in connection with implementation of various technologies and related guidelines of the SEBI. Thus, findings are based on the scope given to us and best Practices to be followed."
        ),
        new_x=XPos.LMARGIN, new_y=YPos.NEXT
    )
    
    # Definition of Risk Classifications
    section_title("Definition of Risk Classifications:")
    pdf.multi_cell(0, 5,
        clean_text(
            "The risk of an audit finding is determined by assessing the potential negative impact and the probability that it materializes. Audit findings are classified into four risk classifications. These risk categories assist management in identification, prioritization and implementation of audit recommendations. When the practice is normal as per the guidelines / best practices, the same has been classified as 'OK/ Complied'.\n\n"
            "High Risks: Non-adherence to SEBI and Government Guidelines, Policies Approved by Competent Authority, ICT is not as per standard, high threat probabilities. These risks are so significant that Management should determine any exposure to date and without delay effect an agreed program for their immediate and permanent resolution in order to provide assurance that they will not recur in the future.\n\n"
            "Medium Risks: These risks are important and management should quickly develop action plans that will ensure timely and permanent resolution of the weaknesses noted. These are potential weaknesses in control or security, which could develop into an exposure. This should be addressed at the earliest opportunity.\n\n"
            "Low Risk: These risks are not material in the context of current levels of activity but management should be aware of them and ensure they are resolved as soon as possible as they may become material if activities increase.\n\n"
            "OK/ ACCEPTED: This is normal and good practice. It is as per the guidelines / best practices. The observations categorized as 'ACCEPTED' need no action."
        ),
        new_x=XPos.LMARGIN, new_y=YPos.NEXT
    )

    # Summary of Findings (Table 6)
    section_title("Summary of Findings:")
    
    sev_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Accepted': 0}
    for f in findings:
        st_norm = f.get("status", "Non-Compliant")
        if st_norm == "Compliant":
            sev_counts['Accepted'] += 1
        elif st_norm == "False Positive":
            pass
        else:
            sev = f.get('severity', 'P3 Medium')
            if '1' in sev or 'Critical' in sev or 'High' in sev:
                sev_counts['High'] += 1
            elif '2' in sev or 'Medium' in sev:
                sev_counts['Medium'] += 1
            else:
                sev_counts['Low'] += 1

    summary_rows = [
        ["1", "High Risks", str(sev_counts['High']), "0", str(sev_counts['High'])],
        ["2", "Medium Risks", str(sev_counts['Medium']), "0", str(sev_counts['Medium'])],
        ["3", "Low Risk", str(sev_counts['Low']), "0", str(sev_counts['Low'])],
        ["4", "OK / ACCEPTED", str(sev_counts['Accepted']), str(sev_counts['Accepted']), "0"]
    ]
    with pdf.table(col_widths=(20, 50, 40, 40, 40), text_align="L") as table:
        hdr = table.row()
        hdr.cell("Sr. No", style=hdr_style)
        hdr.cell("Risk Category Description", style=hdr_style)
        hdr.cell("No. of Observations", style=hdr_style)
        hdr.cell("Complied", style=hdr_style)
        hdr.cell("Not Complied", style=hdr_style)
        
        for row in summary_rows:
            r = table.row()
            r.cell(clean_text(row[0]))
            r.cell(clean_text(row[1]), style=bold_style)
            r.cell(clean_text(row[2]))
            r.cell(clean_text(row[3]))
            r.cell(clean_text(row[4]))
            
    # Table 7: Audit conclusion/Observations
    pdf.add_page()
    section_title("Audit conclusion/Observations:")
    
    active_findings = [f for f in findings if f.get("status") != "False Positive"]

    pdf.set_font("Helvetica", "", 7.5)
    with pdf.table(col_widths=(6, 24, 15, 50, 12, 25, 33, 25), text_align="L") as table:
        hdr = table.row()
        hdr_titles = ['S.No.', 'Control points', 'Policy Reference', 'Observations', 'Risk', 'Impact', 'Suggestion', 'Evidence']
        for title in hdr_titles:
            hdr.cell(title, style=hdr_style)
            
        for f_idx, f in enumerate(active_findings, 1):
            r = table.row()
            
            # Map risk
            st_val = f.get("status", "Non-Compliant")
            if st_val == "Compliant":
                mapped_risk = "Accepted"
            else:
                sev = f.get("severity", "P3 Medium")
                if "1" in sev or "Critical" in sev or "High" in sev:
                    mapped_risk = "High"
                elif "2" in sev or "Medium" in sev:
                    mapped_risk = "Medium"
                else:
                    mapped_risk = "Low"
                    
            # Color coding
            bg_color = {
                "High": (254, 226, 226), 
                "Medium": (254, 252, 232), 
                "Low": (239, 246, 255), 
                "Accepted": (240, 253, 244)
            }.get(mapped_risk, (255, 255, 255))
            
            # Styles
            cell_style = FontFace(fill_color=bg_color)
            risk_color = {
                "High": (220, 38, 38),
                "Medium": (217, 119, 6),
                "Low": (37, 99, 235),
                "Accepted": (22, 163, 74)
            }.get(mapped_risk, (30, 41, 59))
            risk_style = FontFace(emphasis="B", fill_color=bg_color, color=risk_color)

            # Cells
            r.cell(clean_text(str(f_idx)), style=cell_style)
            
            ctrl_text = f.get("control_id", "") + " " + f.get("control", "")
            r.cell(clean_text(truncate_cell_text(ctrl_text, 150)), style=cell_style)
            
            ref_text = f.get("clause", "") or "ISO 27001 Annex A"
            r.cell(clean_text(truncate_cell_text(ref_text, 100)), style=cell_style)
            
            obs_text = f.get("finding") or f.get("description") or "—"
            r.cell(clean_text(truncate_cell_text(obs_text, 600)), style=cell_style)
            
            r.cell(clean_text(mapped_risk), style=risk_style)
            
            imp_text = f.get("business_impact") or "NIL"
            r.cell(clean_text(truncate_cell_text(imp_text, 400)), style=cell_style)
            
            sug_text = f.get("recommendation") or "NIL"
            r.cell(clean_text(truncate_cell_text(sug_text, 500)), style=cell_style)
            
            ev_text = f.get("evidence_snippet") or f.get("evidence_quote") or "N/A"
            r.cell(clean_text(truncate_cell_text(ev_text, 400)), style=cell_style)

    pdf_bytes = pdf.output()
    return bytes(pdf_bytes)
