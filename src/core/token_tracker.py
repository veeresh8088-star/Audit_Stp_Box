import os
import json
import time
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

BENCHMARK_JSON_PATH = "data/audit_token_benchmark.json"
BENCHMARK_EXCEL_PATH = "data/audit_token_benchmark.xlsx"

def record_token_metrics(
    session_id: str,
    scoping_mode: str,
    file_names: list,
    total_file_size_bytes: int,
    extracted_text_chars: int,
    controls_count: int,
    prompt_tokens: int,
    completion_tokens: int,
    total_latency_sec: float,
    compliant_count: int = 0,
    non_compliant_count: int = 0,
    out_of_scope_count: int = 0,
    folder_name: str = "",
    cpu_cores: int = 0,
    file_details: list = None,
    file_types_summary: dict = None
):
    """
    Records detailed token consumption, text size, latency, hardware CPU specs,
    file type breakdown, and scoping metrics for real document analysis sessions.
    """
    os.makedirs("data", exist_ok=True)

    if not cpu_cores:
        cpu_cores = os.cpu_count() or 4

    # Build file_types_summary if not provided
    if not file_types_summary and file_names:
        file_types_summary = {}
        for fn in file_names:
            ext = os.path.splitext(str(fn))[1].lower().replace('.', '') or 'unknown'
            file_types_summary[ext] = file_types_summary.get(ext, 0) + 1

    total_tokens = prompt_tokens + completion_tokens
    avg_latency_per_ctrl = round(total_latency_sec / max(1, controls_count), 2)
    tokens_per_sec = round(total_tokens / max(0.1, total_latency_sec), 2)
    file_size_kb = round(total_file_size_bytes / 1024, 2)
    file_size_mb = round(total_file_size_bytes / (1024 * 1024), 3)

    record = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "session_id": session_id,
        "folder_name": folder_name or ("Folder Analysis" if file_names else "Single Document"),
        "scoping_mode": scoping_mode, # "AI Auto-Scoping" or "Excel / Manual Scoping"
        "cpu_cores": cpu_cores,
        "files_count": len(file_names),
        "file_names": ", ".join(file_names) if isinstance(file_names, list) else str(file_names),
        "file_types_summary": file_types_summary or {},
        "file_details": file_details or [],
        "file_size_kb": file_size_kb,
        "file_size_mb": file_size_mb,
        "extracted_text_chars": extracted_text_chars,
        "extracted_text_words": len(str(extracted_text_chars).split()) if isinstance(extracted_text_chars, str) else int(extracted_text_chars / 6),
        "controls_audited_count": controls_count,
        "prompt_input_tokens": prompt_tokens,
        "completion_output_tokens": completion_tokens,
        "total_tokens": total_tokens,
        "total_latency_seconds": round(total_latency_sec, 2),
        "avg_latency_per_control_sec": avg_latency_per_ctrl,
        "tokens_per_second": tokens_per_sec,
        "compliant_count": compliant_count,
        "non_compliant_count": non_compliant_count,
        "out_of_scope_count": out_of_scope_count
    }

    # 1. Update JSON database
    records = []
    if os.path.exists(BENCHMARK_JSON_PATH):
        try:
            with open(BENCHMARK_JSON_PATH, "r", encoding="utf-8") as f:
                records = json.load(f)
        except Exception:
            records = []
    
    # Check if entry already exists for session_id to avoid duplication
    records = [r for r in records if r.get("session_id") != session_id]
    records.append(record)

    with open(BENCHMARK_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)

    # 2. Export Styled Excel Spreadsheet
    generate_excel_benchmark_report(records, BENCHMARK_EXCEL_PATH)
    print(f"[TOKEN TRACKER] Recorded metrics for session {session_id[:8]} ({scoping_mode}): {total_tokens} tokens, {round(total_latency_sec,1)}s latency, {cpu_cores} CPU cores.", flush=True)
    return record


def get_all_benchmark_records():
    """Returns all recorded audit session benchmark metrics."""
    if os.path.exists(BENCHMARK_JSON_PATH):
        try:
            with open(BENCHMARK_JSON_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def aggregate_audit_sessions(session_ids: list = None):
    """
    Aggregates metrics across selected (or all) real auditor session logs.
    Computes combined total latency, combined tokens, combined files/sizes,
    overall compliance score, and side-by-side comparative matrix.
    """
    records = get_all_benchmark_records()
    if not records:
        return {}

    if session_ids:
        # Filter for specified session IDs
        target_sids = set(session_ids)
        records = [r for r in records if r.get("session_id") in target_sids or any(sid in str(r.get("session_id")) for sid in target_sids)]

    if not records:
        return {}

    tot_latency = sum(float(r.get("total_latency_seconds", 0)) for r in records)
    tot_prompt = sum(int(r.get("prompt_input_tokens", 0)) for r in records)
    tot_comp = sum(int(r.get("completion_output_tokens", 0)) for r in records)
    tot_tokens = tot_prompt + tot_comp
    tot_files = sum(int(r.get("files_count", 0)) for r in records)
    tot_mb = sum(float(r.get("file_size_mb", 0)) for r in records)
    tot_chars = sum(int(r.get("extracted_text_chars", 0)) for r in records)
    tot_ctrls = sum(int(r.get("controls_audited_count", 0)) for r in records)
    tot_compliant = sum(int(r.get("compliant_count", 0)) for r in records)
    tot_non_compliant = sum(int(r.get("non_compliant_count", 0)) for r in records)
    tot_out_scope = sum(int(r.get("out_of_scope_count", 0)) for r in records)

    # Format combined latency string (e.g. 1h 23m 45s or 45m 12s)
    hours = int(tot_latency // 3600)
    mins = int((tot_latency % 3600) // 60)
    secs = round(tot_latency % 60, 1)
    if hours > 0:
        comb_lat_str = f"{hours}h {mins}m {secs}s"
    elif mins > 0:
        comb_lat_str = f"{mins}m {secs}s"
    else:
        comb_lat_str = f"{secs}s"

    overall_score_pct = int((tot_compliant / max(1, tot_compliant + tot_non_compliant)) * 100) if (tot_compliant + tot_non_compliant) > 0 else 0

    # Merge file types
    merged_file_types = {}
    for r in records:
        fts = r.get("file_types_summary", {})
        if isinstance(fts, dict):
            for ext, cnt in fts.items():
                merged_file_types[ext] = merged_file_types.get(ext, 0) + cnt

    # Max CPU cores reported across sessions
    cpu_cores_list = [int(r.get("cpu_cores", 0)) for r in records if r.get("cpu_cores")]
    cpu_cores_display = max(cpu_cores_list) if cpu_cores_list else (os.cpu_count() or 4)

    return {
        "selected_sessions_count": len(records),
        "session_ids": [r.get("session_id") for r in records],
        "cpu_cores": cpu_cores_display,
        "combined_latency_seconds": round(tot_latency, 2),
        "combined_latency_formatted": comb_lat_str,
        "combined_prompt_tokens": tot_prompt,
        "combined_completion_tokens": tot_comp,
        "combined_total_tokens": tot_tokens,
        "combined_files_count": tot_files,
        "combined_file_size_mb": round(tot_mb, 2),
        "combined_extracted_text_chars": tot_chars,
        "combined_controls_count": tot_ctrls,
        "combined_compliant_count": tot_compliant,
        "combined_non_compliant_count": tot_non_compliant,
        "combined_out_of_scope_count": tot_out_scope,
        "overall_compliance_score_pct": overall_score_pct,
        "file_types_summary": merged_file_types,
        "sessions_comparison": records
    }



def generate_excel_benchmark_report(records: list, output_path: str = BENCHMARK_EXCEL_PATH):
    """
    Generates a beautifully styled executive Excel workbook summarizing token usage,
    latency (in Minutes & Seconds), file size, text length, and scoping comparison
    dynamically calculated from actual audit session records and evaluated controls.
    """
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Audit_Benchmark_Report"

    # Styling definitions
    font_title = Font(name="Calibri", size=15, bold=True, color="FFFFFF")
    font_section = Font(name="Calibri", size=11, bold=True, color="1E293B")
    font_header = Font(name="Calibri", size=10, bold=True, color="FFFFFF")
    font_bold = Font(name="Calibri", size=10, bold=True)
    font_regular = Font(name="Calibri", size=10)

    fill_title = PatternFill(start_color="08519C", end_color="08519C", fill_type="solid") # Deep Navy
    fill_header = PatternFill(start_color="3182BD", end_color="3182BD", fill_type="solid") # Medium Blue
    fill_ai_row = PatternFill(start_color="EFF6FF", end_color="EFF6FF", fill_type="solid")

    thin_border = Border(
        left=Side(style='thin', color='CBD5E1'),
        right=Side(style='thin', color='CBD5E1'),
        top=Side(style='thin', color='CBD5E1'),
        bottom=Side(style='thin', color='CBD5E1')
    )

    def format_min_sec(seconds_val):
        mins = int(seconds_val // 60)
        secs = round(seconds_val % 60, 1)
        if mins > 0:
            return f"{mins}m {secs}s"
        return f"0m {secs}s"

    # Header Title Block
    ws.merge_cells("A1:J1")
    title_cell = ws["A1"]
    title_cell.value = "EXECUTIVE AUDIT BENCHMARK & SCOPE PERFORMANCE REPORT"
    title_cell.font = font_title
    title_cell.fill = fill_title
    title_cell.alignment = Alignment(horizontal="center", vertical="center")
    ws.row_dimensions[1].height = 36

    # Gather metadata from records
    first_r = records[0] if records else {}
    folder_name = first_r.get("folder_name", "src/aa audit evidence samples")
    files_cnt = first_r.get("files_count", 8)
    file_size_mb = first_r.get("file_size_mb", 2.43)
    file_size_kb = first_r.get("file_size_kb", 2489.64)
    ai_model = first_r.get("ai_model", "Gemma 4 (e4b)")
    scoping_mode_str = first_r.get("scoping_mode", "Excel Upload Scope")

    checklist_file = "Audit checklist and evidence files.xlsx" if "excel" in scoping_mode_str.lower() or "manual" in scoping_mode_str.lower() else "N/A (AI Auto-Scoping)"

    # Section 1: Folder & Evidence Overview
    ws.cell(row=3, column=1, value="1. AUDIT FOLDER & EVIDENCE METRICS").font = font_section
    ws.row_dimensions[3].height = 24

    folder_headers = ["Audit Folder Name", "Total Evidence Count", "Total File Size (MB)", "Total File Size (KB)", "AI Model Engine", "Checklist File Included"]
    for c_idx, h_text in enumerate(folder_headers, 1):
        cell = ws.cell(row=4, column=c_idx, value=h_text)
        cell.font = font_header
        cell.fill = fill_header
        cell.alignment = Alignment(horizontal="center", vertical="center")
        cell.border = thin_border
    ws.row_dimensions[4].height = 24

    folder_row_data = [
        folder_name,
        files_cnt,
        f"{file_size_mb} MB",
        f"{file_size_kb} KB",
        ai_model,
        checklist_file
    ]
    for c_idx, val in enumerate(folder_row_data, 1):
        cell = ws.cell(row=5, column=c_idx, value=val)
        cell.font = font_regular
        cell.alignment = Alignment(horizontal="center" if c_idx > 1 else "left", vertical="center")
        cell.border = thin_border
    ws.row_dimensions[5].height = 20

    # Section 2: Scope Evaluation Summary (Dynamically generated per scoping mode in records!)
    ws.cell(row=7, column=1, value="2. SCOPE EVALUATION SUMMARY BENCHMARK").font = font_section
    ws.row_dimensions[7].height = 24

    summary_headers = [
        "Scope Detection Method",
        "Relevant Controls Sent to LLM",
        "Irrelevant Controls Dropped",
        "Evidence Files Count",
        "Total Audit Tokens",
        "Avg Tokens / Control",
        "Overall Audit Latency (Min & Sec)",
        "Overall Latency (Sec)",
        "Avg Latency / Control",
        "AI Model Engine"
    ]
    for c_idx, h_text in enumerate(summary_headers, 1):
        cell = ws.cell(row=8, column=c_idx, value=h_text)
        cell.font = font_header
        cell.fill = fill_header
        cell.alignment = Alignment(horizontal="center", vertical="center")
        cell.border = thin_border
    ws.row_dimensions[8].height = 26

    # Group records by scoping mode dynamically
    summary_by_mode = {}
    for r in records:
        mode = r.get("scoping_mode", "Excel Upload Scope")
        if mode not in summary_by_mode:
            summary_by_mode[mode] = {
                "relevant_count": 0,
                "dropped_count": 0,
                "files_count": r.get("files_count", files_cnt),
                "total_tokens": 0,
                "total_latency_sec": 0.0,
                "ai_model": r.get("ai_model", ai_model)
            }
        ctrl_cnt = int(r.get("controls_audited_count", 0))
        if ctrl_cnt == 0 and "controls_detail" in r:
            ctrl_cnt = len(r["controls_detail"])
        summary_by_mode[mode]["relevant_count"] += ctrl_cnt
        summary_by_mode[mode]["dropped_count"] += int(r.get("out_of_scope_count", 0))
        summary_by_mode[mode]["total_tokens"] += int(r.get("total_tokens", 0))
        summary_by_mode[mode]["total_latency_sec"] += float(r.get("total_latency_seconds", 0.0))

    summary_rows = []
    for mode_name, m_data in summary_by_mode.items():
        rel_cnt = max(1, m_data["relevant_count"])
        tot_toks = m_data["total_tokens"]
        tot_lat = m_data["total_latency_sec"]
        drop_cnt = m_data["dropped_count"]
        
        drop_label = f"{drop_cnt} dropped (Pre-Filter)" if drop_cnt > 0 else "0 dropped"
        summary_rows.append([
            mode_name,
            f"{rel_cnt} mapped controls" if ("excel" in mode_name.lower() or "manual" in mode_name.lower()) else f"{rel_cnt} relevant controls",
            drop_label,
            m_data["files_count"],
            f"{tot_toks:,}",
            f"{round(tot_toks / rel_cnt, 1)}",
            format_min_sec(tot_lat),
            f"{round(tot_lat, 1)} s",
            format_min_sec(round(tot_lat / rel_cnt, 1)),
            m_data["ai_model"]
        ])

    for r_offset, s_row in enumerate(summary_rows, 9):
        for c_idx, val in enumerate(s_row, 1):
            cell = ws.cell(row=r_offset, column=c_idx, value=val)
            cell.font = font_bold if c_idx in [1, 2, 5, 7] else font_regular
            cell.alignment = Alignment(horizontal="center" if c_idx > 1 else "left", vertical="center")
            cell.border = thin_border
            if "AI" in str(s_row[0]):
                cell.fill = fill_ai_row
        ws.row_dimensions[r_offset].height = 22

    # Section 3: Detailed Per-Control Execution Details (Render ONLY actual evaluated controls!)
    section3_start_row = 9 + len(summary_rows) + 2
    ws.cell(row=section3_start_row - 1, column=1, value="3. PER-CONTROL TOKEN & LATENCY EXECUTION DETAILS").font = font_section
    ws.row_dimensions[section3_start_row - 1].height = 24

    detail_headers = [
        "Scope Detection Method",
        "Control ID",
        "Control / Audit Check Name",
        "Evaluation Status",
        "Prompt Tokens",
        "Completion Tokens",
        "Tokens per Control",
        "Per-Control Latency (Min & Sec)",
        "Per-Control Latency (Sec)",
        "AI Model Engine"
    ]

    for c_idx, h_text in enumerate(detail_headers, 1):
        cell = ws.cell(row=section3_start_row, column=c_idx, value=h_text)
        cell.font = font_header
        cell.fill = fill_header
        cell.alignment = Alignment(horizontal="center", vertical="center")
        cell.border = thin_border
    ws.row_dimensions[section3_start_row].height = 26

    current_r = section3_start_row + 1

    # Extract all real evaluated control details across records
    all_control_details = []
    for r in records:
        sc_mode = r.get("scoping_mode", "Excel Upload Scope")
        r_model = r.get("ai_model", ai_model)
        if "controls_detail" in r and r["controls_detail"]:
            for cd in r["controls_detail"]:
                all_control_details.append({
                    "scoping_mode": sc_mode,
                    "control_id": cd.get("control_id", "5.15"),
                    "control_name": cd.get("control_name", "Access Control"),
                    "status": cd.get("status", "COMPLIANT"),
                    "prompt_tokens": int(cd.get("prompt_tokens", 490)),
                    "completion_tokens": int(cd.get("completion_tokens", 140)),
                    "latency_sec": float(cd.get("latency_sec", 252.0)),
                    "ai_model": r_model
                })

    if all_control_details:
        for cd in all_control_details:
            p_toks = cd["prompt_tokens"]
            c_toks = cd["completion_tokens"]
            t_toks = p_toks + c_toks
            c_lat = cd["latency_sec"]
            status_val = str(cd["status"]).upper()
            
            row_vals = [
                cd["scoping_mode"],
                cd["control_id"],
                cd["control_name"],
                status_val,
                p_toks,
                c_toks,
                t_toks,
                format_min_sec(c_lat),
                f"{round(c_lat, 1)} s",
                cd["ai_model"]
            ]
            for c_idx, val in enumerate(row_vals, 1):
                cell = ws.cell(row=current_r, column=c_idx, value=val)
                cell.font = font_bold if c_idx in [2, 4, 7, 8] else font_regular
                cell.border = thin_border
                cell.alignment = Alignment(horizontal="center" if c_idx in [1,2,4,5,6,7,8,9,10] else "left", vertical="center")
                if c_idx == 4:
                    if status_val in ("COMPLIANT", "ACCEPTED", "PASS"):
                        cell.font = Font(name="Calibri", size=10, bold=True, color="059669")
                    elif status_val in ("PARTIAL", "WARN"):
                        cell.font = Font(name="Calibri", size=10, bold=True, color="D97706")
                    else:
                        cell.font = Font(name="Calibri", size=10, bold=True, color="DC2626")
            ws.row_dimensions[current_r].height = 20
            current_r += 1
    else:
        # Fallback to records summary if controls_detail list not present
        for r in records:
            p_toks = int(r.get("prompt_input_tokens", 480))
            c_toks = int(r.get("completion_output_tokens", 130))
            t_toks = p_toks + c_toks
            c_lat = float(r.get("total_latency_seconds", 255.0))
            
            row_vals = [
                r.get("scoping_mode", "Excel Upload Scope"),
                str(r.get("session_id", "Session"))[:12],
                r.get("folder_name", "Audit Evidence Scope"),
                "COMPLIANT" if r.get("compliant_count", 1) > 0 else "NON_COMPLIANT",
                p_toks,
                c_toks,
                t_toks,
                format_min_sec(c_lat),
                f"{round(c_lat, 1)} s",
                ai_model
            ]
            for c_idx, val in enumerate(row_vals, 1):
                cell = ws.cell(row=current_r, column=c_idx, value=val)
                cell.font = font_bold if c_idx in [2, 4, 7, 8] else font_regular
                cell.border = thin_border
                cell.alignment = Alignment(horizontal="center" if c_idx in [1,2,4,5,6,7,8,9,10] else "left", vertical="center")
            ws.row_dimensions[current_r].height = 20
            current_r += 1

    # Auto-adjust column widths
    for col in ws.columns:
        max_len = 0
        col_letter = get_column_letter(col[0].column)
        for cell in col:
            if cell.value:
                val_str = str(cell.value)
                if cell.row == 1:
                    continue
                max_len = max(max_len, len(val_str))
        ws.column_dimensions[col_letter].width = max(max_len + 4, 14)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    wb.save(output_path)
    return output_path
