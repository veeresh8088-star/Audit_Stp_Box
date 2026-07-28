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
    folder_name: str = ""
):
    """
    Records detailed token consumption, text size, latency, and scoping metrics
    for real document analysis sessions.
    """
    os.makedirs("data", exist_ok=True)

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
        "files_count": len(file_names),
        "file_names": ", ".join(file_names),
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
    print(f"[TOKEN TRACKER] Recorded metrics for session {session_id[:8]} ({scoping_mode}): {total_tokens} tokens, {round(total_latency_sec,1)}s latency.", flush=True)
    return record


def generate_excel_benchmark_report(records: list, output_path: str = BENCHMARK_EXCEL_PATH):
    """
    Generates a beautifully styled Excel workbook summarizing token usage,
    latency, file size, text length, and scoping comparison for mentor evaluation.
    """
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Token & Latency Benchmark"

    # Styling definitions
    font_title = Font(name="Arial", size=14, bold=True, color="FFFFFF")
    font_header = Font(name="Arial", size=10, bold=True, color="FFFFFF")
    font_body = Font(name="Arial", size=9)
    font_bold = Font(name="Arial", size=9, bold=True)
    
    fill_title = PatternFill(start_color="1E293B", end_color="1E293B", fill_type="solid") # Dark Slate
    fill_header = PatternFill(start_color="2563EB", end_color="2563EB", fill_type="solid") # Royal Blue
    fill_sub = PatternFill(start_color="3B82F6", end_color="3B82F6", fill_type="solid")

    thin_border = Border(
        left=Side(style='thin', color='CBD5E1'),
        right=Side(style='thin', color='CBD5E1'),
        top=Side(style='thin', color='CBD5E1'),
        bottom=Side(style='thin', color='CBD5E1')
    )

    # 1. Title Header Block
    ws.merge_cells("A1:N1")
    ws["A1"] = "AISecurityAudit — Real-Time Token, Latency & Scoping Benchmark Metrics"
    ws["A1"].font = font_title
    ws["A1"].fill = fill_title
    ws["A1"].alignment = Alignment(horizontal="center", vertical="center")
    ws.row_dimensions[1].height = 40

    # 2. Table Headers
    headers = [
        "Timestamp",
        "Session ID",
        "Folder / Location",
        "Scoping Method",
        "Files Count",
        "File Size (KB)",
        "Text Chars",
        "Controls Audited",
        "Input Tokens",
        "Output Tokens",
        "Total Tokens",
        "Tokens / Control",
        "Total Latency (Sec)",
        "Avg Latency / Control (sec)",
        "Tokens / Sec"
    ]

    ws.append([]) # Row 2 empty spacer
    ws.append(headers) # Row 3 headers
    ws.row_dimensions[3].height = 28

    for col_num, h in enumerate(headers, 1):
        cell = ws.cell(row=3, column=col_num)
        cell.font = font_header
        cell.fill = fill_header
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        cell.border = thin_border

    # 3. Populate Data Rows
    row_idx = 4
    for r in records:
        ctrls = max(1, int(r.get("controls_audited_count", 1)))
        tot_toks = int(r.get("total_tokens", 0))
        tot_lat = float(r.get("total_latency_seconds", 0))
        toks_per_ctrl = round(tot_toks / ctrls, 1)
        lat_per_ctrl = round(tot_lat / ctrls, 2)

        ws.append([
            r.get("timestamp", ""),
            str(r.get("session_id", ""))[:8],
            r.get("folder_name", "Folder Scope"),
            r.get("scoping_mode", "Excel / Manual Scoping"),
            r.get("files_count", 1),
            r.get("file_size_kb", 0),
            r.get("extracted_text_chars", 0),
            ctrls,
            r.get("prompt_input_tokens", 0),
            r.get("completion_output_tokens", 0),
            tot_toks,
            toks_per_ctrl,
            tot_lat,
            lat_per_ctrl,
            r.get("tokens_per_second", 0)
        ])

        ws.row_dimensions[row_idx].height = 22
        for col_num in range(1, len(headers) + 1):
            cell = ws.cell(row=row_idx, column=col_num)
            cell.font = font_body
            cell.border = thin_border
            if col_num in [5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]:
                cell.alignment = Alignment(horizontal="right", vertical="center")
            else:
                cell.alignment = Alignment(horizontal="center", vertical="center")
        row_idx += 1

    # 4. Auto-fit Column Widths
    for col in ws.columns:
        max_len = max(len(str(cell.value or '')) for cell in col)
        col_letter = get_column_letter(col[0].column)
        ws.column_dimensions[col_letter].width = max(max_len + 4, 12)

    wb.save(output_path)
    return output_path
