# -*- coding: utf-8 -*-
"""
Golden Dataset Validation Harness for AICyberAuditBox (RAG accuracy overhaul, Phase 8)

Distinct from tests/run_evals.py, which stays as a fast 4-scenario regression smoke
test. This harness runs the full labeled dataset in qa/eval/golden_dataset.json
through the real audit pipeline and computes real classification metrics --
Accuracy, Precision, Recall, F1, false positives, false negatives -- plus retrieval
recall (extends the GOLD_RETRIEVAL pattern from tests/run_evals.py to this larger
dataset). Binary COMPLIANT/NON_COMPLIANT only, matching the strict FINAL_RESULT
schema from the Phase 5/6 rewrite -- there is no PARTIAL class to score.

"Positive" class = COMPLIANT for precision/recall/F1 purposes.

Usage (needs the full local stack -- LLM + embedding servers + DB -- already running,
same as tests/run_evals.py):
    python qa\\eval\\run_golden_eval.py
"""

import os
import sys
import time
import json

sys.path.append(os.getcwd())

os.environ["LLM_BACKEND"] = "llama.cpp"
os.environ["OLLAMA_HOST"] = "http://127.0.0.1:11434"
os.environ["EMBEDDING_HOST"] = "http://127.0.0.1:11435"

from src.db.database import SessionLocal, DocumentChunk, force_master
from src.core.controls_data import USE_CASES
from src.core.control_keywords import CONTROL_KEYWORDS
from src.ai.audit_graph import audit_graph
from src.core.retrieval import save_document_chunks, _ingested_chunks_cache

DATASET_PATH = os.path.join(os.path.dirname(__file__), "golden_dataset.json")
RESULTS_JSON_PATH = os.path.join(os.path.dirname(__file__), "golden_eval_results.json")
RESULTS_MD_PATH = os.path.join(os.path.dirname(__file__), "GOLDEN_EVAL_REPORT.md")


def clean_db_for_file(filename):
    with force_master():
        session = SessionLocal()
        session.query(DocumentChunk).filter(DocumentChunk.filename == filename).delete()
        session.commit()
        session.close()


def load_dataset():
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("cases", [])


def run_case(case, control_templates):
    control_id = case["control_id"]
    ctrl = control_templates.get(control_id)
    if not ctrl:
        return {"id": case["id"], "error": f"Control {control_id} not found in USE_CASES"}

    doc_name = case["document_name"]
    doc_text = case["document_text"]

    clean_db_for_file(doc_name)
    _ingested_chunks_cache[doc_name] = [
        (doc_text, {"source_file": doc_name, "source_type": "docx", "section_heading": "", "chunk_id": "chunk_gd"})
    ]
    save_document_chunks(doc_name, doc_text)

    state = {
        "control_id": ctrl["use_case"],
        "control_label": ctrl["label"],
        "expected_evidence": ctrl["expected"],
        "prompt_hint": ctrl.get("prompt_hint", ""),
        "severity": ctrl["severity"],
        "standard": ctrl.get("standard", "ISO 27001"),
        "recommendation": ctrl.get("recommendation", ""),
        "keywords": CONTROL_KEYWORDS.get(ctrl["use_case"], {}),

        "document_text": doc_text,
        "file_names_list": [doc_name],
        "llm_model": "gemma4:e4b",
        "summary_text": f"Golden eval case {case['id']}",

        "retrieved_context": "",
        "draft_finding": None,
        "validation_error": None,
        "retry_count": 0,
        "final_finding": None,

        "bg_key": f"golden-{case['id']}",
        "control_idx": 0,
        "total_controls": 1,
        "audit_mode": "Deep",
    }

    start = time.time()
    try:
        output_state = audit_graph.invoke(state)
    except Exception as e:
        return {"id": case["id"], "error": str(e)}
    elapsed = time.time() - start

    final = output_state.get("final_finding") or {}
    actual_result = str(final.get("status") or final.get("final_result") or "NON_COMPLIANT").strip().upper()
    if actual_result not in ("COMPLIANT", "NON_COMPLIANT"):
        actual_result = "NON_COMPLIANT"  # FALSE_POSITIVE/other -- treat as not-compliant for this binary dataset

    retrieved_context = output_state.get("retrieved_context", "") or ""
    gold_phrase = case.get("gold_evidence_phrase")
    if gold_phrase is None:
        retrieval_recall = "N/A"
    else:
        retrieval_recall = gold_phrase.lower() in retrieved_context.lower()

    return {
        "id": case["id"],
        "control_id": control_id,
        "expected": case["expected_final_result"],
        "actual": actual_result,
        "match": actual_result == case["expected_final_result"],
        "retrieval_recall": retrieval_recall,
        "elapsed_sec": round(elapsed, 2),
    }


def compute_metrics(results):
    """Binary confusion matrix, COMPLIANT = positive class."""
    valid = [r for r in results if "error" not in r]
    tp = sum(1 for r in valid if r["expected"] == "COMPLIANT" and r["actual"] == "COMPLIANT")
    tn = sum(1 for r in valid if r["expected"] == "NON_COMPLIANT" and r["actual"] == "NON_COMPLIANT")
    fp = sum(1 for r in valid if r["expected"] == "NON_COMPLIANT" and r["actual"] == "COMPLIANT")
    fn = sum(1 for r in valid if r["expected"] == "COMPLIANT" and r["actual"] == "NON_COMPLIANT")

    total = len(valid)
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    recall_scores = [r["retrieval_recall"] for r in valid if r["retrieval_recall"] != "N/A"]
    retrieval_recall_rate = (sum(1 for s in recall_scores if s) / len(recall_scores)) if recall_scores else "N/A"

    return {
        "total_cases": total,
        "errors": len(results) - total,
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "retrieval_recall_rate": retrieval_recall_rate if retrieval_recall_rate == "N/A" else round(retrieval_recall_rate, 4),
    }


def write_markdown_report(results, metrics):
    md = []
    md.append("# Golden Dataset Evaluation Report")
    md.append(f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}")
    md.append("")
    md.append("## Metrics (binary, COMPLIANT = positive class)")
    md.append(f"- **Total cases:** {metrics['total_cases']} ({metrics['errors']} errored)")
    md.append(f"- **Accuracy:** {metrics['accuracy']:.1%}")
    md.append(f"- **Precision:** {metrics['precision']:.1%}")
    md.append(f"- **Recall:** {metrics['recall']:.1%}")
    md.append(f"- **F1:** {metrics['f1']:.1%}")
    md.append(f"- **False Positives:** {metrics['false_positives']} | **False Negatives:** {metrics['false_negatives']}")
    rr = metrics["retrieval_recall_rate"]
    md.append(f"- **Retrieval Recall Rate:** {rr if rr == 'N/A' else f'{rr:.1%}'}")
    md.append("")
    md.append("Target from the RAG accuracy plan: Accuracy >= 80%, ideally 85-90%. "
               "Treat this as directional until the dataset covers ~30-50 real examples "
               "across ~15-20 controls -- 4 seeded cases on one control isn't enough to "
               "draw real conclusions from.")
    md.append("")
    md.append("## Per-case results")
    md.append("")
    md.append("| ID | Control | Expected | Actual | Match | Retrieval Recall | Time (s) |")
    md.append("|---|---|---|---|---|---|---|")
    for r in results:
        if "error" in r:
            md.append(f"| {r['id']} | - | - | ERROR: {r['error']} | - | - | - |")
        else:
            match_icon = "PASS" if r["match"] else "FAIL"
            md.append(f"| {r['id']} | {r['control_id']} | {r['expected']} | {r['actual']} | {match_icon} | {r['retrieval_recall']} | {r['elapsed_sec']} |")

    with open(RESULTS_MD_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    print(f"Saved markdown report to {RESULTS_MD_PATH}")


def main():
    print("=" * 80)
    print("RUNNING GOLDEN DATASET EVALUATION")
    print("=" * 80)

    cases = load_dataset()
    control_templates = {}
    for c in USE_CASES:
        cid = c["use_case"].split(" ")[0]
        control_templates[cid] = c

    results = []
    for case in cases:
        print(f"\n--- {case['id']}: control {case['control_id']} ({case.get('source', 'unlabeled source')}) ---")
        result = run_case(case, control_templates)
        results.append(result)
        if "error" in result:
            print(f"ERROR: {result['error']}")
        else:
            print(f"Expected={result['expected']} Actual={result['actual']} Match={result['match']} "
                  f"RetrievalRecall={result['retrieval_recall']} Time={result['elapsed_sec']}s")

    metrics = compute_metrics(results)

    print("\n" + "=" * 80)
    print("GOLDEN EVAL SUMMARY")
    print(f"Accuracy: {metrics['accuracy']:.1%} | Precision: {metrics['precision']:.1%} | "
          f"Recall: {metrics['recall']:.1%} | F1: {metrics['f1']:.1%}")
    print(f"FP: {metrics['false_positives']} | FN: {metrics['false_negatives']} | Errors: {metrics['errors']}")
    print("=" * 80)

    with open(RESULTS_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump({"results": results, "metrics": metrics}, f, indent=2)
    print(f"Saved JSON results to {RESULTS_JSON_PATH}")

    write_markdown_report(results, metrics)


if __name__ == "__main__":
    main()
