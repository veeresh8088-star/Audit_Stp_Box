# Golden Dataset Evaluation Report
**Date:** 2026-08-14 18:34:56

## Metrics (binary, COMPLIANT = positive class)
- **Total cases:** 4 (0 errored)
- **Accuracy:** 100.0%
- **Precision:** 100.0%
- **Recall:** 100.0%
- **F1:** 100.0%
- **False Positives:** 0 | **False Negatives:** 0
- **Retrieval Recall Rate:** 100.0%

Target from the RAG accuracy plan: Accuracy >= 80%, ideally 85-90%. Treat this as directional until the dataset covers ~30-50 real examples across ~15-20 controls -- 4 seeded cases on one control isn't enough to draw real conclusions from.

## Per-case results

| ID | Control | Expected | Actual | Match | Retrieval Recall | Time (s) |
|---|---|---|---|---|---|---|
| GD-001 | 8.5 | COMPLIANT | COMPLIANT | PASS | True | 410.63 |
| GD-002 | 8.5 | NON_COMPLIANT | NON_COMPLIANT | PASS | True | 372.5 |
| GD-003 | 8.5 | NON_COMPLIANT | NON_COMPLIANT | PASS | N/A | 597.95 |
| GD-004 | 8.5 | NON_COMPLIANT | NON_COMPLIANT | PASS | N/A | 601.76 |