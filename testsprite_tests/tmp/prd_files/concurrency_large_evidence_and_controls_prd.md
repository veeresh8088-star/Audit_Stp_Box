# Product Requirements Document (PRD)
## Project: AICyberAuditBox - Concurrency Capacity, Large Evidence & High Control Count Stress Testing

### 1. Overview
Determine and stress-test the concurrency capacity under 16GB (8 CPU) and 32GB (8 vCPU) hardware configurations, validating robust performance under massive evidence files (500+ sections, 5,000+ chunks) and high control volume (93+ Annex A controls).

### 2. Verification Modules

#### Module 1: Hardware Concurrency & Parallel Slot Allocation
- Benchmark parallel slot allocation formula: `_np = max(1, min(8, int((avail_gb - model_gb) / slot_gb)))`.
- Verify resource consumption for 16GB RAM (3-4 concurrent runs optimal, max 6) vs 32GB RAM (4-6 concurrent runs optimal, max 8).

#### Module 2: Massive Evidence & Large Document Stress Handling
- Ingest massive evidence files (simulating 500+ pages, 100,000+ characters, 5,000+ chunks).
- Verify hybrid retrieval + BGE reranker selects top candidates within token budget (`hard_max` ceiling).
- Confirm zero context overflow and zero KV cache memory spikes.

#### Module 3: High Control Count Scaling (93+ ISO 27001 Controls)
- Simulate full Annex A audit execution (93 controls).
- Verify dynamic timeout calculation: `timeout = 600s + (num_controls * 30s)` -> 3390s.
- Verify per-control granular checkpointing persistence and zero memory leakage over high control counts.
