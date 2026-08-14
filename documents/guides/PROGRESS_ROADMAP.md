# Compliance Auditor Progress & Development Roadmap

This document outlines the completed features, design decisions, and future roadmap items for the Offline ISO 27001 Auditor system.

---

## 📅 Completed Milestones

### 1. High-Performance XML Tag Auditing (Production-Grade)
* **XML-First Generation**: Replaced strict JSON schema constraints with XML tag structure constraints in the generation and reflection prompts. This prevents sampler deadlocks on local CPU/GPU environments for models like Gemma and Qwen.
* **Auto-Repair Parser**: Implemented robust regex-based tag repair to automatically close unclosed leaf elements (e.g. `<status>COMPLIANT` -> `<status>COMPLIANT</status>`) before ElementTree parsing.
* **Hybrid Parser**: Parses XML with Python's native `xml.etree.ElementTree` wrapped in a root element, falling back to a line-by-line regex scanner if the XML contains syntax errors.
* **JSON Fallback Support**: Keeps backwards compatibility. If the model outputs a JSON string or markdown JSON block, the parser automatically detects it and parses it as JSON.
* **Total Failure Fallback**: Added a catch-all exception handler that catches any completely unparseable output (including empty responses) and safely returns a default `NON_COMPLIANT` finding instead of crashing the graph execution.


### 2. App-Side Deterministic Severity Mapping (Prompt Cleanup)
* **LLM Prompts Cleanup**: Removed the `severity` field entirely from prompt output schemas to keep LLM responses fast and structurally simple.
* **App-Side Logic**: Severity is assigned deterministically by Python logic:
  * Compliant findings automatically receive a severity of `N/A`.
  * Non-compliant or partially compliant findings automatically merge the control's default severity (configured in `USE_CASES`).

---

## 📝 Configuration & Customization Rules

### If You Add, Modify, or Remove a Control:
* **Control Definition**: Controls are defined in [src/core/make_controls.py](file:///c:/Users/HP/Desktop/new%20rt/src/core/make_controls.py) and compiled to [src/core/controls_data.py](file:///c:/Users/HP/Desktop/new%20rt/src/core/controls_data.py) when executed.
* **Changing Control Severity**: To change the risk priority of a control, update the severity argument in `c5_controls`, `c6_controls`, `c7_controls`, or `c8_controls` inside `make_controls.py` and run the script:
  ```bash
  python src/core/make_controls.py
  ```
  The parser will automatically read the updated severity and apply it during auditing runs.
* **If You Remove a Control**: If a control is removed from `make_controls.py`, the system will no longer scan for it or reference its severity. Make sure to rebuild the controls data using the build command above.

---

## 🚀 Future Roadmap (What to Implement Next)

### 1. Migrate Other Chains to XML Format
* **Direct Auditing in `src/ui/app.py`**: The scoping and direct batch-auditing functions in `src/ui/app.py` currently use `"format": "json"`. If these functions experience deadlocks on lower-spec hardware, migrate them to the XML-first parsing strategy implemented in `audit_chains.py`.

### 2. Advanced OCR Distortion Handling
* **OCR Fuzzy Matching**: Enhance the fuzzy threshold checks in [src/core/validator.py](file:///c:/Users/HP/Desktop/new%20rt/src/core/validator.py) to ignore common PDF scanning noise (such as replacing `1` with `l` or `I`, and correcting spacing breaks).

### 3. Model Caching and Embedding Optimization
* **Context Caching**: Implement local context caching mechanisms for Ollama queries to reduce token generation overhead when running multiple controls against the same document.
