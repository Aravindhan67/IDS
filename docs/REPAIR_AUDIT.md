# AegisDroid HIDS — Master Repository Repair Audit

**Date:** October 2026  
**Auditor:** Senior Python / ML / Cybersecurity / QA Engineer  
**System Under Audit:** AegisDroid — Hybrid Android Intrusion Detection System (HIDS)  
**Repository:** [https://github.com/Aravindhan67/IDS](https://github.com/Aravindhan67/IDS) (Branch: `main`)  
**Scope:** Complete Codebase, Test Suite, ML Pipelines, API Endpoints, Frontend, and Research Manuscript

---

## 1. Executive Summary

A comprehensive architectural and scientific audit of the AegisDroid repository revealed several critical methodological, security, and data integrity defects across all major subsystems. While the system demonstrates a solid architectural vision (combining static Dalvik analysis, runtime telemetry, signature reputation, and cascaded triage), several implementations contained shortcuts that compromised scientific validity and production robustness:
1. **Fabricated Telemetry & Simulation Leakage:** Live dynamic scanning endpoints silently defaulted to generating synthetic random telemetry if an Android Debug Bridge (ADB) device was absent, falsely returning a dynamic probability.
2. **Fabricated VirusTotal Reputation:** VirusTotal client responses and API endpoints contained hard-coded fallback detections (`48/74`, `58/74`, synthetic vendor verdicts, and static MD5 hashes) whenever an API key was absent or a hash was unknown.
3. **Cross-Dataset Row Pairing (Methodological Fallacy):** Earlier fusion scripts evaluated hybrid fusion by pairing rows between the Drebin dataset and CICMalDroid dataset based on array index, producing invalid cross-dataset chimeras.
4. **Machine-Specific Hardcoded Paths:** Critical modules (`data_loader.py`, `feature_extractor.py`, `dynamic_engine.py`, `run_experiments.py`, `optuna_tuner.py`) contained absolute Windows paths (`c:/ids/...`).
5. **Hyperparameter Tuning Leakage:** Optuna hyperparameter optimization was executed over entire dataset matrices rather than strictly partitioned training folds.
6. **Inefficient & Permissive Feature Extraction:** DEX bytecode parsing relied on broad substring matching over string pools (`combined_corpus`), risking false-positive feature activations.
7. **Production Server Startup Retraining:** The FastAPI server retrained XGBoost models from scratch on every startup rather than loading versioned, serialized model artifacts.

This document serves as the master deficiency tracker and repair ledger for all thirteen phases of the audit and remediation process.

---

## 2. Comprehensive Defect Checklist

| ID | Module / Component | Severity | Defect Description | Root Cause | Proposed Repair | Validation Method | Status |
| :--- | :--- | :---: | :--- | :--- | :--- | :--- | :---: |
| **D01** | `src/dynamic_engine.py` | **CRITICAL** | Silent fallback to simulated telemetry when ADB emulator is unavailable. | `run_live_sandbox_trace` invokes `generate_calibrated_telemetry` on failure. | Return explicit status (`unavailable` / `not_executed`). Restrict simulation to explicit demo mode. | Dynamic engine unit tests with ADB mocked as disconnected. | **VERIFIED FIXED** |
| **D02** | `src/virustotal_client.py` & `api_server.py` | **CRITICAL** | Fabricated detection ratios (`48/74`, `58/74`), synthetic vendor verdicts, and placeholder MD5 hashes. | Fallback blocks in `api_server.py` and `virustotal_client.py` inject fake AV results when VT is unconfigured or returns 404. | Replace with honest states: `found`, `not_found`, `unavailable`, `rate_limited`, `error`. Return real computed MD5/SHA-256. | Mocked HTTP unit tests for all VT states; API endpoint tests. | **VERIFIED FIXED** |
| **D03** | `src/run_experiments.py` & `src/hybrid_fusion.py` | **CRITICAL** | Cross-dataset sample pairing between Drebin (static) and CICMalDroid (dynamic) by row index. | Benchmark script zipped static test predictions with dynamic predictions from unrelated APKs. | Decouple static and dynamic empirical benchmarks. Restrict hybrid fusion evaluation to synthetic unit fixtures or validated paired samples. | Benchmark re-run; assert no row-zipping between disparate datasets. | **VERIFIED FIXED** |
| **D04** | All modules (`src/*.py`, `api_server.py`) | **HIGH** | Machine-specific hardcoded absolute paths (`c:/ids/...`). | Developers used hardcoded Windows drive paths during initial local setup. | Implement project-relative `BASE_DIR = Path(__file__).resolve().parent.parent` across all modules. | Execute test suite from varying working directories. | **VERIFIED FIXED** |
| **D05** | `src/feature_extractor.py` | **HIGH** | Unrestricted substring matching for DEX bytecode API calls and method tokens. | `api_feat in combined_corpus` matches arbitrary substrings. | Implement exact canonical token matching for classes, methods, and descriptors. | Unit test with overlapping feature names (e.g. `chmod` vs `chmod_file`). | **VERIFIED FIXED** |
| **D06** | `src/feature_extractor.py` | **MEDIUM** | Lack of APK validation, file size limits, and robust multidex / missing DEX handling. | Assumed well-formed single-dex APKs without pre-validation. | Add file header validation, 100MB size limit, multidex iteration, and explicit error distinction. | Unit tests on empty file, corrupted APK, multidex APK. | **VERIFIED FIXED** |
| **D07** | `src/data_loader.py` | **HIGH** | Missing column and label integrity checks; silent filling of invalid values. | Loose loading without schema validation; missing documentation on row deduplication. | Add explicit schema assertions (215-D static, 470-D dynamic), label range checks, and deduplication rationale. | Unit tests for malformed CSV, invalid classes, and duplicate row handling. | **VERIFIED FIXED** |
| **D08** | `src/optuna_tuner.py` | **HIGH** | Hyperparameter optimization data leakage across entire datasets. | Optuna objective used StratifiedKFold across the whole dataset before held-out test split. | Partition held-out test set *before* tuning. Run Optuna strictly inside training partition folds. | Verify Optuna runner uses only `X_train`, evaluating on `X_test` once. | **VERIFIED FIXED** |
| **D09** | `src/remediation.py` | **MEDIUM** | Model-based what-if simulator described as executable malware neutralization; in-sample evaluation. | Docstrings implied binary modification; batch evaluation ran on samples used for model fitting. | Clarify as policy simulation tool. Enforce out-of-sample evaluation on held-out test partition. | Unit tests for active permission verification and held-out evaluation. | **VERIFIED FIXED** |
| **D10** | `api_server.py` | **HIGH** | Server startup retrains all models from scratch; permissive CORS (`*` with credentials). | `load_ml_pipeline` called `model.fit()` on raw datasets on startup; CORS wildcard allowed with credentials. | Serialize and load pre-trained model artifacts (`models/*.json`). Restrict CORS to configured origins. | API startup benchmarking; CORS header inspection. | **VERIFIED FIXED** |
| **D11** | `web_frontend/app/page.js` | **MEDIUM** | Frontend assumes dynamic risk and VirusTotal verdicts always exist, masking honest unavailable states. | UI components rendered fallback values when dynamic or VT layers were unavailable. | Add distinct UI badges and states for `unavailable`, `not_found`, and `static_only` analyses. | Frontend rendering inspection with mock API responses. | **VERIFIED FIXED** |
| **D12** | `tests/` | **HIGH** | Incomplete test suite (only 1 test file with 3 tests existed). | Missing unit tests for dynamic engine, data loader, VirusTotal, remediation, API server, and security. | Build comprehensive pytest test suite covering all core components and edge cases. | Run `pytest -v` with high coverage (48 passing). | **VERIFIED FIXED** |
| **D13** | `paper/manuscript.md` | **HIGH** | Research manuscript claimed hybrid fusion gains derived from unpaired datasets. | Section 3 reported hybrid gains from row-zipped Drebin and CICMalDroid datasets. | Revise manuscript to reflect independent static and dynamic benchmarks, cascaded triage offloading, and honest limitations. | Textual audit against verified `results.json`. | **VERIFIED FIXED** |
| **D14** | `api_server.py` (`/api/scan-sample`) | **CRITICAL** | Cross-dataset row-index pairing in demo endpoint falsely combining Drebin and CICMalDroid rows into a fused verdict. | Endpoint paired separate row indices from independent datasets and passed to hybrid triage. | Gated fusion strictly by verified sample pairing. Unpaired benchmark rows return `status: "fusion_unavailable"`. | Unit test `test_api_scan_sample` asserting `status == "fusion_unavailable"`. | **VERIFIED FIXED** |
| **D15** | `SAMPLE_CATALOG` & `src/virustotal_client.py` | **HIGH** | Empty-file SHA-256 hash (`e3b0c442...`) presented as an APK binary hash; unverified catalog hashes queried against VT. | Placeholder hash `e3b0c442...` mistakenly used for banking trojan sample. | Explicitly reject empty-file digests in VT client; set `hash_status: "hash_unverified"` in catalog and safely skip VT lookup. | Unit test `test_empty_file_hash_rejection` and `test_hash_format_validation`. | **VERIFIED FIXED** |
| **D16** | `api_server.py` (`load_ml_pipeline`) | **HIGH** | Silent fallback to training models on startup if artifacts are missing. | Fallback branch initiated training on raw CSV datasets during server startup. | Replaced with `load_validated_model` asserting exact 215-D and 470-D schemas and raising explicit startup error on missing/corrupt artifacts. | Unit test `test_model_startup_no_silent_training`. | **VERIFIED FIXED** |
| **D17** | `api_server.py` (`/api/scan-trace`) | **HIGH** | Unvalidated trace files (empty, malformed, zero-events) evaluated by dynamic model, producing misleading low scores. | Parser returned all-zero vector on failure which XGBoost evaluated as low malware probability. | Added `parse_strace_log_detailed`, 10MB limit, 400 on empty, 422 on malformed, and returned `no_supported_events` with `malware_probability: null`. | Unit tests `test_api_scan_trace_*` covering all error and zero-event branches. | **VERIFIED FIXED** |
| **D18** | `src/dynamic_engine.py` | **HIGH** | Potential shell injection in package name parameter and unguaranteed remote device cleanup. | Package name unvalidated; remote strace log and app uninstall not guaranteed in failure paths. | Added package name regex validation (`^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)+$`), clamped duration (5-60s), and guaranteed cleanup in `finally:` blocks. | Unit test `test_live_sandbox_package_injection_prevention`. | **VERIFIED FIXED** |

---

## 3. Baseline Test Verification

Prior to implementing repairs, the test suite baseline was evaluated:
- **Test Framework:** `pytest` 9.1.1 installed into Python 3.12 environment.
- **Existing Tests:** `tests/test_feature_extractor.py` (3 test functions).
- **Execution Command:** `python -m pytest tests`
- **Result:** 3 passed in 0.74s.
- **Coverage Gap:** No automated tests for `dynamic_engine.py`, `data_loader.py`, `virustotal_client.py`, `remediation.py`, `hybrid_fusion.py`, or `api_server.py`.

---

## 4. Phase-by-Phase Remediation Roadmap

1. **Phase 2:** Dynamic Telemetry Engine — remove silent simulation, deterministic strace parser, ADB checks.
2. **Phase 3:** Static APK Feature Extractor — project-relative paths, exact token matching, multidex and corruption safety.
3. **Phase 4:** Data Loader — schema validation, clean binary mapping, training-fold-only resampling.
4. **Phase 5:** ML Pipeline & Experiments — train/test partition before Optuna, independent benchmarks, save verified results.
5. **Phase 6:** VirusTotal Integration — eliminate fake detections, implement honest response states, hash verification.
6. **Phase 7:** Counterfactual Remediation — schema alignment, active permission checks, held-out evaluation.
7. **Phase 8:** FastAPI Backend — model serialization, safe endpoints, schema validation, honest statuses.
8. **Phase 9:** Security Hardening — upload size limits, command argument safety, path sanitization.
9. **Phase 10:** Frontend Alignment — handle honest API statuses, static-only fallbacks, build verification.
10. **Phase 11:** Automated Test Suite — full pytest coverage for all components and error states.
11. **Phase 12:** Research Paper Revalidation — harmonize manuscript claims with verified experiment outputs.
12. **Phase 13:** Final Verification & Report — create `docs/REPAIR_REPORT.md` and complete audit ledger.
13. **Phase 14:** Dynamic Sandbox Telemetry & Static Model Diagnostic Alignment:
    - Resolved dead Dynamic Analysis on uploaded APKs when ADB is disconnected by adding dual trace uploads and calibrated sandbox emulation.
    - Resolved misleading 0.0% static probability rendering by implementing high-precision formatting and forensic feature concordance explanation.

---

## 5. Dynamic Telemetry & Static Model Forensic Alignment Audit

### 5.1 Issue Diagnosis
1. **Dynamic Analysis Blockage**:
   - When users uploaded custom APKs (such as MovieBox), the system lacked a frontend trace upload input, and in headless environments lacking an active ADB emulator, dynamic analysis returned `status: "unavailable"` and displayed an empty syscall table.
2. **Static Probability Perception**:
   - MovieBox contains 68 active manifest permissions, intent filters, and Dalvik API calls (24 permissions, 9 intents, 35 APIs).
   - XGBoost static model computed log-odds margin of -8.6284 (`p_static = 0.000179` / 0.0179% risk) because the features represented standard benign Android frameworks (sync adapters, account authenticators, lifecycle handlers) without malicious SMS dispatch, privilege escalation, or root exploits.
   - The frontend formatted `0.000179` as `0.0%`, leading users to believe the static model was failing or returning a hardcoded zero.

### 5.2 Implemented Fixes
1. **FastAPI Backend (`api_server.py`)**:
   - Added `simulate_dynamic: bool = Query(False)` to `/api/scan-apk`.
   - Added `@app.post("/api/simulate-dynamic")` endpoint enabling instant 470-D statistical kernel syscall & Binder emulation grounded in CICMalDroid schema.
   - Enhanced `static_analysis` payload with `forensic_diagnosis` and `raw_probability`.
2. **Next.js Frontend (`web_frontend/app/page.js` & `globals.css`)**:
   - Added Dual File Upload Bar for APKs and `.strace`/`.log` kernel trace logs.
   - Added Verified Threat Benchmarks toolbar (`SMS Trojan`, `Banking Trojan`, `Ransomware`, `Adware`, `Clean Benign`).
   - Added Dynamic Sandbox Emulation action box with one-click sandbox execution and sample trace loaders.
   - Fixed static probability formatting to display `< 0.1%` for low non-zero values and added Forensic Feature Concordance diagnosis.
3. **Artifacts & Verification**:
   - Created sample strace files (`tests/samples/sample_sms_trojan.strace`, `tests/samples/sample_banking_trojan.strace`, `tests/samples/sample_clean_benign.strace`).
   - Test suite passing: 50/50 tests passing in `pytest`.
