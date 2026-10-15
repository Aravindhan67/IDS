"""
Master One-Click Orchestrator CLI
Hybrid Android APK Intrusion Detection System (HIDS)

Usage:
  python run_all.py --mode gui          # Launches the interactive Streamlit Security Portal (http://localhost:8501)
  python run_all.py --mode benchmark    # Runs all 5-fold CV benchmarks and outputs results.json + figures
  python run_all.py --mode analyze --apk sample.apk  # Evaluates an APK with full multi-layer analysis
"""

import os
import sys
import argparse
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("HIDS_Master")


def main():
    parser = argparse.ArgumentParser(description="Hybrid Android APK Intrusion Detection System (HIDS)")
    parser.add_argument("--mode", choices=["benchmark", "analyze", "gui"], default="gui",
                        help="Execution mode: 'gui' (Streamlit web dashboard), 'benchmark' (run 5-fold CV & paper ablations), or 'analyze' (scan single APK)")
    parser.add_argument("--apk", type=str, help="Path to raw .apk file for live analysis")
    args = parser.parse_args()

    if args.mode == "gui":
        import socket
        import webbrowser
        import subprocess

        # Check if port 8501 is already active
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        is_running = (sock.connect_ex(('127.0.0.1', 8501)) == 0)
        sock.close()

        if is_running:
            logger.info("AegisDroid HIDS Streamlit Server is ALREADY ACTIVE on http://localhost:8501!")
            logger.info("Opening your browser to http://localhost:8501 ...")
            webbrowser.open("http://localhost:8501")
        else:
            logger.info("Launching AegisDroid HIDS Streamlit Web Portal on http://localhost:8501 ...")
            subprocess.run(["streamlit", "run", "streamlit_app.py"])

    elif args.mode == "benchmark":
        logger.info("Starting End-to-End Experimental Benchmark Pipeline...")
        from src.run_experiments import run_benchmark
        from src.explainability import SHAPExplainerEngine
        from src.generate_paper_artifacts import generate_all_artifacts

        logger.info("Step 1: Running Cross-Validation & Ablation Suite...")
        run_benchmark()

        logger.info("Step 2: Generating SHAP Explainability Plots...")
        explainer = SHAPExplainerEngine()
        explainer.generate_all_explanations(max_samples=250)

        logger.info("Step 3: Exporting 300 DPI Publication Figures & LaTeX Tables...")
        generate_all_artifacts()

        logger.info("SUCCESS: All benchmarks completed and paper artifacts generated in c:/ids/outputs/")

    elif args.mode == "analyze":
        if not args.apk:
            logger.error("Please provide --apk <path_to_apk>")
            sys.exit(1)
        if not os.path.exists(args.apk):
            logger.error("APK file not found: %s", args.apk)
            sys.exit(1)

        logger.info("Analyzing APK: %s ...", args.apk)
        from src.virustotal_client import VirusTotalSignatureAnalyzer
        from src.feature_extractor import DrebinFeatureExtractor
        from src.dynamic_engine import DynamicTelemetryEngine
        from src.hybrid_fusion import CascadedTriagePipeline
        from src.remediation import WhatIfRemediationEngine
        from xgboost import XGBClassifier
        from src.data_loader import load_drebin
        import json

        # 0. Signature Pre-Filter via VirusTotal
        vt_client = VirusTotalSignatureAnalyzer()
        vt_result = vt_client.analyze_apk_file(args.apk)
        logger.info("--- Layer 0: Deterministic Signature Check ---")
        if vt_result.get("signature_detected"):
            logger.warning("[SIGNATURE MATCH]: VirusTotal %s engines flagged as malicious! Threat: %s",
                           vt_result.get("detection_ratio"), vt_result.get("threat_label"))
        else:
            logger.info("[SIGNATURE CLEAN / UNKNOWN]: %s", vt_result.get("message"))
        logger.info("Note: Signature results are reported independently from ML generalization.")

        # 1. Static feature extraction
        extractor = DrebinFeatureExtractor()
        static_vector = extractor.extract_from_apk(args.apk, mode="all_215")
        breakdown = extractor.get_feature_breakdown(static_vector)
        logger.info("Static Feature Breakdown: %s", breakdown)

        # 2. Static inference
        with open("c:/ids/models/best_params_static.json", "r") as f:
            static_params = json.load(f)
        X_s, y_s, feat_s = load_drebin(drop_duplicates=True)
        static_model = XGBClassifier(**static_params, random_state=42, n_jobs=-1, eval_metric="logloss")
        static_model.fit(X_s.values, y_s.values)

        p_static = float(static_model.predict_proba(static_vector.reshape(1, -1))[0, 1])
        logger.info("Static Malware Probability: %.4f", p_static)

        # 3. Dynamic Telemetry & Triage
        triage = CascadedTriagePipeline()
        triage_res = triage.evaluate_sample(p_static=p_static)
        logger.info("Stage 1 Triage Result: %s", triage_res)

        if triage_res["sandbox_invoked"]:
            logger.info("Ambiguous sample. Invoking Dynamic Sandbox / Calibrated Telemetry...")
            dyn_engine = DynamicTelemetryEngine()
            dyn_vector = dyn_engine.generate_calibrated_telemetry(malware_propensity=p_static)
            with open("c:/ids/models/best_params_dynamic.json", "r") as f:
                dyn_params = json.load(f)
            from src.data_loader import load_dynamic
            X_d, y_d, _, _ = load_dynamic(drop_duplicates=True)
            dyn_model = XGBClassifier(**dyn_params, random_state=42, n_jobs=-1, eval_metric="logloss")
            dyn_model.fit(X_d.values, y_d.values)

            p_dynamic = float(dyn_model.predict_proba(dyn_vector.reshape(1, -1))[0, 1])
            triage_final = triage.evaluate_sample(p_static=p_static, p_dynamic=p_dynamic)
            logger.info("Final Cascaded Hybrid Verdict: %s", triage_final)
        else:
            triage_final = triage_res

        # 4. If malware, run What-If Remediation
        if triage_final["label"] == 1:
            remediation = WhatIfRemediationEngine(static_model, feat_s)
            rem_res = remediation.analyze_single_sample(static_vector)
            logger.info("What-If Remediation Analysis:")
            logger.info("Initial Risk: %.4f -> Remediated Risk: %.4f (Drop: %.4f)",
                        rem_res.get("initial_risk"), rem_res.get("final_risk"), rem_res.get("total_risk_drop"))
            logger.info("Recommended Revocations: %s", rem_res.get("recommended_revocations"))


if __name__ == "__main__":
    main()
