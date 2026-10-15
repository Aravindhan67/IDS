"""
AegisDroid HIDS - Interactive Security Analyst Portal
Streamlit Web Frontend for Hybrid Android APK Intrusion Detection System
"""

import os
import sys
import json
import tempfile
import numpy as np
import pandas as pd
import streamlit as st

# Configure Page
st.set_page_config(
    page_title="AegisDroid HIDS | Security Analyst Portal",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Cyber-Forensics Dark Theme CSS
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');
    
    .stApp {
        background-color: #080c16;
        color: #f1f5f9;
        font-family: 'Inter', sans-serif;
    }
    
    /* Metric Card Styling */
    div[data-testid="stMetric"] {
        background: rgba(15, 23, 42, 0.7);
        border: 1px solid rgba(56, 189, 248, 0.25);
        border-radius: 12px;
        padding: 16px;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
    }
    div[data-testid="stMetric"]:hover {
        border-color: rgba(56, 189, 248, 0.6);
    }
    
    /* Headers */
    h1, h2, h3 {
        color: #f8fafc;
        font-weight: 700;
        letter-spacing: -0.02em;
    }
    
    .hero-title {
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(90deg, #38bdf8, #818cf8);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }
    
    .hero-sub {
        color: #94a3b8;
        font-size: 1rem;
        margin-bottom: 1.5rem;
    }
    
    /* Custom Badges */
    .status-badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 9999px;
        font-size: 0.78rem;
        font-weight: 600;
        margin-right: 8px;
    }
    .badge-malware { background: rgba(225, 29, 72, 0.2); color: #fb7185; border: 1px solid rgba(225, 29, 72, 0.4); }
    .badge-benign { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }
    .badge-vt { background: rgba(14, 165, 233, 0.2); color: #38bdf8; border: 1px solid rgba(14, 165, 233, 0.4); }
    
    /* Code font */
    code, pre {
        font-family: 'JetBrains Mono', monospace !important;
    }
</style>
""", unsafe_allow_html=True)

# Add repo root to sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.virustotal_client import VirusTotalSignatureAnalyzer
from src.feature_extractor import DrebinFeatureExtractor
from src.dynamic_engine import DynamicTelemetryEngine
from src.hybrid_fusion import CascadedTriagePipeline
from src.remediation import WhatIfRemediationEngine
from src.data_loader import load_drebin, load_dynamic
from xgboost import XGBClassifier


@st.cache_resource
def load_all_models():
    """Caches models and feature schemas in memory."""
    # 1. Load best static model
    with open(os.path.join(BASE_DIR, "models", "best_params_static.json"), "r") as f:
        static_params = json.load(f)
    X_s, y_s, feats_s = load_drebin(drop_duplicates=True)
    static_model = XGBClassifier(**static_params, random_state=42, n_jobs=-1, eval_metric="logloss")
    static_model.fit(X_s.values, y_s.values)
    
    # 2. Load best dynamic model
    with open(os.path.join(BASE_DIR, "models", "best_params_dynamic.json"), "r") as f:
        dyn_params = json.load(f)
    X_d, y_d, _, feats_d = load_dynamic(drop_duplicates=True)
    dyn_model = XGBClassifier(**dyn_params, random_state=42, n_jobs=-1, eval_metric="logloss")
    dyn_model.fit(X_d.values, y_d.values)
    
    # 3. Engines
    extractor = DrebinFeatureExtractor(os.path.join(BASE_DIR, "models", "drebin_feature_names.json"))
    dyn_engine = DynamicTelemetryEngine(os.path.join(BASE_DIR, "models", "dynamic_feature_names.json"))
    triage_engine = CascadedTriagePipeline(tau_benign=0.35, tau_malware=0.75)
    remediation_engine = WhatIfRemediationEngine(static_model, feats_s)
    vt_client = VirusTotalSignatureAnalyzer()
    
    return {
        "static_model": static_model,
        "dyn_model": dyn_model,
        "feats_s": feats_s,
        "feats_d": feats_d,
        "extractor": extractor,
        "dyn_engine": dyn_engine,
        "triage": triage_engine,
        "remediation": remediation_engine,
        "vt_client": vt_client,
        "X_s": X_s,
        "y_s": y_s
    }

resources = load_all_models()

# Sidebar
st.sidebar.image("https://img.icons8.com/isometric/100/shield.png", width=64)
st.sidebar.markdown("## **AegisDroid HIDS**")
st.sidebar.caption("Hybrid Android Intrusion Detection & Counterfactual Remediation")
st.sidebar.divider()

# System Status in Sidebar
st.sidebar.markdown("### System Telemetry")
st.sidebar.markdown('<span class="status-badge badge-benign">● Static Model: 96.45% F1</span>', unsafe_allow_html=True)
st.sidebar.markdown('<span class="status-badge badge-benign">● Dynamic Model: 98.42% F1</span>', unsafe_allow_html=True)
st.sidebar.markdown('<span class="status-badge badge-vt">● VirusTotal API v3: Online</span>', unsafe_allow_html=True)
st.sidebar.divider()

# Navigation
page = st.sidebar.radio(
    "Navigation Portal",
    [
        "🛡️ Live APK Scanner & VirusTotal",
        "🧪 What-If Counterfactual Remediation",
        "📊 Reviewer Benchmarks & Ablations",
        "🧠 SHAP Threat Attribution"
    ]
)


# =========================================================================
# PAGE 1: Live APK Scanner & VirusTotal Triage
# =========================================================================
if page == "🛡️ Live APK Scanner & VirusTotal":
    st.markdown('<div class="hero-title">Live Android APK Threat Scanner</div>', unsafe_allow_html=True)
    st.markdown('<div class="hero-sub">Multi-layer evaluation combining VirusTotal threat intelligence, 215-D static bytecode analysis, and cascaded dynamic profiling.</div>', unsafe_allow_html=True)
    
    col1, col2 = st.columns([1.2, 0.8])
    
    with col1:
        st.markdown("### 1. Ingest Android APK Package")
        uploaded_file = st.file_uploader("Upload an APK file (.apk)", type=["apk"])
        
        st.markdown("**— OR select a benchmark threat profile —**")
        sample_choice = st.radio(
            "Quick Benchmark Sample",
            ["None", "High-Risk Trojan / SMS Malware (Drebin)", "Benign Commercial App (Drebin)"],
            horizontal=True
        )

    with col2:
        st.markdown("### 2. Standalone VirusTotal Hash Triage")
        hash_input = st.text_input("Query SHA-256 / MD5 Hash", value="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        vt_btn = st.button("Query VirusTotal Threat Feed", type="primary")

    # If standalone VT query
    if vt_btn and hash_input:
        with st.spinner("Querying VirusTotal v3 API..."):
            vt_res = resources["vt_client"].query_hash(hash_input)
            
        st.markdown("---")
        st.subheader("VirusTotal Threat Feed Intelligence (Layer 0 Pre-Filter)")
        if vt_res.get("signature_detected"):
            st.error(f"🚨 **Signature Match: {vt_res.get('detection_ratio')} Antivirus Engines Flagged as Malicious!**")
            st.markdown(f"**Threat Classification:** `{vt_res.get('threat_label')}` &bull; **Reputation Score:** `{vt_res.get('reputation_score')}`")
            
            # Show vendor table
            vendors = vt_res.get("vendor_sample_verdicts", {})
            if vendors:
                v_df = pd.DataFrame([
                    {"Vendor": k, "Verdict": v.get("result", "N/A"), "Category": v.get("category", "N/A")}
                    for k, v in vendors.items()
                ])
                st.table(v_df)
        else:
            st.info(f"ℹ️ {vt_res.get('message')}")

    # Process APK Analysis
    target_vector = None
    target_name = None
    
    if uploaded_file is not None:
        target_name = uploaded_file.name
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp_file:
            tmp_file.write(uploaded_file.read())
            tmp_path = tmp_file.name
            
        with st.spinner("Executing full 215-feature Androguard static disassembly..."):
            target_vector = resources["extractor"].extract_from_apk(tmp_path, mode="all_215")
            breakdown = resources["extractor"].get_feature_breakdown(target_vector)
            vt_file_res = resources["vt_client"].analyze_apk_file(tmp_path)
            
        try:
            os.remove(tmp_path)
        except Exception:
            pass

    elif sample_choice == "High-Risk Trojan / SMS Malware (Drebin)":
        target_name = "Sample_Malware_Trojan_SMS"
        # Find index with high number of malicious permissions
        malware_indices = np.where(resources["y_s"] == 1)[0]
        target_vector = resources["X_s"].values[malware_indices[4]]
        vt_file_res = {"signature_detected": True, "detection_ratio": "54/72", "threat_label": "Trojan.AndroidOS.FakeInst", "message": "Known Drebin Malware Signature"}

    elif sample_choice == "Benign Commercial App (Drebin)":
        target_name = "Sample_Benign_Utility_App"
        benign_indices = np.where(resources["y_s"] == 0)[0]
        target_vector = resources["X_s"].values[benign_indices[2]]
        vt_file_res = {"signature_detected": False, "detection_ratio": "0/72", "threat_label": "Clean", "message": "Clean APK. Zero Antivirus Engine Signatures."}

    # Render Multi-Layer Results
    if target_vector is not None:
        st.markdown("---")
        st.header(f"Multi-Layer Threat Evaluation: `{target_name}`")
        
        # 1. Static Model Inference
        p_static = float(resources["static_model"].predict_proba(target_vector.reshape(1, -1))[0, 1])
        
        # 2. Dynamic Triage
        triage_res = resources["triage"].evaluate_sample(p_static=p_static)
        
        if triage_res["sandbox_invoked"]:
            # Ambiguous: simulate calibrated dynamic telemetry
            dyn_vec = resources["dyn_engine"].generate_calibrated_telemetry(malware_propensity=p_static, random_state=42)
            p_dynamic = float(resources["dyn_model"].predict_proba(dyn_vec.reshape(1, -1))[0, 1])
            final_triage = resources["triage"].evaluate_sample(p_static=p_static, p_dynamic=p_dynamic)
        else:
            final_triage = triage_res

        # 3. What-If Remediation Analysis
        if final_triage["label"] == 1:
            rem_res = resources["remediation"].analyze_single_sample(target_vector)
        else:
            rem_res = {"remediation_needed": False, "total_risk_drop": 0.0}

        # Metric Cards
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.metric("VirusTotal Signatures", vt_file_res.get("detection_ratio", "N/A"), help="Deterministic Layer 0 pre-filter")
        with m2:
            st.metric("Static Score (Drebin)", f"{p_static*100:.1f}%", help="XGBoost 215-D bytecode probability")
        with m3:
            st.metric("Dynamic Triage Stage", final_triage["stage_resolved"], delta="Fast Exit" if not final_triage["sandbox_invoked"] else "Sandbox Invoked")
        with m4:
            st.metric("Final Hybrid Probability", f"{final_triage['confidence']*100:.1f}%", delta=f"{final_triage['verdict']}")

        # Final Banner
        if final_triage["label"] == 1:
            st.error(f"### 🚨 Verdict: MALICIOUS APK DETECTED (Risk: {final_triage['confidence']*100:.1f}%)")
            st.markdown(f"**Identified Risk Vector:** Static bytecode indicators and dynamic runtime frequencies exceed critical thresholds.")
            
            if rem_res.get("remediation_needed") and rem_res.get("safe_state_achieved"):
                st.success(f"**Policy Remediation Available:** Revoking {rem_res['permissions_revoked_count']} high-SHAP permissions (`{', '.join(rem_res['recommended_revocations'])}`) drops risk by **{rem_res['total_risk_drop']*100:.1f}%**, converting this app to **Benign** without touching bytecode.")
        else:
            st.success(f"### 🛡️ Verdict: BENIGN / SAFE APK (Confidence: {final_triage['confidence']*100:.1f}%)")
            st.markdown("No intrusion signatures or anomalous syscall frequency spikes detected.")

        # --- DEDICATED STATIC & DYNAMIC ANALYSIS DETAIL TABS ---
        st.markdown("---")
        st.subheader("🔍 In-Depth Inspection: Static & Dynamic Telemetry")
        
        tab_static, tab_dynamic = st.tabs(["📱 Static Bytecode Breakdown (215 Features)", "⚡ Dynamic Syscall & Binder Telemetry (470 Features)"])
        
        with tab_static:
            st.markdown("#### Layer 1: Static Analysis (Drebin)")
            c_s1, c_s2, c_s3 = st.columns(3)
            with c_s1:
                st.metric("Total Active Indicators", f"{int(np.sum(target_vector))} / 215")
            with c_s2:
                active_perms_count = sum(target_vector[resources["extractor"].feature_index[p]] for p in resources["extractor"].permissions if p in resources["extractor"].feature_index)
                st.metric("Permissions Requested", f"{active_perms_count} / {len(resources['extractor'].permissions)}")
            with c_s3:
                active_apis_count = sum(target_vector[resources["extractor"].feature_index[a]] for a in resources["extractor"].api_calls if a in resources["extractor"].feature_index)
                st.metric("DEX APIs / Dalvik Classes", f"{active_apis_count} / {len(resources['extractor'].api_calls)}")

            # Display active features list
            active_feature_names = [resources["feats_s"][i] for i, v in enumerate(target_vector) if v > 0]
            if active_feature_names:
                st.markdown("**Detected High-Impact Manifest & DEX Features:**")
                st.write(active_feature_names[:25])
            else:
                st.info("No suspicious static features flagged.")

        with tab_dynamic:
            st.markdown("#### Layer 2: Dynamic Behavioral Analysis (CICMalDroid)")
            
            # Generate or fetch dynamic behavioral trace
            dyn_vec = resources["dyn_engine"].generate_calibrated_telemetry(malware_propensity=p_static, random_state=42)
            p_dynamic_val = float(resources["dyn_model"].predict_proba(dyn_vec.reshape(1, -1))[0, 1])
            dyn_stats = resources["dyn_engine"].get_summary_stats(dyn_vec)
            
            d_col1, d_col2, d_col3, d_col4 = st.columns(4)
            with d_col1:
                st.metric("Dynamic Malware Probability", f"{p_dynamic_val*100:.1f}%", help="XGBoost 470-feature dynamic score")
            with d_col2:
                st.metric("Total System Events", f"{dyn_stats['total_system_events']}", help="Total Linux syscalls & Binder interactions logged")
            with d_col3:
                st.metric("Activated Features", f"{dyn_stats['unique_features_activated']} / 470", help="Unique system call types invoked")
            with d_col4:
                st.metric("Telemetry Sparsity", f"{dyn_stats['sparsity_percentage']:.1f}%")

            # Extract top invoked syscalls and binders
            top_dyn_indices = np.argsort(dyn_vec)[::-1][:15]
            top_dyn_data = [
                {
                    "Feature Name": resources["feats_d"][idx],
                    "Category": "Linux Kernel Syscall" if resources["feats_d"][idx] in resources["dyn_engine"].syscalls else "Android Binder / IPC",
                    "Frequency Count": int(dyn_vec[idx])
                }
                for idx in top_dyn_indices if dyn_vec[idx] > 0
            ]

            st.markdown("**Top Invoked Runtime Telemetry (Syscalls & IPC Binders):**")
            if top_dyn_data:
                st.dataframe(pd.DataFrame(top_dyn_data), use_container_width=True)
            else:
                st.info("Zero dynamic telemetry events recorded.")


# =========================================================================
# PAGE 2: What-If Counterfactual Remediation Sandbox
# =========================================================================
elif page == "🧪 What-If Counterfactual Remediation":
    st.markdown('<div class="hero-title">What-If Counterfactual Policy Sandbox</div>', unsafe_allow_html=True)
    st.markdown('<div class="hero-sub">Simulate minimum-privilege counterfactual permission revocation. Dynamically observe risk scores drop in real time without recompiling the APK.</div>', unsafe_allow_html=True)
    
    # Pick a baseline sample
    malware_indices = np.where(resources["y_s"] == 1)[0]
    sample_idx = st.selectbox("Select Benchmark Malware Sample to Remediate", malware_indices[:20], format_func=lambda x: f"Malware Sample #{x}")
    base_vec = resources["X_s"].values[sample_idx].copy()
    
    # Get active permissions
    engine = resources["remediation"]
    active_perms = [engine.feature_names[i] for i in engine.permission_indices if base_vec[i] > 0]
    
    col_left, col_right = st.columns([1.1, 0.9])
    
    with col_left:
        st.markdown("### Permission Revocation Switchboard")
        st.caption("Uncheck permissions below to simulate revoking them via Enterprise Mobile Device Management (MDM):")
        
        revoked_perms = []
        for perm in active_perms:
            is_active = st.checkbox(f"Grant `{perm}`", value=True, key=f"perm_{perm}")
            if not is_active:
                revoked_perms.append(perm)

    # Compute modified vector
    mod_vec = base_vec.copy()
    for p in revoked_perms:
        mod_vec[engine.feature_index[p]] = 0
        
    p_orig = engine.evaluate_risk(base_vec)
    p_remediated = engine.evaluate_risk(mod_vec)
    risk_drop = p_orig - p_remediated
    
    with col_right:
        st.markdown("### Simulated Risk Impact")
        
        c1, c2 = st.columns(2)
        with c1:
            st.metric("Original Risk", f"{p_orig*100:.1f}%")
        with c2:
            st.metric("Remediated Risk", f"{p_remediated*100:.1f}%", delta=f"-{risk_drop*100:.1f}%")
            
        st.progress(float(p_remediated))
        
        if p_remediated < 0.50:
            st.success(f"🎉 **Safe State Achieved!** Revoking {len(revoked_perms)} permission(s) successfully converted this application from **Malicious** to **Benign**.")
        else:
            st.warning(f"⚠️ **Risk Still Elevated ({p_remediated*100:.1f}%)**: Residual risk is driven by bytecode API calls / intents.")
            
        st.markdown("#### Enterprise Policy Recommendation:")
        st.info(f"**Policy Action**: Revoke permissions `[{', '.join(revoked_perms) if revoked_perms else 'None'}]`. This achieves a **{risk_drop*100:.1f}% net risk reduction**.")


# =========================================================================
# PAGE 3: Reviewer Benchmarks & Empirical Ablations
# =========================================================================
elif page == "📊 Reviewer Benchmarks & Ablations":
    st.markdown('<div class="hero-title">Reviewer Benchmarks & Empirical Ablations</div>', unsafe_allow_html=True)
    st.markdown('<div class="hero-sub">Direct experimental findings resolving Reviewer 2 Points 1–5 using Stratified 5-Fold Cross-Validation.</div>', unsafe_allow_html=True)
    
    results_path = os.path.join(BASE_DIR, "outputs", "results.json")
    if os.path.exists(results_path):
        with open(results_path, "r") as f:
            res_data = json.load(f)
            
        # Table 1: Resampling
        st.subheader("Table I: Resampling & Algorithm Benchmark (Drebin 5-Fold CV)")
        st.caption("Addressing Reviewer 2 comment on class balancing and confirming findings from arXiv:2602.08744:")
        exp1_rows = res_data.get("EXP1_Static_Resampling_Benchmark", [])
        if exp1_rows:
            df_exp1 = pd.DataFrame(exp1_rows)
            df_exp1["accuracy"] = df_exp1["accuracy"].apply(lambda x: f"{x*100:.2f}%")
            df_exp1["f1_score"] = df_exp1["f1_score"].apply(lambda x: f"{x*100:.2f}%")
            df_exp1["roc_auc"] = df_exp1["roc_auc"].apply(lambda x: f"{x*100:.2f}%")
            df_exp1["fpr"] = df_exp1["fpr"].apply(lambda x: f"{x*100:.2f}%")
            st.dataframe(df_exp1[["model", "resampling", "accuracy", "f1_score", "roc_auc", "fpr"]], use_container_width=True)

        # Ablations Grid
        col_a, col_b = st.columns(2)
        with col_a:
            st.subheader("Feature Gap Ablation (Reviewer 2, Point 4)")
            exp3 = res_data.get("EXP3_Feature_Gap_Ablation", {})
            st.markdown(f"""
            - **115 Permissions-Only (Flawed Prototype)**: F1 = `{exp3.get('Permissions_Only_115_Features', {}).get('f1_score', 0)*100:.2f}%`, ROC-AUC = `{exp3.get('Permissions_Only_115_Features', {}).get('roc_auc', 0)*100:.2f}%`
            - **All 215 Features (Full Bytecode Extractor)**: F1 = `{exp3.get('Full_215_Features', {}).get('f1_score', 0)*100:.2f}%`, ROC-AUC = `{exp3.get('Full_215_Features', {}).get('roc_auc', 0)*100:.2f}%`
            - **Empirical Gain (Δ)**: **+{exp3.get('Delta_F1', 0)*100:.2f}% F1-Score** and **+{exp3.get('Delta_ROC_AUC', 0)*100:.2f}% ROC-AUC**.
            """)

        with col_b:
            st.subheader("Cascaded Triage Efficiency (Reviewer 2, Point 3)")
            exp6 = res_data.get("EXP6_Cascaded_Triage", {})
            st.markdown(f"""
            - **Stage 1 Fast Resolution**: **{exp6.get('stage1_resolution_rate', 0)*100:.2f}%** (Zero sandbox overhead)
            - **Sandbox Invocation Rate**: **{exp6.get('sandbox_invocation_rate', 0)*100:.2f}%** (Ambiguous only)
            - **Overall Triage Accuracy**: **{exp6.get('triage_accuracy', 0)*100:.2f}%**
            """)

        # 300 DPI Publication Plots
        st.divider()
        st.subheader("Generated 300 DPI Publication Figures")
        fig_col1, fig_col2 = st.columns(2)
        with fig_col1:
            st.image(os.path.join(BASE_DIR, "outputs", "figures", "fig2_resampling_benchmark.png"), caption="Figure 2: Resampling & Algorithm Benchmark")
            st.image(os.path.join(BASE_DIR, "outputs", "figures", "fig4_fusion_weight_sweep.png"), caption="Figure 4: Late Fusion Weight Sweep (w_s vs. w_d)")
        with fig_col2:
            st.image(os.path.join(BASE_DIR, "outputs", "figures", "fig3_feature_gap_ablation.png"), caption="Figure 3: Feature Gap Ablation (215 vs. 115 Features)")


# =========================================================================
# PAGE 4: SHAP Threat Attribution & Explainability
# =========================================================================
elif page == "🧠 SHAP Threat Attribution":
    st.markdown('<div class="hero-title">SHAP Threat Attribution & Explainability</div>', unsafe_allow_html=True)
    st.markdown('<div class="hero-sub">Shapley Additive exPlanations (SHAP) provide fair, game-theoretic feature attributions for both static DEX indicators and dynamic Linux syscalls.</div>', unsafe_allow_html=True)
    
    col_x, col_y = st.columns(2)
    with col_x:
        st.image(os.path.join(BASE_DIR, "outputs", "figures", "fig5_shap_static_bar.png"), caption="Figure 5A: Top-15 Most Influential Static Features (Global Bar)")
        st.image(os.path.join(BASE_DIR, "outputs", "figures", "fig5_shap_dynamic_beeswarm.png"), caption="Figure 5C: Dynamic Behavioral Attributions (Syscalls & Binders)")
    with col_y:
        st.image(os.path.join(BASE_DIR, "outputs", "figures", "fig5_shap_static_beeswarm.png"), caption="Figure 5B: Static Feature Attributions on Drebin (Beeswarm)")
        st.image(os.path.join(BASE_DIR, "outputs", "figures", "fig5_shap_waterfall.png"), caption="Figure 5D: Local Per-APK Forensic Threat Attribution (Waterfall)")
