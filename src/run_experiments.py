"""
Master Experimental Benchmark & Ablation Runner
Hybrid Android APK Intrusion Detection System (HIDS)

Executes:
1. Resampling Benchmark: LR vs RF vs XGBoost across None vs SMOTE vs scale_pos_weight
2. Feature Gap Ablation: All 215 features vs 115 permissions-only
3. Dynamic Branch Ablation: Flawed Mock vs Calibrated Dynamic
4. Late Fusion Weight Sweep: w_s in [0.0, 1.0]
5. Cascaded Triage Evaluation: Sandbox offloading rate & accuracy
6. What-If Counterfactual Remediation: Risk drop quantification
Saves results to c:/ids/outputs/results.json
"""

import os
import sys
import json
import logging
from typing import Dict, Any, List
import numpy as np
import pandas as pd

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, precision_recall_curve, auc, confusion_matrix
)

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.data_loader import (
    load_drebin, load_dynamic, get_stratified_splits,
    apply_training_resampling, compute_scale_pos_weight
)
from src.hybrid_fusion import CascadedTriagePipeline, late_fusion_weight_sweep
from src.remediation import WhatIfRemediationEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_prob: np.ndarray) -> Dict[str, float]:
    """
    Computes comprehensive evaluation metrics.
    """
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    
    try:
        roc_auc = roc_auc_score(y_true, y_prob)
    except Exception:
        roc_auc = 0.5
        
    try:
        p_curve, r_curve, _ = precision_recall_curve(y_true, y_prob)
        pr_auc = auc(r_curve, p_curve)
    except Exception:
        pr_auc = 0.5
        
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    
    return {
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1_score": float(f1),
        "roc_auc": float(roc_auc),
        "pr_auc": float(pr_auc),
        "fpr": float(fpr)
    }


def run_benchmark():
    logger.info("Initializing Master Benchmark Execution...")
    results: Dict[str, Any] = {}
    
    # 1. Load best Optuna params
    static_params_path = "c:/ids/models/best_params_static.json"
    dynamic_params_path = "c:/ids/models/best_params_dynamic.json"
    
    with open(static_params_path, "r") as f:
        best_static_params = json.load(f)
    with open(dynamic_params_path, "r") as f:
        best_dynamic_params = json.load(f)
        
    # 2. Ingest datasets
    X_static, y_static, feat_static = load_drebin(drop_duplicates=True)
    X_dynamic, y_dynamic, _, feat_dynamic = load_dynamic(drop_duplicates=True)
    
    # Slice dynamic for balanced runtime if large (e.g. 5000 samples for cross-val benchmark)
    if len(X_dynamic) > 5000:
        from sklearn.model_selection import train_test_split
        X_dyn_eval, _, y_dyn_eval, _ = train_test_split(
            X_dynamic.values, y_dynamic.values, train_size=5000,
            stratify=y_dynamic.values, random_state=42
        )
    else:
        X_dyn_eval, y_dyn_eval = X_dynamic.values, y_dynamic.values

    # =========================================================================
    # EXPERIMENT 1: Resampling Benchmark on Static (Drebin)
    # =========================================================================
    logger.info("=== Running Experiment 1: Resampling Benchmark on Static (Drebin) ===")
    static_folds = get_stratified_splits(X_static.values, y_static.values, n_splits=5)
    
    models = {
        "Logistic_Regression": lambda **kwargs: LogisticRegression(max_iter=500, random_state=42, **kwargs),
        "Random_Forest": lambda **kwargs: RandomForestClassifier(n_estimators=150, max_depth=10, random_state=42, n_jobs=-1, **kwargs),
        "XGBoost_Optuna": lambda **kwargs: XGBClassifier(**best_static_params, random_state=42, n_jobs=-1, eval_metric="logloss", **kwargs)
    }
    
    resampling_configs = ["None", "SMOTE", "scale_pos_weight"]
    exp1_records = []
    
    for m_name, m_builder in models.items():
        for resample in resampling_configs:
            # scale_pos_weight is specific to XGBoost
            if resample == "scale_pos_weight" and m_name != "XGBoost_Optuna":
                continue
                
            fold_metrics = []
            for fold, (train_idx, test_idx) in enumerate(static_folds):
                X_tr, y_tr = X_static.values[train_idx], y_static.values[train_idx]
                X_te, y_te = X_static.values[test_idx], y_static.values[test_idx]
                
                # Apply resampling strictly on training partition
                if resample == "SMOTE":
                    X_tr_fit, y_tr_fit = apply_training_resampling(X_tr, y_tr, method="smote")
                    clf = m_builder()
                elif resample == "scale_pos_weight":
                    spw = compute_scale_pos_weight(y_tr)
                    clf = m_builder(scale_pos_weight=spw)
                    X_tr_fit, y_tr_fit = X_tr, y_tr
                else:
                    X_tr_fit, y_tr_fit = X_tr, y_tr
                    clf = m_builder()
                    
                clf.fit(X_tr_fit, y_tr_fit)
                y_pred = clf.predict(X_te)
                y_prob = clf.predict_proba(X_te)[:, 1] if hasattr(clf, "predict_proba") else y_pred
                
                fold_metrics.append(compute_metrics(y_te, y_pred, y_prob))
                
            avg_metrics = {k: float(np.mean([m[k] for m in fold_metrics])) for k in fold_metrics[0]}
            record = {
                "model": m_name,
                "resampling": resample,
                "dataset": "Drebin_Static",
                **avg_metrics
            }
            exp1_records.append(record)
            logger.info("Static [%s | %s] -> F1: %.4f, ROC-AUC: %.4f, FPR: %.4f",
                        m_name, resample, avg_metrics["f1_score"], avg_metrics["roc_auc"], avg_metrics["fpr"])

    results["EXP1_Static_Resampling_Benchmark"] = exp1_records

    # =========================================================================
    # EXPERIMENT 2: Dynamic Syscall/Binder Benchmark
    # =========================================================================
    logger.info("=== Running Experiment 2: Dynamic Syscall/Binder Benchmark ===")
    dyn_folds = get_stratified_splits(X_dyn_eval, y_dyn_eval, n_splits=5)
    dyn_clf = XGBClassifier(**best_dynamic_params, random_state=42, n_jobs=-1, eval_metric="logloss")
    
    dyn_fold_metrics = []
    for fold, (train_idx, test_idx) in enumerate(dyn_folds):
        X_tr, y_tr = X_dyn_eval[train_idx], y_dyn_eval[train_idx]
        X_te, y_te = X_dyn_eval[test_idx], y_dyn_eval[test_idx]
        
        dyn_clf.fit(X_tr, y_tr)
        y_pred = dyn_clf.predict(X_te)
        y_prob = dyn_clf.predict_proba(X_te)[:, 1]
        dyn_fold_metrics.append(compute_metrics(y_te, y_pred, y_prob))
        
    dyn_avg = {k: float(np.mean([m[k] for m in dyn_fold_metrics])) for k in dyn_fold_metrics[0]}
    results["EXP2_Dynamic_Benchmark"] = dyn_avg
    logger.info("Dynamic XGBoost -> F1: %.4f, ROC-AUC: %.4f, FPR: %.4f",
                dyn_avg["f1_score"], dyn_avg["roc_auc"], dyn_avg["fpr"])

    # =========================================================================
    # EXPERIMENT 3: Feature Gap Ablation (All 215 Features vs 115 Permissions-Only)
    # (Resolves Reviewer 2 Point 4)
    # =========================================================================
    logger.info("=== Running Experiment 3: Feature Gap Ablation ===")
    # Identify permission columns
    perm_cols = [
        c for c in feat_static if c.isupper() and ("_" in c or "PERMISSION" in c) and not c.startswith("L")
    ]
    logger.info("Permission columns count: %d / 215 (leaving %d bytecode features)", 
                len(perm_cols), len(feat_static) - len(perm_cols))
    
    X_perm_only = X_static.copy()
    non_perm_cols = [c for c in feat_static if c not in perm_cols]
    X_perm_only[non_perm_cols] = 0  # Zero out 46.5% bytecode features
    
    # 5-fold CV on permissions only
    perm_fold_metrics = []
    for fold, (train_idx, test_idx) in enumerate(static_folds):
        X_tr, y_tr = X_perm_only.values[train_idx], y_static.values[train_idx]
        X_te, y_te = X_perm_only.values[test_idx], y_static.values[test_idx]
        
        clf = XGBClassifier(**best_static_params, random_state=42, n_jobs=-1, eval_metric="logloss")
        clf.fit(X_tr, y_tr)
        y_pred = clf.predict(X_te)
        y_prob = clf.predict_proba(X_te)[:, 1]
        perm_fold_metrics.append(compute_metrics(y_te, y_pred, y_prob))
        
    perm_avg = {k: float(np.mean([m[k] for m in perm_fold_metrics])) for k in perm_fold_metrics[0]}
    
    # Find full 215 feature XGBoost baseline from EXP1
    full_215_res = [r for r in exp1_records if r["model"] == "XGBoost_Optuna" and r["resampling"] == "None"][0]
    
    gap_record = {
        "Full_215_Features": full_215_res,
        "Permissions_Only_115_Features": perm_avg,
        "Delta_F1": round(full_215_res["f1_score"] - perm_avg["f1_score"], 4),
        "Delta_ROC_AUC": round(full_215_res["roc_auc"] - perm_avg["roc_auc"], 4),
        "Delta_FPR": round(perm_avg["fpr"] - full_215_res["fpr"], 4)
    }
    results["EXP3_Feature_Gap_Ablation"] = gap_record
    logger.info("Feature Gap Impact: Delta F1: +%.4f, Delta ROC-AUC: +%.4f with full bytecode extraction",
                gap_record["Delta_F1"], gap_record["Delta_ROC_AUC"])

    # =========================================================================
    # EXPERIMENT 4: Dynamic Mock Bug Ablation
    # (Resolves Reviewer 2 Points 1 & 5)
    # =========================================================================
    logger.info("=== Running Experiment 4: Dynamic Mock Bug Ablation ===")
    # Evaluate hybrid score when dynamic branch is flawed mock (P_d = 0.5) vs real P_d
    p_static_test = y_prob  # test predictions from last fold
    p_mock_dyn = np.full_like(p_static_test, 0.5)  # constant mock
    p_real_dyn = dyn_clf.predict_proba(X_dyn_eval[:len(p_static_test)])[:, 1]
    
    # Late fusion 0.5*P_s + 0.5*P_d
    p_hybrid_mock = 0.5 * p_static_test + 0.5 * p_mock_dyn
    p_hybrid_real = 0.5 * p_static_test + 0.5 * p_real_dyn
    
    mock_metrics = compute_metrics(y_te, (p_hybrid_mock >= 0.5).astype(int), p_hybrid_mock)
    real_metrics = compute_metrics(y_te, (p_hybrid_real >= 0.5).astype(int), p_hybrid_real)
    
    results["EXP4_Dynamic_Mock_Ablation"] = {
        "Flawed_Mock_Constant_Pd": mock_metrics,
        "Calibrated_Dynamic_Branch": real_metrics,
        "F1_Improvement": round(real_metrics["f1_score"] - mock_metrics["f1_score"], 4)
    }

    # =========================================================================
    # EXPERIMENT 5: Late Fusion Weight Sweep (w_s in [0.0, 1.0])
    # =========================================================================
    logger.info("=== Running Experiment 5: Late Fusion Weight Sweep ===")
    sweep_results = late_fusion_weight_sweep(p_static_test, p_real_dyn, y_te, steps=11)
    results["EXP5_Fusion_Weight_Sweep"] = sweep_results

    # =========================================================================
    # EXPERIMENT 6: Cascaded Triage Pipeline Evaluation
    # =========================================================================
    logger.info("=== Running Experiment 6: Cascaded Triage Pipeline Evaluation ===")
    triage = CascadedTriagePipeline(tau_benign=0.35, tau_malware=0.75)
    triage_stats = triage.simulate_triage_efficiency(p_static_test, p_real_dyn, y_te)
    results["EXP6_Cascaded_Triage"] = triage_stats
    logger.info("Cascaded Triage: %.2f%% resolved at Stage 1, %.2f%% Sandbox Invocation, Accuracy: %.4f",
                triage_stats["stage1_resolution_rate"] * 100,
                triage_stats["sandbox_invocation_rate"] * 100,
                triage_stats["triage_accuracy"])

    # =========================================================================
    # EXPERIMENT 7: What-If Counterfactual Remediation Evaluation
    # (Resolves Novelty requirement)
    # =========================================================================
    logger.info("=== Running Experiment 7: What-If Counterfactual Remediation ===")
    static_model = XGBClassifier(**best_static_params, random_state=42, n_jobs=-1, eval_metric="logloss")
    static_model.fit(X_static.values, y_static.values)
    
    remediation_engine = WhatIfRemediationEngine(static_model, feat_static)
    remediation_stats = remediation_engine.batch_counterfactual_experiment(
        X_static.values[test_idx], y_static.values[test_idx], max_samples=100
    )
    results["EXP7_WhatIf_Remediation"] = remediation_stats
    logger.info("What-If Remediation: Benign Conversion Rate: %.2f%%, Avg Risk Drop: %.4f",
                remediation_stats["benign_conversion_rate"] * 100,
                remediation_stats["average_risk_reduction"])

    # =========================================================================
    # Persist Results JSON
    # =========================================================================
    out_json_path = "c:/ids/outputs/results.json"
    with open(out_json_path, "w") as f:
        json.dump(results, f, indent=2)
    logger.info("Master benchmark completed! Full results saved to %s", out_json_path)
    
    return results


if __name__ == "__main__":
    run_benchmark()
