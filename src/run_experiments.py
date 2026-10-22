"""
Master Experimental Benchmark & Scientific Ablation Runner
AegisDroid Hybrid Android Intrusion Detection System (HIDS)

Executes Methodologically Honest Evaluations:
1. Resampling Benchmark: LR vs RF vs XGBoost across None vs SMOTE vs Cost-Sensitive Weighting.
   Stratified 5-Fold Cross-Validation with strict training-fold-only resampling.
2. Feature Gap Ablation: All 215 features vs 115 permissions-only.
3. Independent Dynamic Behavioral Benchmark: 5-Fold CV on CICMalDroid (Zero cross-dataset row-zipping).
4. Cascaded Triage Architecture Evaluation: Two-stage routing efficiency on synthetic control cohort.
5. What-If Counterfactual Remediation: Out-of-sample policy simulation on held-out test partitions.

Saves verified artifacts to project-relative outputs/results.json.
"""

import os
import sys
import json
import logging
from pathlib import Path
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

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.data_loader import (
    load_drebin, load_dynamic, get_stratified_splits,
    apply_training_resampling, compute_scale_pos_weight
)
from src.hybrid_fusion import CascadedTriagePipeline, late_fusion_weight_sweep
from src.remediation import WhatIfRemediationEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("AegisDroid.Experiments")


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_prob: np.ndarray) -> Dict[str, Any]:
    """
    Computes comprehensive evaluation metrics including confusion matrix and FPR.
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
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "roc_auc": round(float(roc_auc), 4),
        "pr_auc": round(float(pr_auc), 4),
        "fpr": round(float(fpr), 4),
        "confusion_matrix": {
            "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)
        },
        "support": {
            "pos": int(np.sum(y_true == 1)),
            "neg": int(np.sum(y_true == 0))
        }
    }


def run_benchmark():
    logger.info("Initializing Master Benchmark Execution...")
    results: Dict[str, Any] = {
        "metadata": {
            "system": "AegisDroid HIDS",
            "protocol": "LEAKAGE_FREE_5_FOLD_CV_INDEPENDENT_DATASETS",
            "static_dataset": "Drebin (215 features)",
            "dynamic_dataset": "CICMalDroid (470 features)",
            "pairing_policy": "NO_UNPAIRED_ROW_ZIPPING"
        }
    }

    # 1. Load best Optuna params from models/
    static_params_path = BASE_DIR / "models" / "best_params_static.json"
    dynamic_params_path = BASE_DIR / "models" / "best_params_dynamic.json"

    with open(static_params_path, "r", encoding="utf-8") as f:
        best_static_params = json.load(f)
    with open(dynamic_params_path, "r", encoding="utf-8") as f:
        best_dynamic_params = json.load(f)

    # 2. Ingest datasets with schema verification and deduplication
    X_static, y_static, feat_static = load_drebin(drop_duplicates=True)
    X_dynamic, y_dynamic, _, feat_dynamic = load_dynamic(drop_duplicates=True)

    # Slice dynamic for rapid cross-validation if large (representative 5000-sample slice)
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
    static_folds = get_stratified_splits(X_static.values, y_static.values, n_splits=5, random_state=42)

    models = {
        "Logistic_Regression": lambda **kwargs: LogisticRegression(max_iter=500, random_state=42, **kwargs),
        "Random_Forest": lambda **kwargs: RandomForestClassifier(n_estimators=150, max_depth=10, random_state=42, n_jobs=-1, **kwargs),
        "XGBoost_Optuna": lambda **kwargs: XGBClassifier(**best_static_params, random_state=42, n_jobs=-1, eval_metric="logloss", **kwargs)
    }

    resampling_configs = ["None", "SMOTE", "Cost_Sensitive"]
    exp1_records = []

    for m_name, m_builder in models.items():
        for resample in resampling_configs:
            fold_metrics = []
            for fold, (train_idx, test_idx) in enumerate(static_folds):
                X_tr, y_tr = X_static.values[train_idx], y_static.values[train_idx]
                X_te, y_te = X_static.values[test_idx], y_static.values[test_idx]

                # Apply resampling strictly on training partition
                if resample == "SMOTE":
                    X_tr_fit, y_tr_fit = apply_training_resampling(X_tr, y_tr, method="smote", random_state=42 + fold)
                    clf = m_builder()
                elif resample == "Cost_Sensitive":
                    if m_name == "XGBoost_Optuna":
                        spw = compute_scale_pos_weight(y_tr)
                        clf = m_builder(scale_pos_weight=spw)
                    else:
                        clf = m_builder(class_weight="balanced")
                    X_tr_fit, y_tr_fit = X_tr, y_tr
                else:
                    X_tr_fit, y_tr_fit = X_tr, y_tr
                    clf = m_builder()

                clf.fit(X_tr_fit, y_tr_fit)
                y_pred = clf.predict(X_te)
                y_prob = clf.predict_proba(X_te)[:, 1] if hasattr(clf, "predict_proba") else y_pred

                fold_metrics.append(compute_metrics(y_te, y_pred, y_prob))

            avg_metrics = {
                k: round(float(np.mean([m[k] for m in fold_metrics])), 4)
                for k in ["accuracy", "precision", "recall", "f1_score", "roc_auc", "pr_auc", "fpr"]
            }
            record = {
                "model": m_name,
                "resampling": resample,
                "dataset": "Drebin_Static",
                "samples": len(X_static),
                **avg_metrics
            }
            exp1_records.append(record)
            logger.info(
                "Static [%s | %s] -> F1: %.4f, ROC-AUC: %.4f, FPR: %.4f",
                m_name, resample, avg_metrics["f1_score"], avg_metrics["roc_auc"], avg_metrics["fpr"]
            )

    results["EXP1_Static_Resampling_Benchmark"] = exp1_records

    # =========================================================================
    # EXPERIMENT 2: Independent Dynamic Syscall/Binder Benchmark
    # =========================================================================
    logger.info("=== Running Experiment 2: Dynamic Syscall/Binder Benchmark (CICMalDroid) ===")
    dyn_folds = get_stratified_splits(X_dyn_eval, y_dyn_eval, n_splits=5, random_state=42)
    dyn_clf = XGBClassifier(**best_dynamic_params, random_state=42, n_jobs=-1, eval_metric="logloss")

    dyn_fold_metrics = []
    for fold, (train_idx, test_idx) in enumerate(dyn_folds):
        X_tr, y_tr = X_dyn_eval[train_idx], y_dyn_eval[train_idx]
        X_te, y_te = X_dyn_eval[test_idx], y_dyn_eval[test_idx]

        dyn_clf.fit(X_tr, y_tr)
        y_pred = dyn_clf.predict(X_te)
        y_prob = dyn_clf.predict_proba(X_te)[:, 1]
        dyn_fold_metrics.append(compute_metrics(y_te, y_pred, y_prob))

    dyn_avg = {
        k: round(float(np.mean([m[k] for m in dyn_fold_metrics])), 4)
        for k in ["accuracy", "precision", "recall", "f1_score", "roc_auc", "pr_auc", "fpr"]
    }
    dyn_avg["dataset"] = "CICMalDroid_Dynamic"
    dyn_avg["samples_evaluated"] = len(X_dyn_eval)
    results["EXP2_Dynamic_Benchmark"] = dyn_avg
    logger.info(
        "Dynamic XGBoost -> F1: %.4f, ROC-AUC: %.4f, FPR: %.4f",
        dyn_avg["f1_score"], dyn_avg["roc_auc"], dyn_avg["fpr"]
    )

    # =========================================================================
    # EXPERIMENT 3: Feature Gap Ablation (All 215 Features vs 115 Permissions-Only)
    # =========================================================================
    logger.info("=== Running Experiment 3: Feature Gap Ablation ===")
    perm_cols = [
        c for c in feat_static if c.isupper() and not c.startswith("L") and not c.startswith("/")
    ]
    logger.info("Permission columns count: %d / 215 (leaving %d bytecode features)", len(perm_cols), len(feat_static) - len(perm_cols))

    X_perm_only = X_static.copy()
    non_perm_cols = [c for c in feat_static if c not in perm_cols]
    X_perm_only[non_perm_cols] = 0  # Zero out 100 bytecode features

    perm_fold_metrics = []
    for fold, (train_idx, test_idx) in enumerate(static_folds):
        X_tr, y_tr = X_perm_only.values[train_idx], y_static.values[train_idx]
        X_te, y_te = X_perm_only.values[test_idx], y_static.values[test_idx]

        clf = XGBClassifier(**best_static_params, random_state=42, n_jobs=-1, eval_metric="logloss")
        clf.fit(X_tr, y_tr)
        y_pred = clf.predict(X_te)
        y_prob = clf.predict_proba(X_te)[:, 1]
        perm_fold_metrics.append(compute_metrics(y_te, y_pred, y_prob))

    perm_avg = {
        k: round(float(np.mean([m[k] for m in perm_fold_metrics])), 4)
        for k in ["accuracy", "precision", "recall", "f1_score", "roc_auc", "pr_auc", "fpr"]
    }

    full_215_res = [r for r in exp1_records if r["model"] == "XGBoost_Optuna" and r["resampling"] == "None"][0]

    gap_record = {
        "Full_215_Features": full_215_res,
        "Permissions_Only_115_Features": perm_avg,
        "Delta_F1": round(full_215_res["f1_score"] - perm_avg["f1_score"], 4),
        "Delta_ROC_AUC": round(full_215_res["roc_auc"] - perm_avg["roc_auc"], 4),
        "Delta_FPR": round(perm_avg["fpr"] - full_215_res["fpr"], 4)
    }
    results["EXP3_Feature_Gap_Ablation"] = gap_record
    logger.info(
        "Feature Gap Impact: Delta F1: +%.4f, Delta ROC-AUC: +%.4f with full bytecode extraction",
        gap_record["Delta_F1"], gap_record["Delta_ROC_AUC"]
    )

    # =========================================================================
    # EXPERIMENT 4: Cascaded Triage Pipeline Evaluation (Controlled Routing Control)
    # =========================================================================
    logger.info("=== Running Experiment 4: Cascaded Triage Architecture Evaluation ===")
    triage = CascadedTriagePipeline(tau_benign=0.35, tau_malware=0.75)

    # Evaluate static stage resolution rate on Drebin test predictions
    # Train static model on train fold, evaluate on held-out test fold
    last_train_idx, last_test_idx = static_folds[-1]
    static_model_eval = XGBClassifier(**best_static_params, random_state=42, n_jobs=-1, eval_metric="logloss")
    static_model_eval.fit(X_static.values[last_train_idx], y_static.values[last_train_idx])
    p_static_test = static_model_eval.predict_proba(X_static.values[last_test_idx])[:, 1]
    y_test_cohort = y_static.values[last_test_idx]

    # Measure routing without synthetic row-zipping:
    # Samples with P_s < 0.35 or P_s > 0.75 resolved at Stage 1
    stage1_resolved = np.sum((p_static_test < 0.35) | (p_static_test > 0.75))
    total_test = len(p_static_test)
    stage1_rate = float(stage1_resolved / total_test)
    sandbox_invoked_rate = float(1.0 - stage1_rate)

    # Correctness on Stage 1 resolved items
    stage1_mask = (p_static_test < 0.35) | (p_static_test > 0.75)
    stage1_preds = (p_static_test[stage1_mask] >= 0.5).astype(int)
    stage1_acc = float(np.mean(stage1_preds == y_test_cohort[stage1_mask])) if np.sum(stage1_mask) > 0 else 0.0

    triage_stats = {
        "total_test_samples": total_test,
        "stage1_resolution_rate": round(stage1_rate, 4),
        "sandbox_invocation_rate": round(sandbox_invoked_rate, 4),
        "stage1_accuracy": round(stage1_acc, 4),
        "operating_thresholds": {"tau_benign": 0.35, "tau_malware": 0.75},
        "note": "Evaluated strictly on held-out static test cohort. Avoids cross-dataset row pairing."
    }
    results["EXP4_Cascaded_Triage"] = triage_stats
    logger.info(
        "Cascaded Triage: %.2f%% resolved at Stage 1, %.2f%% Sandbox Invocation, Stage 1 Accuracy: %.4f",
        triage_stats["stage1_resolution_rate"] * 100,
        triage_stats["sandbox_invocation_rate"] * 100,
        triage_stats["stage1_accuracy"]
    )

    # =========================================================================
    # EXPERIMENT 5: What-If Counterfactual Remediation Evaluation (Held-Out Fold)
    # =========================================================================
    logger.info("=== Running Experiment 5: What-If Counterfactual Remediation (Held-Out Test Fold) ===")
    remediation_engine = WhatIfRemediationEngine(static_model_eval, feat_static)
    remediation_stats = remediation_engine.batch_counterfactual_experiment(
        X_static.values[last_test_idx], y_static.values[last_test_idx], max_samples=100
    )
    results["EXP5_WhatIf_Remediation"] = remediation_stats
    logger.info(
        "What-If Remediation: Benign Conversion Rate: %.2f%%, Avg Risk Drop: %.4f, Avg Perms Revoked: %.2f",
        remediation_stats["benign_conversion_rate"] * 100,
        remediation_stats["average_risk_reduction"],
        remediation_stats.get("average_permissions_revoked", 0)
    )

    # Save to outputs/results.json
    out_json_path = BASE_DIR / "outputs" / "results.json"
    with open(out_json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    logger.info("Master benchmark completed successfully! Results written to %s", out_json_path)
    return results


if __name__ == "__main__":
    run_benchmark()
