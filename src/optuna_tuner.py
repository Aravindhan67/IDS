"""
Bayesian Hyperparameter Optimization using Optuna for XGBoost
AegisDroid Hybrid Android Intrusion Detection System (HIDS)

Strict Leakage-Free Protocol:
1. Partitions dataset into an 80% Training Partition and a 20% Held-Out Test Partition.
2. Runs Bayesian Optimization (TPE) via Optuna strictly on the Training Partition using Stratified 5-Fold CV.
3. Fits the final model with optimal parameters on the Training Partition.
4. Evaluates once on the untouched Held-Out Test Partition to compute unbiased test performance.
5. Saves validated hyperparameters and test evaluation records to project-relative models/ directory.
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Tuple
import numpy as np
import optuna
from xgboost import XGBClassifier
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.metrics import f1_score, roc_auc_score, accuracy_score, precision_score, recall_score

BASE_DIR = Path(__file__).resolve().parent.parent

optuna.logging.set_verbosity(optuna.logging.WARNING)
logger = logging.getLogger("AegisDroid.OptunaTuner")


def tune_xgboost_leakage_free(
    X: np.ndarray,
    y: np.ndarray,
    model_name: str = "static",
    n_trials: int = 25,
    random_state: int = 42,
    test_size: float = 0.20
) -> Tuple[Dict[str, Any], Dict[str, float]]:
    """
    Executes leak-free Bayesian Hyperparameter Optimization with strict held-out test isolation.

    Args:
        X: Full feature matrix.
        y: Binary target array.
        model_name: 'static' or 'dynamic'.
        n_trials: Number of Optuna trials.
        random_state: Random seed for reproducibility.
        test_size: Proportion for held-out test partition.

    Returns:
        Tuple[Dict[str, Any], Dict[str, float]]: (Best Hyperparameters, Held-Out Test Metrics)
    """
    logger.info(
        "Starting Leakage-Free Optuna Tuning for [%s] (Total samples: %d, Features: %d)...",
        model_name, X.shape[0], X.shape[1]
    )

    # 1. Isolate held-out test partition BEFORE any tuning or model selection
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=random_state
    )

    logger.info(
        "Dataset partitioned: Train=%d samples, Held-Out Test=%d samples (Class balance: %.2f%% pos)",
        len(X_train), len(X_test), float(np.mean(y_train) * 100)
    )

    # 2. Stratified 5-Fold Cross-Validation strictly inside Training Partition
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=random_state)

    def objective(trial: optuna.Trial) -> float:
        params = {
            "n_estimators": trial.suggest_int("n_estimators", 100, 300, step=50),
            "max_depth": trial.suggest_int("max_depth", 3, 7),
            "learning_rate": trial.suggest_float("learning_rate", 0.03, 0.2, log=True),
            "subsample": trial.suggest_float("subsample", 0.7, 1.0),
            "colsample_bytree": trial.suggest_float("colsample_bytree", 0.7, 1.0),
            "min_child_weight": trial.suggest_int("min_child_weight", 1, 5),
            "gamma": trial.suggest_float("gamma", 0.0, 2.0),
            "reg_alpha": trial.suggest_float("reg_alpha", 1e-3, 3.0, log=True),
            "reg_lambda": trial.suggest_float("reg_lambda", 1e-3, 3.0, log=True),
            "random_state": random_state,
            "n_jobs": -1,
            "eval_metric": "logloss",
        }

        scores = []
        for fold, (t_idx, v_idx) in enumerate(cv.split(X_train, y_train)):
            X_tr, y_tr = X_train[t_idx], y_train[t_idx]
            X_va, y_va = X_train[v_idx], y_train[v_idx]

            clf = XGBClassifier(**params)
            clf.fit(X_tr, y_tr)
            preds = clf.predict(X_va)
            f1 = f1_score(y_va, preds, zero_division=0)
            scores.append(f1)

            trial.report(f1, fold)
            if trial.should_prune():
                raise optuna.exceptions.TrialPruned()

        return float(np.mean(scores))

    sampler = optuna.samplers.TPESampler(seed=random_state)
    pruner = optuna.pruners.MedianPruner(n_warmup_steps=2)
    study = optuna.create_study(direction="maximize", sampler=sampler, pruner=pruner)
    study.optimize(objective, n_trials=n_trials, timeout=120)

    best_params = study.best_params
    best_cv_f1 = study.best_value
    logger.info("Optuna search completed for [%s]. Best Training-CV F1: %.4f", model_name, best_cv_f1)

    # 3. Fit final model on entire training partition
    final_clf = XGBClassifier(**best_params, random_state=random_state, n_jobs=-1, eval_metric="logloss")
    final_clf.fit(X_train, y_train)

    # 4. Evaluate ONCE on untouched held-out test partition
    test_preds = final_clf.predict(X_test)
    test_probs = final_clf.predict_proba(X_test)[:, 1]

    test_metrics = {
        "held_out_accuracy": float(accuracy_score(y_test, test_preds)),
        "held_out_precision": float(precision_score(y_test, test_preds, zero_division=0)),
        "held_out_recall": float(recall_score(y_test, test_preds, zero_division=0)),
        "held_out_f1": float(f1_score(y_test, test_preds, zero_division=0)),
        "held_out_roc_auc": float(roc_auc_score(y_test, test_probs)),
        "best_cv_f1": float(best_cv_f1),
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "evaluation_protocol": "LEAKAGE_FREE_HELD_OUT_TEST_EVALUATION"
    }

    logger.info(
        "Held-Out Test Metrics for [%s]: F1=%.4f, ROC-AUC=%.4f, Acc=%.4f",
        model_name, test_metrics["held_out_f1"], test_metrics["held_out_roc_auc"], test_metrics["held_out_accuracy"]
    )

    # 5. Save optimal parameters to models/
    out_dir = BASE_DIR / "models"
    os.makedirs(out_dir, exist_ok=True)
    out_param_path = out_dir / f"best_params_{model_name}.json"
    with open(out_param_path, "w", encoding="utf-8") as f:
        json.dump(best_params, f, indent=2)

    logger.info("Saved verified optimal parameters to %s", out_param_path)
    return best_params, test_metrics


def run_all_tuning(n_trials: int = 15):
    """
    Executes leak-free tuning for both Static (Drebin) and Dynamic (CICMalDroid) models.
    """
    from src.data_loader import load_drebin, load_dynamic

    # 1. Static Model Tuning
    X_s, y_s, _ = load_drebin(drop_duplicates=True)
    tune_xgboost_leakage_free(X_s.values, y_s.values, model_name="static", n_trials=n_trials)

    # 2. Dynamic Model Tuning (representative stratified slice for rapid convergence)
    X_d, y_d, _, _ = load_dynamic(drop_duplicates=True)
    if len(X_d) > 4000:
        X_tune, _, y_tune, _ = train_test_split(
            X_d.values, y_d.values, train_size=4000, stratify=y_d.values, random_state=42
        )
    else:
        X_tune, y_tune = X_d.values, y_d.values

    tune_xgboost_leakage_free(X_tune, y_tune, model_name="dynamic", n_trials=n_trials)
    logger.info("All Optuna tuning runs finished successfully!")


if __name__ == "__main__":
    run_all_tuning(n_trials=10)
