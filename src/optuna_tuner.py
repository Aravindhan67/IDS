"""
Bayesian Hyperparameter Optimization using Optuna for XGBoost
Hybrid Android APK Intrusion Detection System (HIDS)
"""

import os
import json
import logging
from typing import Dict, Any
import numpy as np
import optuna
from xgboost import XGBClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import f1_score, roc_auc_score

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.data_loader import load_drebin, load_dynamic

# Configure logging
optuna.logging.set_verbosity(optuna.logging.WARNING)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def tune_xgboost(
    X: np.ndarray,
    y: np.ndarray,
    model_name: str = "static",
    n_trials: int = 25,
    random_state: int = 42
) -> Dict[str, Any]:
    """
    Runs Bayesian Optimization (TPE) via Optuna to tune XGBoost.
    
    Args:
        X: Feature matrix.
        y: Binary target array.
        model_name: 'static' or 'dynamic'.
        n_trials: Number of Optuna trials.
        random_state: Seed.
        
    Returns:
        Dict with best hyperparameters.
    """
    logger.info("Starting Optuna tuning for [%s] model (%d samples, %d features, %d trials)...",
                model_name, X.shape[0], X.shape[1], n_trials)
    
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=random_state)
    
    def objective(trial: optuna.Trial) -> float:
        params = {
            "n_estimators": trial.suggest_int("n_estimators", 100, 350, step=50),
            "max_depth": trial.suggest_int("max_depth", 3, 8),
            "learning_rate": trial.suggest_float("learning_rate", 0.02, 0.2, log=True),
            "subsample": trial.suggest_float("subsample", 0.65, 1.0),
            "colsample_bytree": trial.suggest_float("colsample_bytree", 0.6, 1.0),
            "min_child_weight": trial.suggest_int("min_child_weight", 1, 6),
            "gamma": trial.suggest_float("gamma", 0.0, 3.0),
            "reg_alpha": trial.suggest_float("reg_alpha", 1e-3, 5.0, log=True),
            "reg_lambda": trial.suggest_float("reg_lambda", 1e-3, 5.0, log=True),
            "random_state": random_state,
            "n_jobs": -1,
            "eval_metric": "logloss",
        }
        
        scores = []
        for fold, (train_idx, val_idx) in enumerate(cv.split(X, y)):
            X_tr, y_tr = X[train_idx], y[train_idx]
            X_va, y_val = X[val_idx], y[val_idx]
            
            clf = XGBClassifier(**params)
            clf.fit(X_tr, y_tr)
            preds = clf.predict(X_va)
            f1 = f1_score(y_val, preds, zero_division=0)
            scores.append(f1)
            
            # Intermediate reporting for early pruning
            trial.report(f1, fold)
            if trial.should_prune():
                raise optuna.exceptions.TrialPruned()
                
        return float(np.mean(scores))

    sampler = optuna.samplers.TPESampler(seed=random_state)
    pruner = optuna.pruners.MedianPruner(n_warmup_steps=2)
    study = optuna.create_study(direction="maximize", sampler=sampler, pruner=pruner)
    study.optimize(objective, n_trials=n_trials, timeout=120)
    
    best_params = study.best_params
    best_score = study.best_value
    logger.info("Optuna tuning complete for [%s]. Best F1-Score: %.4f", model_name, best_score)
    logger.info("Optimal Parameters: %s", best_params)
    
    # Save parameters
    out_dir = "c:/ids/models"
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"best_params_{model_name}.json")
    with open(out_path, "w") as f:
        json.dump(best_params, f, indent=2)
    logger.info("Saved optimal parameters to %s", out_path)
    
    return best_params


def run_all_tuning(n_trials: int = 20):
    """
    Executes tuning for both Static and Dynamic models.
    """
    # 1. Static model tuning
    X_s, y_s, _ = load_drebin(drop_duplicates=True)
    tune_xgboost(X_s.values, y_s.values, model_name="static", n_trials=n_trials)
    
    # 2. Dynamic model tuning (subsampled if needed for speed, e.g. 5000 samples)
    X_d, y_d, _, _ = load_dynamic(drop_duplicates=True)
    # Fast tuning on representative 4000-sample stratified slice
    if len(X_d) > 4000:
        from sklearn.model_selection import train_test_split
        X_tune, _, y_tune, _ = train_test_split(
            X_d.values, y_d.values, train_size=4000, stratify=y_d.values, random_state=42
        )
    else:
        X_tune, y_tune = X_d.values, y_d.values
        
    tune_xgboost(X_tune, y_tune, model_name="dynamic", n_trials=n_trials)
    logger.info("All Optuna tuning jobs finished successfully!")


if __name__ == "__main__":
    run_all_tuning(n_trials=15)
