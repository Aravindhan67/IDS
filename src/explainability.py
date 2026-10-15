"""
Explainable AI (XAI) & Threat Attribution Engine using SHAP
Hybrid Android APK Intrusion Detection System (HIDS)

Generates:
- Global SHAP beeswarm summary plots
- Feature importance rankings
- Per-APK local waterfall threat attribution plots
- 300 DPI publication figures
"""

import os
import sys
import json
import logging
from typing import Dict, Any, List, Optional
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import shap
from xgboost import XGBClassifier

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.data_loader import load_drebin, load_dynamic

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class SHAPExplainerEngine:
    """
    SHAP TreeExplainer wrapper for Static and Dynamic XGBoost models.
    """
    
    def __init__(self, fig_dir: str = "c:/ids/outputs/figures"):
        self.fig_dir = fig_dir
        os.makedirs(self.fig_dir, exist_ok=True)
        
    def generate_all_explanations(self, max_samples: int = 500):
        logger.info("Initializing SHAP Explainability Engine...")
        
        # 1. Load data & models
        X_s, y_s, feat_s = load_drebin(drop_duplicates=True)
        with open("c:/ids/models/best_params_static.json", "r") as f:
            static_params = json.load(f)
            
        static_model = XGBClassifier(**static_params, random_state=42, n_jobs=-1, eval_metric="logloss")
        static_model.fit(X_s.values, y_s.values)
        
        # Select background and evaluation samples
        np.random.seed(42)
        sample_indices = np.random.choice(len(X_s), size=min(max_samples, len(X_s)), replace=False)
        X_sample = X_s.iloc[sample_indices]
        
        logger.info("Computing TreeExplainer values for Static Model (%d samples)...", len(X_sample))
        explainer_static = shap.TreeExplainer(static_model)
        shap_values_static = explainer_static(X_sample)
        
        # --- Plot 1: Static SHAP Summary Beeswarm (300 DPI) ---
        plt.figure(figsize=(10, 8), dpi=300)
        shap.summary_plot(shap_values_static.values, X_sample, feature_names=feat_s, max_display=15, show=False)
        plt.title("Static Model SHAP Feature Attributions (Drebin)", fontsize=13, pad=15)
        plt.tight_layout()
        out_beeswarm = os.path.join(self.fig_dir, "fig5_shap_static_beeswarm.png")
        plt.savefig(out_beeswarm, dpi=300, bbox_inches="tight")
        plt.close()
        logger.info("Saved static SHAP beeswarm to %s", out_beeswarm)
        
        # --- Plot 2: Static SHAP Bar Importance (300 DPI) ---
        plt.figure(figsize=(9, 6), dpi=300)
        shap.summary_plot(shap_values_static.values, X_sample, feature_names=feat_s, plot_type="bar", max_display=15, show=False)
        plt.title("Top-15 Most Influential Static Features", fontsize=13, pad=15)
        plt.tight_layout()
        out_bar = os.path.join(self.fig_dir, "fig5_shap_static_bar.png")
        plt.savefig(out_bar, dpi=300, bbox_inches="tight")
        plt.close()
        logger.info("Saved static SHAP bar plot to %s", out_bar)
        
        # --- Plot 3: Dynamic Model SHAP ---
        logger.info("Computing TreeExplainer values for Dynamic Model...")
        X_d, y_d, _, feat_d = load_dynamic(drop_duplicates=True)
        with open("c:/ids/models/best_params_dynamic.json", "r") as f:
            dynamic_params = json.load(f)
            
        dyn_indices = np.random.choice(len(X_d), size=min(max_samples, len(X_d)), replace=False)
        X_d_sample = X_d.iloc[dyn_indices]
        
        dyn_model = XGBClassifier(**dynamic_params, random_state=42, n_jobs=-1, eval_metric="logloss")
        dyn_model.fit(X_d.values, y_d.values)
        
        explainer_dyn = shap.TreeExplainer(dyn_model)
        shap_values_dyn = explainer_dyn(X_d_sample)
        
        plt.figure(figsize=(10, 8), dpi=300)
        shap.summary_plot(shap_values_dyn.values, X_d_sample, feature_names=feat_d, max_display=15, show=False)
        plt.title("Dynamic Behavioral SHAP Attributions (Syscalls & Binders)", fontsize=13, pad=15)
        plt.tight_layout()
        out_dyn = os.path.join(self.fig_dir, "fig5_shap_dynamic_beeswarm.png")
        plt.savefig(out_dyn, dpi=300, bbox_inches="tight")
        plt.close()
        logger.info("Saved dynamic SHAP beeswarm to %s", out_dyn)
        
        # --- Plot 4: Local Waterfall for Single High-Risk APK ---
        # Find a true positive malware sample
        malware_indices = np.where(y_s.iloc[sample_indices] == 1)[0]
        if len(malware_indices) > 0:
            target_idx = malware_indices[0]
            plt.figure(figsize=(9, 6), dpi=300)
            shap.plots.waterfall(shap_values_static[target_idx], max_display=10, show=False)
            plt.title("Local SHAP Threat Attribution for Malicious APK", fontsize=12, pad=15)
            plt.tight_layout()
            out_waterfall = os.path.join(self.fig_dir, "fig5_shap_waterfall.png")
            plt.savefig(out_waterfall, dpi=300, bbox_inches="tight")
            plt.close()
            logger.info("Saved local SHAP waterfall plot to %s", out_waterfall)
            
        logger.info("All SHAP explainability artifacts generated successfully!")


if __name__ == "__main__":
    engine = SHAPExplainerEngine()
    engine.generate_all_explanations(max_samples=250)
