"""
What-If Counterfactual Remediation Engine
Hybrid Android APK Intrusion Detection System (HIDS)

Implements the core paper novelty:
Simulates minimum-privilege counterfactual permission revocation.
Pairs with SHAP feature attributions to provide actionable enterprise policy remediation
without requiring binary APK recompilation.
"""

import os
import json
import logging
from typing import Dict, Any, List, Tuple
import numpy as np
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class WhatIfRemediationEngine:
    """
    Performs counterfactual what-if analysis on static APK feature vectors.
    """
    
    def __init__(self, model: Any, feature_names: List[str]):
        self.model = model
        self.feature_names = feature_names
        self.feature_index = {feat: idx for idx, feat in enumerate(feature_names)}
        
        # Categorize permissions
        self.permission_indices = [
            idx for idx, feat in enumerate(feature_names)
            if feat.isupper() and ("_" in feat or "PERMISSION" in feat) and not feat.startswith("L")
        ]
        self.permission_names = [self.feature_names[i] for i in self.permission_indices]
        logger.info("WhatIfRemediationEngine initialized with %d permissions", len(self.permission_names))

    def evaluate_risk(self, vector: np.ndarray) -> float:
        """
        Returns malware probability P(Malware | X).
        """
        if vector.ndim == 1:
            vector = vector.reshape(1, -1)
        prob = self.model.predict_proba(vector)[0, 1]
        return float(prob)

    def analyze_single_sample(
        self,
        vector: np.ndarray,
        target_threshold: float = 0.50
    ) -> Dict[str, Any]:
        """
        Analyzes a single APK vector, identifies active permissions,
        simulates individual and cumulative zeroing, and recommends minimal policy changes.
        """
        p_baseline = self.evaluate_risk(vector)
        if p_baseline < target_threshold:
            return {
                "initial_risk": p_baseline,
                "initial_verdict": "Benign",
                "remediation_needed": False,
                "message": "Sample is already classified as Benign. No remediation required."
            }

        # 1. Identify active permissions in this APK
        active_perm_indices = [
            idx for idx in self.permission_indices if vector[idx] > 0
        ]
        
        if not active_perm_indices:
            return {
                "initial_risk": p_baseline,
                "initial_verdict": "Malware",
                "remediation_needed": True,
                "remediation_possible": False,
                "message": "Risk driven by non-permission features (intents/APIs). Cannot remediate via permissions."
            }

        # 2. Individual sensitivity: zero out each active permission one by one
        individual_impacts = []
        for idx in active_perm_indices:
            feat_name = self.feature_names[idx]
            v_mod = vector.copy()
            v_mod[idx] = 0
            p_mod = self.evaluate_risk(v_mod)
            risk_reduction = p_baseline - p_mod
            individual_impacts.append({
                "feature": feat_name,
                "index": idx,
                "p_after_revocation": round(p_mod, 4),
                "risk_reduction": round(risk_reduction, 4)
            })

        # Sort permissions by risk reduction descending
        individual_impacts.sort(key=lambda x: x["risk_reduction"], reverse=True)

        # 3. Cumulative greedy revocation
        cumulative_steps = []
        v_current = vector.copy()
        current_risk = p_baseline
        remediated_permissions = []
        is_safe = False

        for item in individual_impacts:
            idx = item["index"]
            feat_name = item["feature"]
            v_current[idx] = 0
            current_risk = self.evaluate_risk(v_current)
            remediated_permissions.append(feat_name)
            
            cumulative_steps.append({
                "revoked_permission": feat_name,
                "remaining_risk": round(current_risk, 4),
                "total_drop": round(p_baseline - current_risk, 4)
            })
            
            if current_risk < target_threshold:
                is_safe = True
                break

        return {
            "remediation_needed": True,
            "remediation_possible": True,
            "initial_risk": round(p_baseline, 4),
            "final_risk": round(current_risk, 4),
            "total_risk_drop": round(p_baseline - current_risk, 4),
            "initial_verdict": "Malware",
            "final_verdict": "Benign" if is_safe else "Remediated (Still Elevated)",
            "safe_state_achieved": is_safe,
            "permissions_revoked_count": len(remediated_permissions),
            "recommended_revocations": remediated_permissions,
            "individual_sensitivity": individual_impacts[:10],
            "cumulative_trajectory": cumulative_steps
        }

    def batch_counterfactual_experiment(
        self,
        X_test: np.ndarray,
        y_test: np.ndarray,
        max_samples: int = 150
    ) -> Dict[str, Any]:
        """
        Runs counterfactual analysis across a test slice of true malware samples.
        Computes aggregate statistics for paper figures.
        """
        # Select malware samples only
        malware_indices = np.where(y_test == 1)[0]
        if len(malware_indices) > max_samples:
            np.random.seed(42)
            malware_indices = np.random.choice(malware_indices, size=max_samples, replace=False)

        drops = []
        safe_conversions = 0
        perms_revoked_counts = []
        
        for idx in malware_indices:
            res = self.analyze_single_sample(X_test[idx])
            if res.get("remediation_needed") and "total_risk_drop" in res:
                drops.append(res["total_risk_drop"])
                perms_revoked_counts.append(res["permissions_revoked_count"])
                if res.get("safe_state_achieved"):
                    safe_conversions += 1

        total_evaluated = len(drops)
        return {
            "total_malware_evaluated": total_evaluated,
            "benign_conversion_rate": float(safe_conversions / total_evaluated) if total_evaluated > 0 else 0.0,
            "average_risk_reduction": float(np.mean(drops)) if drops else 0.0,
            "median_risk_reduction": float(np.median(drops)) if drops else 0.0,
            "average_permissions_revoked": float(np.mean(perms_revoked_counts)) if perms_revoked_counts else 0.0
        }
