"""
Hybrid Fusion Engine & Cascaded Triage Pipeline
Hybrid Android APK Intrusion Detection System (HIDS)

Resolves:
- Reviewer 2 Point 3 (Unpaired dataset evaluation via Cascaded Triage Architecture)
- Reviewer 2 Point 2 (Decoupled signature pre-filter)
"""

import os
import json
import logging
from typing import Dict, Any, Tuple, Optional, List, Set
import numpy as np

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class SignaturePreFilter:
    """
    Deterministic Signature Pre-Filter (VirusTotal API v3 & Hash Matching).
    Decoupled strictly from ML benchmarks (Reviewer 2 Point 2).
    """
    
    def __init__(self, api_key: Optional[str] = None):
        from src.virustotal_client import VirusTotalSignatureAnalyzer
        self.vt_analyzer = VirusTotalSignatureAnalyzer(api_key=api_key)
        self.local_cache: Set[str] = {
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "44d88612fea8a8f36de82e1278abb02f"
        }
        
    def check_file(self, filepath: str) -> Dict[str, Any]:
        """
        Computes hashes and queries VirusTotal threat feed.
        """
        return self.vt_analyzer.analyze_apk_file(filepath)

    def check_signature(self, file_hash: str) -> Tuple[bool, str]:
        """
        Queries VirusTotal API v3 and local cache.
        """
        clean_hash = file_hash.lower().strip()
        if clean_hash in self.local_cache:
            return True, "Known Malicious Signature (Local Threat Cache)"
            
        vt_res = self.vt_analyzer.query_hash(clean_hash)
        if vt_res.get("signature_detected"):
            ratio = vt_res.get("detection_ratio", "N/A")
            label = vt_res.get("threat_label", "Malware")
            return True, f"VirusTotal Threat Feed Match ({ratio} engines: {label})"
            
        return False, "No Signature Match (Proceed to ML Pipeline)"


class CascadedTriagePipeline:
    """
    Two-Stage Cascaded Triage Pipeline:
    - Stage 1 (Fast Static Filter): Millisecond inference via 215-D static features.
      Resolves clear benign (P_s < tau_1) and clear malware (P_s > tau_2).
    - Stage 2 (Dynamic Sandbox): Triggered only for borderline / ambiguous samples (tau_1 <= P_s <= tau_2).
    """
    
    def __init__(
        self,
        tau_benign: float = 0.35,
        tau_malware: float = 0.75,
        default_static_weight: float = 0.55
    ):
        self.tau_benign = tau_benign
        self.tau_malware = tau_malware
        self.w_s = default_static_weight
        self.w_d = 1.0 - default_static_weight
        
    def evaluate_sample(
        self,
        p_static: float,
        p_dynamic: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Evaluates a single sample through the cascaded triage pipeline.
        
        Args:
            p_static: Probability of malware from static model (0.0 to 1.0).
            p_dynamic: Probability of malware from dynamic model (optional).
            
        Returns:
            Dict containing triage verdict, stage resolved, and hybrid confidence.
        """
        # Stage 1: Quick Static Gatekeeper
        if p_static < self.tau_benign:
            return {
                "verdict": "Benign",
                "label": 0,
                "confidence": float(1.0 - p_static),
                "stage_resolved": "Stage 1 (Static)",
                "sandbox_invoked": False,
                "p_static": float(p_static),
                "p_dynamic": None,
                "p_hybrid": float(p_static)
            }
        elif p_static > self.tau_malware:
            return {
                "verdict": "Malware",
                "label": 1,
                "confidence": float(p_static),
                "stage_resolved": "Stage 1 (Static)",
                "sandbox_invoked": False,
                "p_static": float(p_static),
                "p_dynamic": None,
                "p_hybrid": float(p_static)
            }
            
        # Stage 2: Ambiguous Sample -> Invoke Dynamic Sandbox
        if p_dynamic is None:
            # Requires dynamic execution
            return {
                "verdict": "Ambiguous (Requires Sandbox)",
                "label": -1,
                "confidence": 0.5,
                "stage_resolved": "Pending Stage 2",
                "sandbox_invoked": True,
                "p_static": float(p_static),
                "p_dynamic": None,
                "p_hybrid": None
            }
            
        p_hybrid = (self.w_s * p_static) + (self.w_d * p_dynamic)
        label = 1 if p_hybrid >= 0.5 else 0
        verdict = "Malware" if label == 1 else "Benign"
        conf = p_hybrid if label == 1 else (1.0 - p_hybrid)
        
        return {
            "verdict": verdict,
            "label": label,
            "confidence": float(conf),
            "stage_resolved": "Stage 2 (Dynamic Fusion)",
            "sandbox_invoked": True,
            "p_static": float(p_static),
            "p_dynamic": float(p_dynamic),
            "p_hybrid": float(p_hybrid)
        }

    def simulate_triage_efficiency(
        self,
        p_static_array: np.ndarray,
        p_dynamic_array: np.ndarray,
        ground_truth: np.ndarray
    ) -> Dict[str, float]:
        """
        Measures the sandbox offloading rate and accuracy across a batch.
        """
        n_samples = len(p_static_array)
        resolved_stage1 = 0
        correct_predictions = 0
        
        for i in range(n_samples):
            ps = p_static_array[i]
            pd = p_dynamic_array[i]
            gt = ground_truth[i]
            
            res = self.evaluate_sample(ps, pd)
            if not res["sandbox_invoked"]:
                resolved_stage1 += 1
                
            if res["label"] == gt:
                correct_predictions += 1
                
        return {
            "total_samples": n_samples,
            "stage1_resolution_rate": float(resolved_stage1 / n_samples),
            "sandbox_invocation_rate": float((n_samples - resolved_stage1) / n_samples),
            "triage_accuracy": float(correct_predictions / n_samples)
        }


def late_fusion_weight_sweep(
    p_static: np.ndarray,
    p_dynamic: np.ndarray,
    y_true: np.ndarray,
    steps: int = 11
) -> List[Dict[str, float]]:
    """
    Performs systematic weight sweep w_s in [0.0, 1.0] for late fusion.
    """
    from sklearn.metrics import f1_score, roc_auc_score, accuracy_score
    results = []
    
    weights = np.linspace(0.0, 1.0, steps)
    for ws in weights:
        wd = 1.0 - ws
        p_hybrid = ws * p_static + wd * p_dynamic
        y_pred = (p_hybrid >= 0.5).astype(int)
        
        acc = accuracy_score(y_true, y_pred)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        try:
            auc = roc_auc_score(y_true, p_hybrid)
        except Exception:
            auc = 0.5
            
        results.append({
            "w_static": round(float(ws), 2),
            "w_dynamic": round(float(wd), 2),
            "accuracy": float(acc),
            "f1_score": float(f1),
            "roc_auc": float(auc)
        })
        
    return results


if __name__ == "__main__":
    triage = CascadedTriagePipeline()
    # Test benign sample
    res1 = triage.evaluate_sample(p_static=0.12)
    assert res1["verdict"] == "Benign" and not res1["sandbox_invoked"]
    
    # Test malware sample
    res2 = triage.evaluate_sample(p_static=0.91)
    assert res2["verdict"] == "Malware" and not res2["sandbox_invoked"]
    
    # Test ambiguous sample requiring sandbox
    res3 = triage.evaluate_sample(p_static=0.52, p_dynamic=0.88)
    assert res3["verdict"] == "Malware" and res3["sandbox_invoked"]
    print("Cascaded Triage tests passed successfully!")
