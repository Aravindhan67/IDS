"""
Full 215-Feature Static Extractor for Android APKs
Hybrid Android APK Intrusion Detection System (HIDS)

Resolves Reviewer 2 Point 4:
Closes the 46.5% feature gap by extracting:
- Permissions (from AndroidManifest.xml)
- Intent filters (from AndroidManifest.xml)
- Dalvik bytecode API calls, class references, and reflection (from classes.dex via Androguard)
"""

import os
import json
import logging
from typing import Dict, List, Optional, Tuple, Set
import numpy as np

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class DrebinFeatureExtractor:
    """
    Extracts all 215 Drebin static features from raw Android APKs using Androguard.
    """
    
    def __init__(self, schema_path: str = "c:/ids/models/drebin_feature_names.json"):
        if not os.path.exists(schema_path):
            raise FileNotFoundError(f"Feature schema not found at {schema_path}")
            
        with open(schema_path, "r") as f:
            self.feature_names = json.load(f)
            
        self.num_features = len(self.feature_names)
        self.feature_index = {feat: idx for idx, feat in enumerate(self.feature_names)}
        
        # Categorize features
        self.permissions: Set[str] = set()
        self.intents: Set[str] = set()
        self.api_calls: Set[str] = set()
        
        self._categorize_features()
        logger.info("Initialized DrebinFeatureExtractor with %d features "
                    "(%d Permissions, %d Intents, %d API/Bytecode calls)",
                    self.num_features, len(self.permissions), len(self.intents), len(self.api_calls))

    def _categorize_features(self):
        for feat in self.feature_names:
            feat_lower = feat.lower()
            if "intent" in feat_lower or "action" in feat_lower:
                self.intents.add(feat)
            elif feat.isupper() and ("_" in feat or "PERMISSION" in feat) and not feat.startswith("L"):
                self.permissions.add(feat)
            else:
                self.api_calls.add(feat)

    def extract_from_apk(
        self, 
        apk_path: str, 
        mode: str = "all_215"
    ) -> np.ndarray:
        """
        Extracts feature vector from an APK file.
        
        Args:
            apk_path: Path to the .apk file.
            mode: 'all_215' for full feature extraction, 
                  'permissions_only' for ablation study (zeroing out intents & APIs).
                  
        Returns:
            np.ndarray: Binary feature vector of shape (215,), uint8.
        """
        if not os.path.exists(apk_path):
            raise FileNotFoundError(f"APK file not found: {apk_path}")
            
        vector = np.zeros(self.num_features, dtype=np.uint8)
        
        try:
            # Silence verbose logging
            try:
                from loguru import logger as loguru_logger
                loguru_logger.disable("androguard")
            except Exception:
                pass
            logging.getLogger("androguard").setLevel(logging.ERROR)

            from androguard.core.apk import APK
            from androguard.core.dex import DEX
            a = APK(apk_path)
        except Exception as e:
            logger.error("Error analyzing APK with Androguard: %s", e)
            return vector

        # 1. Extract Permissions
        try:
            manifest_perms = a.get_permissions() or []
            manifest_perms += a.get_declared_permissions() or []
            for perm in manifest_perms:
                clean_perm = perm.split(".")[-1]
                if clean_perm in self.feature_index:
                    vector[self.feature_index[clean_perm]] = 1
                if perm in self.feature_index:
                    vector[self.feature_index[perm]] = 1
        except Exception as e:
            logger.warning("Could not extract permissions: %s", e)

        # If permissions_only ablation mode, stop here
        if mode == "permissions_only":
            return vector

        # 2. Extract Intent Filters
        try:
            intent_actions = set()
            for activity in (a.get_activities() or []):
                filters = a.get_intent_filters("activity", activity) or {}
                intent_actions.update(filters.get("action", []))
            for service in (a.get_services() or []):
                filters = a.get_intent_filters("service", service) or {}
                intent_actions.update(filters.get("action", []))
            for receiver in (a.get_receivers() or []):
                filters = a.get_intent_filters("receiver", receiver) or {}
                intent_actions.update(filters.get("action", []))

            for action in intent_actions:
                if action in self.feature_index:
                    vector[self.feature_index[action]] = 1
                short_action = action.split(".")[-1]
                if short_action in self.feature_index:
                    vector[self.feature_index[short_action]] = 1
        except Exception as e:
            logger.warning("Could not extract intents: %s", e)

        # 3. Extract Dalvik Bytecode API Calls and Classes
        try:
            class_tokens = set()
            method_tokens = set()
            dex_strings = set()

            dex_blobs = list(a.get_all_dex())
            for dex in dex_blobs:
                d = DEX(dex)
                # 3a. Classes
                for cname in d.get_classes_names():
                    class_tokens.add(cname)
                    # Normalize: 'Landroid/telephony/TelephonyManager;' -> 'Landroid.telephony.TelephonyManager'
                    c_dot = cname.replace('/', '.').rstrip(';')
                    class_tokens.add(c_dot)
                    # Without leading 'L'
                    c_clean = c_dot.lstrip('L')
                    class_tokens.add(c_clean)
                    # Short class name: 'TelephonyManager'
                    short_c = c_clean.split('.')[-1]
                    class_tokens.add(short_c)

                # 3b. Methods & Invocations
                for method in d.get_methods():
                    m_name = method.get_name()
                    c_raw = method.get_class_name()
                    c_dot = c_raw.replace('/', '.').rstrip(';')
                    c_clean = c_dot.lstrip('L')
                    short_c = c_clean.split('.')[-1]

                    method_tokens.add(f"{c_raw}->{m_name}")
                    method_tokens.add(f"{c_dot}.{m_name}")
                    method_tokens.add(f"{c_clean}.{m_name}")
                    method_tokens.add(f"{short_c}.{m_name}")
                    method_tokens.add(m_name)

                # 3c. DEX string pool
                dex_strings.update(d.get_strings())

            # Aggregate corpus for fast lookup
            combined_corpus = " ".join(class_tokens) + " " + " ".join(method_tokens)

            for api_feat in self.api_calls:
                idx = self.feature_index[api_feat]
                # Check direct match in combined corpus or string pool
                if (api_feat in combined_corpus or 
                    api_feat in dex_strings or 
                    api_feat in class_tokens or 
                    api_feat in method_tokens):
                    vector[idx] = 1
        except Exception as e:
            logger.warning("Could not extract DEX bytecode APIs: %s", e)

        return vector

    def get_feature_breakdown(self, vector: np.ndarray) -> Dict[str, int]:
        """
        Reports non-zero feature counts across permissions, intents, and APIs.
        """
        active_perms = sum(vector[self.feature_index[f]] for f in self.permissions)
        active_intents = sum(vector[self.feature_index[f]] for f in self.intents)
        active_apis = sum(vector[self.feature_index[f]] for f in self.api_calls)
        return {
            "total_active": int(np.sum(vector)),
            "active_permissions": int(active_perms),
            "active_intents": int(active_intents),
            "active_apis": int(active_apis)
        }


if __name__ == "__main__":
    extractor = DrebinFeatureExtractor()
    print("Extractor initialized successfully. Ready for APK parsing.")
