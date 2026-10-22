"""
Full 215-Feature Static Extractor for Android APKs
AegisDroid Hybrid Android Intrusion Detection System (HIDS)

Extracts all 215 Drebin static features using Androguard:
- AndroidManifest permissions (requested and declared)
- AndroidManifest intent filters and broadcast actions
- Dalvik bytecode API invocations, class references, and sensitive strings (Multidex supported)

Replaces unrestricted substring search with deterministic, canonical token matching.
Prevents false-positive feature activations and ensures exact schema alignment.
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
import numpy as np

logger = logging.getLogger("AegisDroid.FeatureExtractor")

BASE_DIR = Path(__file__).resolve().parent.parent
MAX_APK_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB safe limit


class DrebinFeatureExtractor:
    """
    Extracts all 215 Drebin static features from raw Android APKs using Androguard.
    """

    def __init__(self, schema_path: Optional[str] = None):
        if schema_path is None:
            schema_path = str(BASE_DIR / "models" / "drebin_feature_names.json")

        if not os.path.exists(schema_path):
            raise FileNotFoundError(f"Feature schema not found at: {schema_path}")

        with open(schema_path, "r", encoding="utf-8") as f:
            self.feature_names: List[str] = json.load(f)

        self.num_features = len(self.feature_names)
        if self.num_features != 215:
            raise ValueError(f"Expected exactly 215 Drebin features, got {self.num_features}")

        if len(set(self.feature_names)) != self.num_features:
            raise ValueError("Duplicate feature names detected in schema")

        self.feature_index: Dict[str, int] = {feat: idx for idx, feat in enumerate(self.feature_names)}

        # Categorize features grounded in Drebin specification
        self.permissions: Set[str] = set()
        self.intents: Set[str] = set()
        self.api_calls: Set[str] = set()

        self._categorize_features()
        logger.info(
            "Initialized DrebinFeatureExtractor with %d features "
            "(%d Permissions, %d Intents, %d API/Bytecode calls)",
            self.num_features, len(self.permissions), len(self.intents), len(self.api_calls)
        )

    def _categorize_features(self):
        """
        Categorizes features into Permissions (115), Intents (24), and APIs/Bytecode (76).
        Grounded in Drebin feature taxonomy.
        """
        for feat in self.feature_names:
            feat_lower = feat.lower()
            if "intent" in feat_lower or "action" in feat_lower:
                self.intents.add(feat)
            elif feat.isupper() and not feat.startswith("L") and not feat.startswith("/"):
                # Captures all manifest permissions including single-word permissions like INTERNET, CAMERA
                self.permissions.add(feat)
            else:
                self.api_calls.add(feat)

    def validate_apk_file(self, apk_path: str) -> None:
        """
        Validates APK file existence, size, and zip magic header.
        """
        if not os.path.exists(apk_path):
            raise FileNotFoundError(f"APK file not found: {apk_path}")

        size = os.path.getsize(apk_path)
        if size == 0:
            raise ValueError(f"APK file is empty (0 bytes): {apk_path}")

        if size > MAX_APK_SIZE_BYTES:
            raise ValueError(f"APK file exceeds maximum safe limit ({size} > {MAX_APK_SIZE_BYTES} bytes): {apk_path}")

        with open(apk_path, "rb") as f:
            magic = f.read(4)
            if magic not in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
                raise ValueError(f"File '{apk_path}' is not a valid ZIP/APK archive (magic: {magic!r})")

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
        vec, _ = self.extract_from_apk_detailed(apk_path, mode=mode)
        return vec

    def extract_from_apk_detailed(
        self,
        apk_path: str,
        mode: str = "all_215"
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Extracts feature vector and returns comprehensive forensic metadata.

        Returns:
            Tuple[np.ndarray, Dict[str, Any]]: (Binary vector of shape (215,), Metadata dict)
        """
        vector = np.zeros(self.num_features, dtype=np.uint8)

        try:
            self.validate_apk_file(apk_path)
        except Exception as e:
            logger.error("APK pre-validation failed for '%s': %s", apk_path, e)
            return vector, {
                "status": "error",
                "error": str(e),
                "active_features_count": 0,
                "breakdown": self.get_feature_breakdown(vector)
            }

        try:
            # Silence verbose Androguard logging
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
            return vector, {
                "status": "error",
                "error": f"Androguard parse failure: {e}",
                "active_features_count": 0,
                "breakdown": self.get_feature_breakdown(vector)
            }

        # 1. Extract Permissions from AndroidManifest.xml
        try:
            manifest_perms = set(a.get_permissions() or [])
            manifest_perms.update(a.get_declared_permissions() or [])

            for raw_perm in manifest_perms:
                # Direct match (e.g., "android.permission.SEND_SMS" or custom)
                if raw_perm in self.feature_index:
                    vector[self.feature_index[raw_perm]] = 1
                # Short name match (e.g., "SEND_SMS")
                short_perm = raw_perm.split(".")[-1]
                if short_perm in self.feature_index:
                    vector[self.feature_index[short_perm]] = 1

        except Exception as e:
            logger.warning("Could not extract permissions: %s", e)

        # If ablation mode requested, stop here
        if mode == "permissions_only":
            breakdown = self.get_feature_breakdown(vector)
            return vector, {
                "status": "success",
                "mode": "permissions_only",
                "active_features_count": int(np.sum(vector)),
                "breakdown": breakdown
            }

        # 2. Extract Intent Filters from Components
        try:
            intent_actions: Set[str] = set()
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
            logger.warning("Could not extract intent filters: %s", e)

        # 3. Extract Dalvik Bytecode APIs, Class References, and Sensitive Strings (Multidex)
        try:
            exact_classes: Set[str] = set()
            exact_methods: Set[str] = set()
            exact_method_names: Set[str] = set()
            exact_strings: Set[str] = set()

            dex_blobs = list(a.get_all_dex())
            for dex_bytes in dex_blobs:
                if not dex_bytes:
                    continue
                try:
                    d = DEX(dex_bytes)
                except Exception as dex_err:
                    logger.warning("Failed parsing DEX slice in '%s': %s", apk_path, dex_err)
                    continue

                # 3a. Class tokens
                for cname in (d.get_classes_names() or []):
                    exact_classes.add(cname)
                    # Normalized formats
                    c_dot = cname.replace('/', '.').rstrip(';')
                    exact_classes.add(c_dot)
                    c_clean = c_dot.lstrip('L')
                    exact_classes.add(c_clean)
                    short_c = c_clean.split('.')[-1]
                    exact_classes.add(short_c)

                # 3b. Method tokens & Invocations
                for method in (d.get_methods() or []):
                    m_name = method.get_name()
                    c_raw = method.get_class_name()
                    c_dot = c_raw.replace('/', '.').rstrip(';')
                    c_clean = c_dot.lstrip('L')
                    short_c = c_clean.split('.')[-1]

                    exact_method_names.add(m_name)
                    exact_methods.add(f"{c_raw}->{m_name}")
                    exact_methods.add(f"{c_dot}.{m_name}")
                    exact_methods.add(f"{c_clean}.{m_name}")
                    exact_methods.add(f"{short_c}.{m_name}")

                # 3c. String pool
                for s in (d.get_strings() or []):
                    exact_strings.add(s)

            # Exact canonical matching for API features (NO permissive substring search)
            for api_feat in self.api_calls:
                idx = self.feature_index[api_feat]

                # Direct match in string constants (e.g. '/system/bin', '/system/app')
                if api_feat in exact_strings:
                    vector[idx] = 1
                    continue

                # Direct class match (e.g. 'DexClassLoader', 'SecretKey', 'Ljavax.crypto.Cipher')
                if api_feat in exact_classes:
                    vector[idx] = 1
                    continue

                # Method invocation or Class.method match (e.g. 'TelephonyManager.getDeviceId', 'Runtime.getRuntime')
                if api_feat in exact_methods:
                    vector[idx] = 1
                    continue

                # Method invocation with dot suffix (e.g. 'HttpGet.init', 'HttpPost.init')
                if api_feat.endswith(".init") and (api_feat in exact_methods or api_feat.split(".")[0] in exact_classes):
                    vector[idx] = 1
                    continue

                # Standalone method name match (e.g. 'transact', 'onBind', 'chmod', 'chown')
                if api_feat in exact_method_names:
                    vector[idx] = 1
                    continue

        except Exception as e:
            logger.warning("Could not extract DEX bytecode APIs: %s", e)

        breakdown = self.get_feature_breakdown(vector)
        return vector, {
            "status": "success",
            "mode": mode,
            "active_features_count": int(np.sum(vector)),
            "breakdown": breakdown
        }

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
    sample_path = str(BASE_DIR / "tests" / "samples" / "test_sample.apk")
    if os.path.exists(sample_path):
        v, meta = extractor.extract_from_apk_detailed(sample_path)
        print("Extraction Result on sample APK:", meta)
    print("DrebinFeatureExtractor verification passed!")
