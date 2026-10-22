"""
VirusTotal Signature & Threat Intelligence Client
AegisDroid Hybrid Android Intrusion Detection System (HIDS)

Provides deterministic hash reputation lookups via VirusTotal API v3.
Decoupled strictly from Machine Learning models to preserve empirical integrity.

Enforces Honest Response States:
- 'found': Genuine match found in VirusTotal database.
- 'not_found': File hash not recognized by VirusTotal (404).
- 'unavailable': No API key configured in environment.
- 'rate_limited': VirusTotal public API rate limit reached (429).
- 'error': Network timeout or HTTP error.

Zero Fabricated Detections:
Never fabricates detection ratios (e.g. 48/74), invented vendor verdicts, or mock hashes.
"""

import os
import re
import hashlib
import logging
from pathlib import Path
from typing import Dict, Any, Optional
import requests
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(str(BASE_DIR / ".env"))

logger = logging.getLogger("AegisDroid.VirusTotal")
VT_BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalSignatureAnalyzer:
    """
    Interfaces with VirusTotal v3 API for deterministic APK hash reputation analysis.
    """

    def __init__(self, api_key: Optional[str] = None):
        if api_key is not None:
            self.api_key = api_key
        else:
            self.api_key = os.getenv("VIRUSTOTAL_API_KEY", "")

        # Masked key for safe logging
        if self.api_key:
            masked = f"{self.api_key[:4]}...{self.api_key[-4:]}" if len(self.api_key) > 8 else "***"
            logger.info("VirusTotal client initialized with API key: %s", masked)
        else:
            logger.info("VIRUSTOTAL_API_KEY not configured. Live VirusTotal lookups will return 'unavailable'.")

        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }

    @staticmethod
    def compute_file_hashes(filepath: str) -> Dict[str, str]:
        """
        Computes SHA-256, SHA-1, and MD5 hashes of a file.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        sha256_hash = hashlib.sha256()
        sha1_hash = hashlib.sha1()
        md5_hash = hashlib.md5()

        with open(filepath, "rb") as f:
            for block in iter(lambda: f.read(65536), b""):
                sha256_hash.update(block)
                sha1_hash.update(block)
                md5_hash.update(block)

        return {
            "sha256": sha256_hash.hexdigest(),
            "sha1": sha1_hash.hexdigest(),
            "md5": md5_hash.hexdigest()
        }

    @staticmethod
    def is_valid_hash(hash_str: str) -> bool:
        """Validates if string is a valid MD5 (32), SHA-1 (40), or SHA-256 (64) hex string."""
        if not hash_str or not isinstance(hash_str, str):
            return False
        clean = hash_str.strip().lower()
        if len(clean) in (32, 40, 64) and re.fullmatch(r"[0-9a-f]+", clean):
            return True
        return False

    def query_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Queries VirusTotal API v3 for a given file hash.
        Returns explicit status: 'found', 'not_found', 'unavailable', 'rate_limited', or 'error'.
        """
        clean_hash = file_hash.strip().lower() if file_hash else ""

        if not self.is_valid_hash(clean_hash):
            return {
                "status": "error",
                "success": False,
                "signature_detected": False,
                "hash": clean_hash,
                "error": "invalid_hash_format",
                "message": "Provided hash is not a valid hexadecimal MD5, SHA-1, or SHA-256 string."
            }

        if not self.api_key:
            return {
                "status": "unavailable",
                "success": False,
                "signature_detected": False,
                "hash": clean_hash,
                "message": "VirusTotal API key is not configured in .env. Signature analysis unavailable.",
                "decoupled_from_ml": True
            }

        endpoint = f"{VT_BASE_URL}/files/{clean_hash}"
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=10)

            if response.status_code == 200:
                data = response.json().get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total_engines = sum(stats.values()) if stats else 0

                threat_class = attributes.get("popular_threat_classification", {})
                suggested_threat = threat_class.get("suggested_threat_label", "Unknown")

                # Extract notable AV engines verdicts if present
                last_results = attributes.get("last_analysis_results", {})
                top_vendors = ["Kaspersky", "Microsoft", "Google", "Avast", "Symantec", "Sophos", "ESET-NOD32"]
                vendor_verdicts = {}
                for v in top_vendors:
                    if v in last_results:
                        vendor_verdicts[v] = {
                            "category": last_results[v].get("category"),
                            "result": last_results[v].get("result")
                        }

                is_malicious = (malicious >= 3)
                verdict = "Known Malware" if is_malicious else ("Suspicious" if malicious > 0 else "Clean / Benign")

                return {
                    "status": "found",
                    "success": True,
                    "signature_detected": is_malicious,
                    "verdict": verdict,
                    "hash": clean_hash,
                    "malicious_engines": malicious,
                    "suspicious_engines": suspicious,
                    "harmless_engines": harmless,
                    "undetected_engines": undetected,
                    "total_engines": total_engines,
                    "detection_ratio": f"{malicious}/{total_engines}" if total_engines > 0 else "0/0",
                    "threat_label": suggested_threat,
                    "reputation_score": attributes.get("reputation", 0),
                    "meaningful_name": attributes.get("meaningful_name", "N/A"),
                    "vendor_sample_verdicts": vendor_verdicts,
                    "decoupled_from_ml": True,
                    "message": f"VirusTotal match: {malicious}/{total_engines} engines flagged as malicious."
                }

            elif response.status_code == 404:
                return {
                    "status": "not_found",
                    "success": True,
                    "signature_detected": False,
                    "verdict": "Unknown / Not Found (Zero Prior Detections)",
                    "hash": clean_hash,
                    "detection_ratio": "0/0",
                    "malicious_engines": 0,
                    "suspicious_engines": 0,
                    "total_engines": 0,
                    "vendor_sample_verdicts": {},
                    "threat_label": "Not Found",
                    "message": "File hash was not found in VirusTotal database. Proceeding to ML analysis.",
                    "decoupled_from_ml": True
                }

            elif response.status_code == 429:
                logger.warning("VirusTotal API rate limit hit (429).")
                return {
                    "status": "rate_limited",
                    "success": False,
                    "signature_detected": False,
                    "hash": clean_hash,
                    "error": "Rate limit exceeded (429)",
                    "message": "VirusTotal request rate limit reached. Proceeding to ML pipeline."
                }

            else:
                return {
                    "status": "error",
                    "success": False,
                    "signature_detected": False,
                    "hash": clean_hash,
                    "error": f"HTTP {response.status_code}",
                    "message": f"VirusTotal API returned HTTP status {response.status_code}."
                }

        except requests.exceptions.RequestException as e:
            logger.error("VirusTotal request exception: %s", e)
            return {
                "status": "error",
                "success": False,
                "signature_detected": False,
                "hash": clean_hash,
                "error": str(e),
                "message": "Network error connecting to VirusTotal threat feed."
            }

    def analyze_apk_file(self, apk_path: str) -> Dict[str, Any]:
        """
        Computes hashes of the APK and queries VirusTotal using the actual computed SHA-256.
        """
        hashes = self.compute_file_hashes(apk_path)
        sha256 = hashes["sha256"]
        logger.info("Computed APK SHA-256: %s. Querying VirusTotal reputation...", sha256)
        result = self.query_hash(sha256)
        result["file_hashes"] = hashes
        return result


if __name__ == "__main__":
    analyzer = VirusTotalSignatureAnalyzer()
    # Test valid hash format check
    assert analyzer.is_valid_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    assert not analyzer.is_valid_hash("not_a_hash")

    # Offline test query
    res = analyzer.query_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    print("Offline / Direct Query Status:", res.get("status"))
    print("VirusTotalSignatureAnalyzer self-test passed!")
