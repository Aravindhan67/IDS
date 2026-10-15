"""
VirusTotal Signature & Threat Intelligence Client
Hybrid Android APK Intrusion Detection System (HIDS)

Resolves Reviewer 2 Point 2:
Provides real-time VirusTotal API v3 integration for deterministic hash lookup,
while maintaining strict decoupling from ML generalization benchmarks.
"""

import os
import sys
import hashlib
import logging
from typing import Dict, Any, Optional, Tuple
import requests
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

VT_BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalSignatureAnalyzer:
    """
    Interfaces with VirusTotal v3 API for deterministic APK hash reputation analysis.
    """
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY", "")
        if not self.api_key:
            logger.warning("VIRUSTOTAL_API_KEY is not configured. Live VirusTotal lookups will be disabled.")
            
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

    def query_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Queries VirusTotal API v3 for a given file hash.
        """
        clean_hash = file_hash.strip().lower()
        if not self.api_key:
            return {
                "success": False,
                "signature_detected": False,
                "error": "Missing VIRUSTOTAL_API_KEY",
                "message": "VirusTotal API key not configured. Proceeding to ML analysis."
            }

        endpoint = f"{VT_BASE_URL}/files/{clean_hash}"
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=12)
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total_engines = sum(stats.values()) if stats else 0
                
                # Popular threat category
                threat_class = attributes.get("popular_threat_classification", {})
                suggested_threat = threat_class.get("suggested_threat_label", "Unknown")
                
                # Extract notable AV engines verdicts
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
                    "success": True,
                    "signature_detected": is_malicious,
                    "verdict": verdict,
                    "hash": clean_hash,
                    "malicious_engines": malicious,
                    "suspicious_engines": suspicious,
                    "total_engines": total_engines,
                    "detection_ratio": f"{malicious}/{total_engines}",
                    "threat_label": suggested_threat,
                    "reputation_score": attributes.get("reputation", 0),
                    "meaningful_name": attributes.get("meaningful_name", "N/A"),
                    "vendor_sample_verdicts": vendor_verdicts,
                    "decoupled_from_ml": True,
                    "message": f"VirusTotal match: {malicious}/{total_engines} engines flagged as malicious."
                }
                
            elif response.status_code == 404:
                return {
                    "success": True,
                    "signature_detected": False,
                    "verdict": "Unknown to Threat Feed (Zero Prior Signatures)",
                    "hash": clean_hash,
                    "message": "File hash not found in VirusTotal database. Full ML analysis required.",
                    "decoupled_from_ml": True
                }
                
            elif response.status_code == 429:
                logger.warning("VirusTotal API rate limit hit (429).")
                return {
                    "success": False,
                    "signature_detected": False,
                    "error": "Rate limit exceeded (429)",
                    "message": "VirusTotal request rate limit reached. Proceeding to ML pipeline."
                }
                
            else:
                return {
                    "success": False,
                    "signature_detected": False,
                    "error": f"HTTP {response.status_code}",
                    "message": f"VirusTotal API returned status {response.status_code}."
                }

        except requests.exceptions.RequestException as e:
            logger.error("VirusTotal request exception: %s", e)
            return {
                "success": False,
                "signature_detected": False,
                "error": str(e),
                "message": "Network error connecting to VirusTotal. Proceeding to ML pipeline."
            }

    def analyze_apk_file(self, apk_path: str) -> Dict[str, Any]:
        """
        Computes hashes of the APK and queries VirusTotal.
        """
        hashes = self.compute_file_hashes(apk_path)
        sha256 = hashes["sha256"]
        logger.info("Computed APK SHA-256: %s. Querying VirusTotal...", sha256)
        result = self.query_hash(sha256)
        result["file_hashes"] = hashes
        return result


if __name__ == "__main__":
    analyzer = VirusTotalSignatureAnalyzer()
    # Test with standard EICAR test string hash
    eicar_sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    logger.info("Testing VirusTotal API connection with reference malware hash: %s", eicar_sha256)
    res = analyzer.query_hash(eicar_sha256)
    import json
    print(json.dumps(res, indent=2))
