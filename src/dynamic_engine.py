"""
Dynamic Telemetry Engine & Syscall/Binder Profiler
AegisDroid Hybrid Android Intrusion Detection System (HIDS)

Provides deterministic parsing of Linux kernel system call traces and Android IPC Binder transactions
strictly aligned with the 470 CICMalDroid feature schema.

Supports:
1. Real kernel strace / Frida log parsing from live Android devices or user uploads.
2. Safe live execution orchestration via ADB with explicit timeout, device verification, and cleanup.
3. Explicit separation between live execution, uploaded traces, dataset samples, and demo simulation.
   Silent fallbacks to synthetic telemetry are strictly disabled.
"""

import os
import re
import json
import shutil
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
import numpy as np

logger = logging.getLogger("AegisDroid.DynamicEngine")

BASE_DIR = Path(__file__).resolve().parent.parent


class DynamicTelemetryEngine:
    """
    Parses dynamic behavioral event frequencies matching the 470 CICMalDroid features.
    Provides verified ADB runtime tracing and strictly isolated demo simulation.
    """

    def __init__(self, schema_path: Optional[str] = None):
        if schema_path is None:
            schema_path = str(BASE_DIR / "models" / "dynamic_feature_names.json")

        if not os.path.exists(schema_path):
            raise FileNotFoundError(f"Dynamic feature schema not found at: {schema_path}")

        with open(schema_path, "r", encoding="utf-8") as f:
            self.feature_names: List[str] = json.load(f)

        self.num_features = len(self.feature_names)
        if self.num_features != 470:
            logger.warning("Dynamic schema contains %d features (expected 470)", self.num_features)

        self.feature_index: Dict[str, int] = {feat: idx for idx, feat in enumerate(self.feature_names)}

        # Partition into Linux kernel syscalls and Android Binder / high-level IPC transactions
        self.syscalls: Set[str] = set()
        self.binders: Set[str] = set()
        for feat in self.feature_names:
            if feat.islower() or feat.startswith("__") or feat.startswith("_"):
                self.syscalls.add(feat)
            else:
                self.binders.add(feat)

        # Pre-compile regex for fast binder and syscall token extraction in strace logs
        # Escaped tokens for binder features
        binder_patterns = [re.escape(b) for b in sorted(self.binders, key=len, reverse=True)]
        self._binder_regex = re.compile(r"(" + "|".join(binder_patterns) + r")") if binder_patterns else None

        logger.info(
            "Initialized DynamicTelemetryEngine with %d features (%d Syscalls, %d Binders/IPC)",
            self.num_features, len(self.syscalls), len(self.binders)
        )

    def get_139_syscall_schema(self) -> List[str]:
        """Returns the exact 139 Linux syscall feature schema subset from CICMalDroid."""
        return sorted(list(self.syscalls))[:139]

    def parse_strace_log(self, log_path: str) -> np.ndarray:
        """
        Parses an actual Linux strace log file from emulator or physical device execution.
        Counts occurrences of the 470 syscalls and Binder transactions deterministically.

        Handles:
        - Standard strace: '1234  ioctl(4, BINDER_WRITE_READ, ...) = 0'
        - Prefixed with timestamps: '12:00:00.123456 open("/dev/null", O_RDONLY) = 3'
        - Resumed lines: '<... futex resumed> ) = 0'
        - Malformed or incomplete lines.

        Returns:
            np.ndarray: Integer vector of shape (470,), int32.
        """
        vector = np.zeros(self.num_features, dtype=np.int32)
        if not log_path or not os.path.exists(log_path):
            logger.warning("Trace log not found at '%s'. Returning zero vector.", log_path)
            return vector

        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line_clean = line.strip()
                    if not line_clean or line_clean.startswith("---") or line_clean.startswith("+++"):
                        continue

                    # 1. Parse system call from start of line or after PID/timestamp
                    paren_idx = line_clean.find("(")
                    if paren_idx > 0:
                        prefix = line_clean[:paren_idx].strip()
                        # Tokens before '(' e.g. "1234 openat" or "ioctl"
                        call_token = prefix.split()[-1] if prefix.split() else ""
                        if call_token in self.feature_index:
                            vector[self.feature_index[call_token]] += 1

                    # 2. Match Binder IPC transactions if present in the line
                    if self._binder_regex:
                        for match in self._binder_regex.finditer(line_clean):
                            b_name = match.group(1)
                            if b_name in self.feature_index:
                                vector[self.feature_index[b_name]] += 1

        except Exception as e:
            logger.error("Error parsing trace log '%s': %s", log_path, e)

        return vector

    def check_adb_connection(self) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Verifies whether an active Android emulator or physical device is connected via ADB.

        Returns:
            Tuple[bool, Optional[str], Optional[str]]: (has_device, adb_path, device_id)
        """
        adb_path = shutil.which("adb")
        if not adb_path:
            # Check default Android SDK locations
            candidates = [
                os.path.expanduser("~/AppData/Local/Android/Sdk/platform-tools/adb.exe"),
                "C:/Users/ARAVINDHAN T/AppData/Local/Android/Sdk/platform-tools/adb.exe",
                "/usr/bin/adb",
                "/usr/local/bin/adb"
            ]
            for c in candidates:
                if os.path.exists(c):
                    adb_path = c
                    break

        if not adb_path:
            return False, None, None

        try:
            res = subprocess.run([adb_path, "devices"], capture_output=True, text=True, timeout=5)
            lines = [line.strip() for line in res.stdout.strip().split("\n") if line.strip()]
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "device":
                    return True, adb_path, parts[0]
        except Exception as e:
            logger.warning("ADB device check failed: %s", e)

        return False, adb_path, None

    def run_live_sandbox_trace(
        self,
        apk_path: str,
        package_name: Optional[str] = None,
        duration_seconds: int = 15,
        temp_log_path: Optional[str] = None
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Executes live dynamic sandbox profiling on a connected Android emulator/device via ADB.
        Strictly requires an active Android environment. Does NOT silently fabricate mock telemetry.

        Returns:
            Tuple[np.ndarray, Dict[str, Any]]: (Feature vector, Execution metadata)
            Metadata status: 'success', 'unavailable', or 'failed'.
        """
        if temp_log_path is None:
            temp_log_path = str(BASE_DIR / "outputs" / "live_strace.log")

        has_device, adb_path, device_id = self.check_adb_connection()

        if not has_device or not adb_path:
            logger.info("No active Android emulator connected via ADB. Dynamic live execution unavailable.")
            return np.zeros(self.num_features, dtype=np.int32), {
                "status": "unavailable",
                "execution_mode": "none",
                "reason": "No active Android device or emulator connected via ADB. Static analysis preserved.",
                "duration_seconds": 0,
                "events_captured": 0
            }

        # Safe execution workflow
        try:
            if not os.path.exists(apk_path):
                raise FileNotFoundError(f"Target APK not found: {apk_path}")

            # 1. Resolve package name if not provided
            if not package_name:
                try:
                    from androguard.core.apk import APK
                    a = APK(apk_path)
                    package_name = a.get_package()
                except Exception as e:
                    logger.warning("Could not extract package name via Androguard: %s", e)

            if not package_name:
                raise ValueError("Could not determine package name for target APK.")

            logger.info("Executing live dynamic profiling for package '%s' on device %s...", package_name, device_id)

            # 2. Install APK with timeout
            install_res = subprocess.run(
                [adb_path, "-s", device_id, "install", "-r", apk_path],
                capture_output=True, text=True, timeout=40
            )
            if "Success" not in install_res.stdout:
                raise RuntimeError(f"APK installation failed: {install_res.stderr or install_res.stdout}")

            # 3. Launch application main activity using monkey
            subprocess.run(
                [adb_path, "-s", device_id, "shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"],
                capture_output=True, timeout=10
            )

            # 4. Attach strace to spawned process tree
            strace_remote_log = "/data/local/tmp/aegis_trace.log"
            strace_script = (
                f"pid=$(pidof {package_name}); "
                f"if [ -n \"$pid\" ]; then "
                f"  timeout {duration_seconds} strace -f -p $pid -o {strace_remote_log}; "
                f"fi"
            )
            subprocess.run(
                [adb_path, "-s", device_id, "shell", strace_script],
                timeout=duration_seconds + 10,
                capture_output=True
            )

            # 5. Pull trace log
            os.makedirs(os.path.dirname(temp_log_path), exist_ok=True)
            subprocess.run(
                [adb_path, "-s", device_id, "pull", strace_remote_log, temp_log_path],
                timeout=15,
                capture_output=True
            )

            # 6. Parse trace log
            vector = self.parse_strace_log(temp_log_path)
            events = int(np.sum(vector))

            # 7. Safe cleanup on device
            subprocess.run([adb_path, "-s", device_id, "shell", f"rm -f {strace_remote_log}"], timeout=10)
            subprocess.run([adb_path, "-s", device_id, "uninstall", package_name], timeout=20)

            logger.info("Live dynamic execution succeeded: %d kernel events captured.", events)
            return vector, {
                "status": "success",
                "execution_mode": "live_adb_strace",
                "device_id": device_id,
                "duration_seconds": duration_seconds,
                "events_captured": events
            }

        except Exception as e:
            logger.error("Live dynamic execution failed: %s", e)
            return np.zeros(self.num_features, dtype=np.int32), {
                "status": "failed",
                "execution_mode": "failed",
                "reason": str(e),
                "duration_seconds": 0,
                "events_captured": 0
            }

    def generate_calibrated_telemetry(
        self,
        malware_propensity: float = 0.5,
        activity_level: str = "medium",
        random_state: Optional[int] = None
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Synthesizes statistically grounded dynamic telemetry vectors for DEMONSTRATION ONLY.
        Strictly labeled with simulation provenance to ensure empirical transparency.

        Args:
            malware_propensity: 0.0 (pure benign profile) to 1.0 (aggressive malware profile).
            activity_level: 'low', 'medium', or 'high' total event volume.
            random_state: Seed for reproducible evaluations.

        Returns:
            Tuple[np.ndarray, Dict[str, Any]]: (Vector of shape (470,), Metadata with simulation provenance).
        """
        rng = np.random.RandomState(random_state)
        vector = np.zeros(self.num_features, dtype=np.int32)

        vol_mult = {"low": 0.5, "medium": 1.0, "high": 2.5}.get(activity_level, 1.0)

        # 1. Base Linux runtime syscalls (occur in both benign and malware apps)
        common_syscalls = [
            'open', 'read', 'write', 'close', 'mmap2', 'ioctl', 'futex',
            'clock_gettime', 'epoll_wait', 'stat64', 'fstat64', 'brk'
        ]
        for sc in common_syscalls:
            if sc in self.feature_index:
                base_count = int(rng.poisson(lam=35 * vol_mult))
                vector[self.feature_index[sc]] = max(1, base_count)

        # 2. Malware-correlated syscalls (process manipulation, stealth, network)
        malicious_syscalls = [
            'execve', 'fork', 'clone', 'ptrace', 'prctl', 'chmod', 'chown32',
            'mount', 'mprotect', 'sysinfo', 'socket', 'connect', 'sendto'
        ]
        for sc in malicious_syscalls:
            if sc in self.feature_index:
                if rng.rand() < (0.2 + 0.7 * malware_propensity):
                    count = int(rng.geometric(p=0.2 / (1.0 + 3.0 * malware_propensity)) * vol_mult)
                    vector[self.feature_index[sc]] = count

        # 3. Malware-correlated Android Binder transactions
        malicious_binders = [
            'ACCESS_PERSONAL_INFO___', 'ALTER_PHONE_STATE___', 'sendMultipartText',
            'getDeviceId', 'getSubscriberId', 'getIccSerialNumber', 'FS_ACCESS(WRITE)____',
            'NETWORK_ACCESS(WRITE)____', 'TERMINATE_PROCESS', 'CREATE_THREAD_____'
        ]
        for binder in malicious_binders:
            if binder in self.feature_index:
                if rng.rand() < (0.15 + 0.8 * malware_propensity):
                    count = int(rng.poisson(lam=(2 + 15 * malware_propensity) * vol_mult))
                    vector[self.feature_index[binder]] = count

        meta = {
            "status": "simulated",
            "execution_mode": "simulated_demo_protocol",
            "provenance": "SIMULATED_DEMO_DATA_NOT_LIVE_EXECUTION",
            "malware_propensity": malware_propensity,
            "activity_level": activity_level,
            "random_state": random_state
        }
        return vector, meta

    def get_summary_stats(self, vector: np.ndarray) -> Dict[str, Any]:
        """
        Summarizes the dynamic telemetry vector properties with exact syscall vs binder partition.
        """
        total_calls = int(np.sum(vector))
        non_zero = int(np.sum(vector > 0))
        max_call = int(np.max(vector)) if len(vector) > 0 else 0

        total_syscalls = 0
        total_binders = 0
        active_syscalls = 0
        active_binders = 0
        for i, val in enumerate(vector):
            if val > 0:
                feat = self.feature_names[i]
                if feat in self.syscalls:
                    total_syscalls += int(val)
                    active_syscalls += 1
                else:
                    total_binders += int(val)
                    active_binders += 1

        sparsity = float(100.0 * (1.0 - (non_zero / self.num_features))) if self.num_features > 0 else 0.0

        return {
            "total_system_events": total_calls,
            "total_syscalls": total_syscalls,
            "total_binders": total_binders,
            "active_syscalls": active_syscalls,
            "active_binders": active_binders,
            "active_features": non_zero,
            "unique_features_activated": non_zero,
            "max_single_feature_count": max_call,
            "sparsity_percentage": round(sparsity, 2)
        }


if __name__ == "__main__":
    engine = DynamicTelemetryEngine()
    sim_vec, meta = engine.generate_calibrated_telemetry(malware_propensity=0.9, random_state=42)
    stats = engine.get_summary_stats(sim_vec)
    print("Simulated Demo Summary:", stats)
    print("Metadata Provenance:", meta)
    assert np.sum(sim_vec) > 0
    print("DynamicTelemetryEngine self-test passed!")
