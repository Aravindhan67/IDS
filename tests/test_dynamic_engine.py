"""
Automated Unit Tests for Dynamic Telemetry Engine
AegisDroid Hybrid Android Intrusion Detection System (HIDS)

Verifies:
1. Exact 470-D dynamic schema initialization.
2. Strace log parsing for real Linux system calls and Android Binder transactions.
3. Empty, malformed, and missing trace log handling.
4. Handling of unknown system calls without crashing.
5. Verification that ADB failure does NOT silently fall back to simulation.
6. Verification that calibrated simulation is strictly marked with simulation provenance.
"""

import os
import tempfile
import numpy as np
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from src.dynamic_engine import DynamicTelemetryEngine

BASE_DIR = Path(__file__).resolve().parent.parent


@pytest.fixture
def dyn_engine():
    return DynamicTelemetryEngine()


def test_dynamic_engine_init(dyn_engine):
    assert dyn_engine.num_features == 470
    assert len(dyn_engine.syscalls) > 0
    assert len(dyn_engine.binders) > 0
    assert len(dyn_engine.syscalls) + len(dyn_engine.binders) == 470


def test_valid_strace_parsing(dyn_engine):
    # Construct synthetic strace log with known syscalls and binders
    trace_content = (
        "1234  open(\"/system/lib/libc.so\", O_RDONLY) = 3\n"
        "1234  read(3, \"\\177ELF...\", 512) = 512\n"
        "1234  close(3) = 0\n"
        "1234  ioctl(4, BINDER_WRITE_READ, 0xbee0) = 0\n"
        "1234  sendMultipartText(12345, \"message\") = 1\n"
        "1234  ACCESS_PERSONAL_INFO___(user=1) = 0\n"
    )
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
        f.write(trace_content)
        tmp_name = f.name

    try:
        vec = dyn_engine.parse_strace_log(tmp_name)
        assert vec.shape == (470,)
        assert vec.dtype == np.int32
        assert vec[dyn_engine.feature_index["open"]] == 1
        assert vec[dyn_engine.feature_index["read"]] == 1
        assert vec[dyn_engine.feature_index["close"]] == 1
        assert vec[dyn_engine.feature_index["ioctl"]] == 1
        assert vec[dyn_engine.feature_index["sendMultipartText"]] >= 1
        assert vec[dyn_engine.feature_index["ACCESS_PERSONAL_INFO___"]] >= 1

        stats = dyn_engine.get_summary_stats(vec)
        assert stats["total_system_events"] >= 6
        assert stats["active_syscalls"] >= 4
        assert stats["active_binders"] >= 2
    finally:
        if os.path.exists(tmp_name):
            os.remove(tmp_name)


def test_empty_and_missing_trace_log(dyn_engine):
    # 1. Missing file
    v_missing = dyn_engine.parse_strace_log("non_existent_trace.log")
    assert np.all(v_missing == 0)

    # 2. Empty file
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
        tmp_empty = f.name
    try:
        v_empty = dyn_engine.parse_strace_log(tmp_empty)
        assert np.all(v_empty == 0)
    finally:
        if os.path.exists(tmp_empty):
            os.remove(tmp_empty)


def test_malformed_trace_log(dyn_engine):
    malformed_content = (
        "--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR} ---\n"
        "+++ killed by SIGSEGV +++\n"
        "incomplete line with no paren\n"
        "invalid_call_not_in_schema(1, 2) = 0\n"
        "<... futex resumed> ) = 0\n"
    )
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
        f.write(malformed_content)
        tmp_name = f.name

    try:
        vec = dyn_engine.parse_strace_log(tmp_name)
        assert vec.shape == (470,)
        assert isinstance(vec, np.ndarray)
    finally:
        if os.path.exists(tmp_name):
            os.remove(tmp_name)


def test_adb_unavailable_no_silent_simulation(dyn_engine):
    """
    Critical requirement: When ADB is disconnected, live sandbox must return
    status: 'unavailable' and a zero vector, NEVER fabricating random telemetry.
    """
    with patch.object(dyn_engine, "check_adb_connection", return_value=(False, None, None)):
        vec, meta = dyn_engine.run_live_sandbox_trace("dummy.apk")
        assert np.all(vec == 0), "Expected zero vector when ADB is unavailable"
        assert meta["status"] == "unavailable"
        assert meta["execution_mode"] == "none"
        assert "no active android device" in meta["reason"].lower()


def test_simulated_mode_provenance_isolation(dyn_engine):
    """
    Simulation must be strictly isolated to demo mode and mark its provenance explicitly.
    """
    vec, meta = dyn_engine.generate_calibrated_telemetry(malware_propensity=0.8, random_state=42)
    assert vec.shape == (470,)
    assert np.sum(vec) > 0
    assert meta["status"] == "simulated"
    assert meta["execution_mode"] == "simulated_demo_protocol"
    assert "SIMULATED_DEMO_DATA" in meta["provenance"]


def test_detailed_strace_parsing_states(dyn_engine):
    """
    Tests detailed strace parsing distinguishing: empty, no_supported_events, success.
    """
    # 1. Empty trace
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
        tmp_empty = f.name
    try:
        res_empty = dyn_engine.parse_strace_log_detailed(tmp_empty)
        assert res_empty["status"] == "empty"
        assert res_empty["recognized_events"] == 0
    finally:
        if os.path.exists(tmp_empty):
            os.remove(tmp_empty)

    # 2. Trace with no recognized events
    unsupported_trace = (
        "100  custom_app_log(\"hello world\") = 0\n"
        "100  unrecognized_routine_xyz(1, 2, 3) = 0\n"
        "100  --- SIGCHLD {si_signo=SIGCHLD} ---\n"
    )
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
        f.write(unsupported_trace)
        tmp_unsupported = f.name
    try:
        res_unsupported = dyn_engine.parse_strace_log_detailed(tmp_unsupported)
        assert res_unsupported["status"] == "no_supported_events"
        assert res_unsupported["recognized_events"] == 0
        assert res_unsupported["total_lines"] >= 3
    finally:
        if os.path.exists(tmp_unsupported):
            os.remove(tmp_unsupported)

    # 3. Valid trace with recognized events
    valid_trace = (
        "100  open(\"/system/bin/sh\", O_RDONLY) = 3\n"
        "100  close(3) = 0\n"
        "100  sendMultipartText(12345, \"payload\") = 1\n"
    )
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
        f.write(valid_trace)
        tmp_valid = f.name
    try:
        res_valid = dyn_engine.parse_strace_log_detailed(tmp_valid)
        assert res_valid["status"] == "success"
        assert res_valid["recognized_events"] == 3
        assert res_valid["syscall_events"] >= 2
        assert res_valid["binder_events"] >= 1
    finally:
        if os.path.exists(tmp_valid):
            os.remove(tmp_valid)


def test_live_sandbox_package_injection_prevention(dyn_engine):
    """
    Validates package name syntax against command injection.
    """
    with patch.object(dyn_engine, "check_adb_connection", return_value=(True, "adb", "emulator-5554")):
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(b"PK...")
            tmp_apk = f.name

        try:
            # Dangerous injected package names
            for bad_pkg in ["com.malicious; rm -rf /", "com.app$(reboot)", "pkg&whoami", "invalid package"]:
                vec, meta = dyn_engine.run_live_sandbox_trace(tmp_apk, package_name=bad_pkg)
                assert meta["status"] == "failed"
                assert "invalid package name" in meta["reason"].lower()
        finally:
            if os.path.exists(tmp_apk):
                os.remove(tmp_apk)
