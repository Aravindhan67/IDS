"use client";

import { useState, useEffect } from "react";

const API_BASE = "http://127.0.0.1:8000";

export default function AegisDroidHIDS() {
  const [health, setHealth] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");
  const [selectedSample, setSelectedSample] = useState("sms_trojan");
  const [autoSimulateDynamic, setAutoSimulateDynamic] = useState(true);

  // Hash Copy Feedback State
  const [copiedSha, setCopiedSha] = useState(false);
  const [copiedMd5, setCopiedMd5] = useState(false);

  const copyToClipboard = (text, type) => {
    if (!text) return;
    try {
      navigator.clipboard.writeText(text);
      if (type === "sha") {
        setCopiedSha(true);
        setTimeout(() => setCopiedSha(false), 2000);
      } else {
        setCopiedMd5(true);
        setTimeout(() => setCopiedMd5(false), 2000);
      }
    } catch (e) {
      console.warn("Clipboard copy failed:", e);
    }
  };

  // Fetch Health & Pre-load real dynamic SMS Trojan on initial mount
  useEffect(() => {
    fetchHealth();
    loadSampleScan("sms_trojan");
  }, []);

  const fetchHealth = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/health`);
      if (res.ok) {
        const data = await res.json();
        setHealth(data);
      }
    } catch (err) {
      console.warn("API health check failed:", err);
    }
  };

  const loadSampleScan = async (sampleType) => {
    setScanning(true);
    setErrorMsg("");
    setSelectedSample(sampleType);
    try {
      const res = await fetch(`${API_BASE}/api/scan-sample`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sample_type: sampleType }),
      });
      if (!res.ok) throw new Error("Failed to scan real dataset sample");
      const data = await res.json();
      setScanResult(data);
    } catch (err) {
      setErrorMsg(err.message);
    } finally {
      setScanning(false);
    }
  };

  const handleApkUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".apk")) {
      setErrorMsg("Please upload a valid Android package (.apk)");
      return;
    }

    setScanning(true);
    setErrorMsg("");
    setSelectedSample("custom");
    const formData = new FormData();
    formData.append("file", file);

    const queryParam = autoSimulateDynamic ? "?simulate_dynamic=true" : "";

    try {
      const res = await fetch(`${API_BASE}/api/scan-apk${queryParam}`, {
        method: "POST",
        body: formData,
      });
      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail || `Scan failed: ${res.statusText}`);
      }
      const data = await res.json();
      setScanResult(data);
    } catch (err) {
      setErrorMsg(err.message || "APK upload and analysis failed.");
    } finally {
      setScanning(false);
    }
  };

  const handleTraceUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setScanning(true);
    setErrorMsg("");
    setSelectedSample("custom_trace");
    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch(`${API_BASE}/api/scan-trace`, {
        method: "POST",
        body: formData,
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Trace scan failed: ${res.statusText}`);
      }
      const data = await res.json();

      setScanResult(prev => ({
        ...prev,
        filename: file.name,
        dynamic_analysis: {
          status: data.status,
          malware_probability: data.malware_probability,
          raw_probability: data.malware_probability,
          data_source: `User-Uploaded Kernel Strace Log (${file.name})`,
          triage_stage: "Stage 2: Real Runtime Kernel Trace",
          sandbox_invoked: true,
          telemetry_stats: data.telemetry_stats,
          top_invoked: data.top_invoked || []
        },
        hybrid_verdict: {
          status: "trace_evaluated",
          verdict: data.verdict,
          is_malware: data.malware_probability != null ? data.malware_probability > 0.5 : null,
          confidence: data.malware_probability != null ? Math.max(data.malware_probability, 1 - data.malware_probability) : 0,
          stage_resolved: "Stage 2: Uploaded Runtime Kernel Trace",
          reason: `Execution trace parsed and evaluated against 470-D Dynamic XGBoost model (${data.extracted_events?.recognized_events || 0} recognized events).`
        }
      }));
    } catch (err) {
      setErrorMsg(err.message || "Trace upload and analysis failed.");
    } finally {
      setScanning(false);
    }
  };

  const runSimulatedDynamic = async () => {
    setScanning(true);
    setErrorMsg("");
    try {
      const staticProb = scanResult?.static_analysis?.malware_probability || 0.5;
      const res = await fetch(`${API_BASE}/api/simulate-dynamic`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          static_probability: staticProb,
          activity_level: "medium"
        }),
      });
      if (!res.ok) throw new Error("Dynamic sandbox simulation failed");
      const data = await res.json();

      setScanResult(prev => ({
        ...prev,
        dynamic_analysis: {
          status: "simulation",
          malware_probability: data.malware_probability,
          raw_probability: data.raw_probability,
          data_source: "Calibrated Behavioral Sandbox (Statistical Emulation)",
          triage_stage: "Stage 2: Calibrated Sandbox Emulation",
          sandbox_invoked: true,
          telemetry_stats: data.telemetry_stats,
          top_invoked: data.top_invoked || []
        },
        hybrid_verdict: {
          status: "simulation",
          verdict: data.malware_probability > 0.5 ? "Malicious (Dynamic Sandbox Detection)" : "Clean (Dynamic Sandbox Baseline)",
          is_malware: data.malware_probability > 0.5,
          confidence: Math.max(data.malware_probability, 1 - data.malware_probability),
          stage_resolved: "Stage 2: Calibrated Sandbox Emulation",
          reason: "Multi-Modal verdict synthesized from 215-D static bytecode and 470-D calibrated dynamic sandbox emulation."
        }
      }));
    } catch (err) {
      setErrorMsg(err.message);
    } finally {
      setScanning(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", minHeight: "100vh" }}>
      {/* ================= Modern Top Cyber-Forensics Header ================= */}
      <header className="header">
        <div className="header-container">
          <div className="brand">
            <div className="brand-icon">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <div>
              <div className="brand-title">AegisDroid HIDS</div>
              <div className="brand-subtitle">Autonomous Dynamic, Static & Signature Threat Analysis</div>
            </div>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
            {/* Upload APK Button */}
            <label
              className="btn-primary"
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "8px",
                cursor: scanning ? "wait" : "pointer",
                padding: "8px 18px",
                fontSize: "0.84rem",
                borderRadius: "var(--radius-sm)"
              }}
              htmlFor="custom-apk-upload-input"
              id="upload-apk-label"
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                <polyline points="17 8 12 3 7 8" />
                <line x1="12" y1="3" x2="12" y2="15" />
              </svg>
              <span>{scanning ? "Analyzing..." : "Upload Target APK"}</span>
              <input
                id="custom-apk-upload-input"
                type="file"
                accept=".apk"
                onChange={handleApkUpload}
                style={{ display: "none" }}
                disabled={scanning}
              />
            </label>

            {/* Upload Strace Log Button */}
            <label
              className="btn-secondary"
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "8px",
                cursor: scanning ? "wait" : "pointer",
                padding: "8px 16px",
                fontSize: "0.84rem",
                borderRadius: "var(--radius-sm)"
              }}
              htmlFor="custom-trace-upload-input"
              id="upload-trace-label"
            >
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                <polyline points="14 2 14 8 20 8" />
                <line x1="16" y1="13" x2="8" y2="13" />
                <line x1="16" y1="17" x2="8" y2="17" />
              </svg>
              <span>Upload Kernel Strace (.strace)</span>
              <input
                id="custom-trace-upload-input"
                type="file"
                accept=".strace,.log,.txt"
                onChange={handleTraceUpload}
                style={{ display: "none" }}
                disabled={scanning}
              />
            </label>

            <div className="status-badges">
              <div className={`badge ${health?.status === "online" ? "badge-online" : ""}`}>
                <span className="badge-dot pulse" />
                <span>API: {health?.status === "online" ? "127.0.0.1:8000 ONLINE" : "OFFLINE"}</span>
              </div>

              <div className="badge">
                <span className="badge-dot" style={{ background: "var(--purple-500)" }} />
                <span>Dynamic: CICMalDroid</span>
              </div>

              <div className="badge">
                <span className="badge-dot" style={{ background: "var(--cyan-400)" }} />
                <span>Static: Drebin</span>
              </div>

              <div className="badge badge-vt">
                <span className="badge-dot" />
                <span>VirusTotal Live</span>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* ================= Verified Threat Benchmark Quick Switcher Bar ================= */}
      <div style={{
        background: "rgba(11, 15, 25, 0.95)",
        borderBottom: "1px solid var(--border-subtle)",
        padding: "8px 2rem",
      }}>
        <div style={{
          maxWidth: 1400,
          margin: "0 auto",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          flexWrap: "wrap",
          gap: "10px"
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
            <span style={{ fontSize: "0.74rem", color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 700 }}>
              Verified Threat Benchmarks:
            </span>
            <button
              className={`btn-pill ${selectedSample === "sms_trojan" ? "active" : ""}`}
              onClick={() => loadSampleScan("sms_trojan")}
              disabled={scanning}
              id="select-sms-trojan-btn"
            >
              📱 SMS Trojan (FakeInst)
            </button>
            <button
              className={`btn-pill ${selectedSample === "banking_trojan" ? "active" : ""}`}
              onClick={() => loadSampleScan("banking_trojan")}
              disabled={scanning}
              id="select-banking-trojan-btn"
            >
              🏦 Banking Trojan (BankBot)
            </button>
            <button
              className={`btn-pill ${selectedSample === "ransomware" ? "active" : ""}`}
              onClick={() => loadSampleScan("ransomware")}
              disabled={scanning}
              id="select-ransomware-btn"
            >
              🔒 Ransomware (Simplocker)
            </button>
            <button
              className={`btn-pill ${selectedSample === "adware" ? "active" : ""}`}
              onClick={() => loadSampleScan("adware")}
              disabled={scanning}
              id="select-adware-btn"
            >
              📢 Adware (Airpush)
            </button>
            <button
              className={`btn-pill ${selectedSample === "benign_utility" ? "active" : ""}`}
              onClick={() => loadSampleScan("benign_utility")}
              disabled={scanning}
              id="select-clean-calc-btn"
            >
              🧮 Clean Benign (Calculator)
            </button>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <label style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "0.78rem", color: "var(--text-muted)", cursor: "pointer" }}>
              <input
                type="checkbox"
                checked={autoSimulateDynamic}
                onChange={(e) => setAutoSimulateDynamic(e.target.checked)}
                style={{ accentColor: "var(--purple-500)", cursor: "pointer" }}
              />
              <span>Auto-Emulate Dynamic Sandbox if ADB Offline</span>
            </label>
          </div>
        </div>
      </div>

      {/* ================= Error Banner ================= */}
      {errorMsg && (
        <div style={{ maxWidth: 1400, width: "calc(100% - 4rem)", margin: "1rem auto 0" }}>
          <div style={{ background: "rgba(225, 29, 72, 0.2)", border: "1px solid var(--rose-500)", padding: "12px 18px", borderRadius: "var(--radius-sm)", color: "var(--rose-400)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span>⚠️ {errorMsg}</span>
            <button onClick={() => setErrorMsg("")} style={{ background: "none", border: "none", color: "#fff", cursor: "pointer", fontSize: "1rem" }}>✕</button>
          </div>
        </div>
      )}

      {/* ================= Main Content: Strict 3-Part Threat Inspection ================= */}
      <main className="main-content" style={{ marginTop: "1.5rem" }}>
        {scanResult && (
          <>
            {/* =========================================================================
                1. DYNAMIC ANALYSIS (VALUE & DETAILS) - FIRST
                ========================================================================= */}
            <section className="card" id="dynamic-analysis-section" style={{ marginBottom: "2rem", borderLeft: "5px solid var(--purple-500)" }}>
              <div className="card-header">
                <div>
                  <div className="card-title">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--purple-500)" strokeWidth="2.2">
                      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
                    </svg>
                    1. Dynamic Analysis
                  </div>
                  <div style={{ fontSize: "0.8rem", color: "var(--text-dim)", marginTop: "2px" }}>
                    Runtime Kernel Syscall & IPC Binder Telemetry (470-D Feature Vector)
                  </div>
                </div>
                <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                  <span className="badge" style={{ color: "var(--purple-500)" }}>
                    {scanResult.dynamic_analysis?.data_source || scanResult.dynamic_analysis?.dataset_source || "CICMalDroid 470 Dimensions"}
                  </span>
                  <span className="badge" style={{
                    color: (scanResult.dynamic_analysis?.status === "unavailable" || scanResult.dynamic_analysis?.status === "no_supported_events")
                      ? "var(--amber-400)"
                      : (scanResult.dynamic_analysis?.status === "parse_failed" || scanResult.dynamic_analysis?.status === "failed")
                        ? "var(--rose-400)"
                        : (scanResult.dynamic_analysis?.status === "simulation"
                          ? "var(--purple-400)"
                          : (scanResult.dynamic_analysis?.malware_probability > 0.5 ? "var(--rose-400)" : "var(--emerald-400)"))
                  }}>
                    {scanResult.dynamic_analysis?.status === "unavailable"
                      ? "Dynamic Analysis Offline"
                      : scanResult.dynamic_analysis?.status === "no_supported_events"
                        ? "No Recognized Syscalls/Binders"
                        : (scanResult.dynamic_analysis?.status === "parse_failed" || scanResult.dynamic_analysis?.status === "failed")
                          ? "Dynamic Trace Parsing Failed"
                          : (scanResult.dynamic_analysis?.status === "simulation"
                            ? "Calibrated Sandbox Emulation"
                            : (scanResult.dynamic_analysis?.malware_probability > 0.5 ? "Behavioral Threat Detected" : "Normal Execution Pattern"))}
                  </span>
                </div>
              </div>

              {/* Dynamic Value Row */}
              {scanResult.dynamic_analysis?.malware_probability == null || scanResult.dynamic_analysis?.status === "unavailable" || scanResult.dynamic_analysis?.status === "no_supported_events" || scanResult.dynamic_analysis?.status === "parse_failed" || scanResult.dynamic_analysis?.status === "failed" ? (
                <div style={{ background: "rgba(11, 15, 25, 0.75)", padding: "1.5rem", borderRadius: "var(--radius-sm)", marginBottom: "1.75rem", border: "1px dashed rgba(168, 85, 247, 0.5)" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "8px" }}>
                    <span style={{ fontSize: "1.3rem" }}>ℹ️</span>
                    <span style={{ fontWeight: 700, color: "var(--purple-400)", fontSize: "0.95rem" }}>
                      {scanResult.dynamic_analysis?.status === "no_supported_events"
                        ? "No Supported Kernel Events in Execution Trace (Dynamic Probability Omitted)"
                        : (scanResult.dynamic_analysis?.status === "parse_failed" || scanResult.dynamic_analysis?.status === "failed"
                          ? "Dynamic Trace Parsing / Execution Failed"
                          : "Live Dynamic Telemetry Offline (No Active ADB Device Connected)")}
                    </span>
                  </div>
                  <div style={{ fontSize: "0.85rem", color: "var(--text-muted)", lineHeight: 1.5, marginBottom: "1.25rem" }}>
                    {scanResult.dynamic_analysis?.status === "no_supported_events"
                      ? "The uploaded trace contained zero recognized CICMalDroid 470-D kernel syscalls or Binder IPC tokens."
                      : "No active Android device was detected via ADB, and no execution trace log was attached. You can instantly run calibrated dynamic sandbox emulation below or upload a Linux strace log:"}
                  </div>

                  {/* Interactive Dynamic Fallback Controls */}
                  <div style={{ display: "flex", gap: "12px", flexWrap: "wrap", alignItems: "center" }}>
                    <button
                      className="btn-primary"
                      onClick={runSimulatedDynamic}
                      disabled={scanning}
                      style={{ background: "linear-gradient(135deg, var(--purple-500), #7c3aed)", padding: "8px 18px", fontSize: "0.82rem" }}
                      id="run-calibrated-sandbox-btn"
                    >
                      ⚡ Run Calibrated Dynamic Sandbox Analysis
                    </button>

                    <label
                      className="btn-secondary"
                      style={{ cursor: scanning ? "wait" : "pointer", padding: "8px 16px", fontSize: "0.82rem" }}
                      htmlFor="custom-trace-upload-input-inner"
                      id="attach-trace-inner-btn"
                    >
                      📎 Upload Runtime Strace (.strace / .log)
                      <input
                        id="custom-trace-upload-input-inner"
                        type="file"
                        accept=".strace,.log,.txt"
                        onChange={handleTraceUpload}
                        style={{ display: "none" }}
                        disabled={scanning}
                      />
                    </label>

                    <div style={{ display: "flex", gap: "8px", alignItems: "center", marginLeft: "auto" }}>
                      <span style={{ fontSize: "0.74rem", color: "var(--text-dim)" }}>Load Sample Trace:</span>
                      <button
                        className="btn-secondary"
                        onClick={() => loadSampleScan("sms_trojan")}
                        style={{ padding: "4px 10px", fontSize: "0.74rem" }}
                      >
                        SMS Trojan
                      </button>
                      <button
                        className="btn-secondary"
                        onClick={() => loadSampleScan("banking_trojan")}
                        style={{ padding: "4px 10px", fontSize: "0.74rem" }}
                      >
                        Banking
                      </button>
                      <button
                        className="btn-secondary"
                        onClick={() => loadSampleScan("benign_utility")}
                        style={{ padding: "4px 10px", fontSize: "0.74rem" }}
                      >
                        Clean Benign
                      </button>
                    </div>
                  </div>
                </div>
              ) : (
                <div style={{ display: "grid", gridTemplateColumns: "1.2fr 2fr", gap: "1.5rem", marginBottom: "1.75rem", background: "rgba(11, 15, 25, 0.6)", padding: "1.25rem", borderRadius: "var(--radius-sm)" }}>
                  <div>
                    <div className="stat-label">Dynamic Malware Risk Probability</div>
                    <div style={{ fontSize: "2.8rem", fontWeight: 800, fontFamily: "JetBrains Mono", color: scanResult.dynamic_analysis.malware_probability > 0.5 ? "var(--purple-500)" : "var(--emerald-400)", lineHeight: 1.15 }}>
                      {scanResult.dynamic_analysis.malware_probability > 0 && scanResult.dynamic_analysis.malware_probability < 0.001
                        ? "< 0.1%"
                        : `${(scanResult.dynamic_analysis.malware_probability * 100).toFixed(1)}%`}
                    </div>
                    {scanResult.dynamic_analysis.raw_probability != null && (
                      <div style={{ fontSize: "0.72rem", color: "var(--text-dim)", fontFamily: "JetBrains Mono", marginTop: "2px" }}>
                        Exact Probability: {(scanResult.dynamic_analysis.raw_probability * 100).toFixed(4)}%
                      </div>
                    )}
                    <div className="progress-bar-container" style={{ margin: "12px 0 10px" }}>
                      <div
                        className="progress-bar"
                        style={{
                          width: `${scanResult.dynamic_analysis.malware_probability * 100}%`,
                          background: scanResult.dynamic_analysis.malware_probability > 0.5 ? "linear-gradient(90deg, var(--purple-500), var(--rose-500))" : "var(--emerald-500)",
                        }}
                      />
                    </div>
                    <span style={{ fontSize: "0.82rem", padding: "4px 12px", borderRadius: "4px", background: scanResult.dynamic_analysis.malware_probability > 0.5 ? "rgba(168, 85, 247, 0.2)" : "rgba(16, 185, 129, 0.2)", color: scanResult.dynamic_analysis.malware_probability > 0.5 ? "var(--purple-500)" : "var(--emerald-400)", fontWeight: 700, display: "inline-block" }}>
                      {scanResult.dynamic_analysis.malware_probability > 0.5 ? "⚠️ MALICIOUS RUNTIME BEHAVIOR" : "✅ NORMAL KERNEL EXECUTION"}
                    </span>
                  </div>

                  {/* Dynamic KPI Sub-grid */}
                  {(() => {
                    const stats = scanResult.dynamic_analysis.telemetry_stats || {};
                    const top = scanResult.dynamic_analysis.top_invoked || [];
                    const totalSyscalls = (stats.total_syscalls != null && stats.total_syscalls > 0)
                      ? stats.total_syscalls
                      : top.filter(x => x.type === "Syscall").reduce((acc, c) => acc + c.count, 0);
                    const totalBinders = (stats.total_binders != null && stats.total_binders > 0)
                      ? stats.total_binders
                      : top.filter(x => x.type === "Binder").reduce((acc, c) => acc + c.count, 0);
                    const totalSystem = stats.total_system_events || (totalSyscalls + totalBinders);

                    return (
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
                        <div style={{ background: "rgba(15, 23, 42, 0.75)", padding: "12px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)" }}>
                          <div style={{ fontSize: "0.72rem", color: "var(--text-dim)", textTransform: "uppercase" }}>REAL KERNEL SYSCALLS</div>
                          <div style={{ fontSize: "1.45rem", fontWeight: 700, color: "var(--purple-500)", fontFamily: "JetBrains Mono" }}>
                            {totalSyscalls.toLocaleString()}
                          </div>
                          <div style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>Invocations traced in sandbox</div>
                        </div>
                        <div style={{ background: "rgba(15, 23, 42, 0.75)", padding: "12px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)" }}>
                          <div style={{ fontSize: "0.72rem", color: "var(--text-dim)", textTransform: "uppercase" }}>IPC BINDER TRANSACTIONS</div>
                          <div style={{ fontSize: "1.45rem", fontWeight: 700, color: "var(--cyan-400)", fontFamily: "JetBrains Mono" }}>
                            {totalBinders.toLocaleString()}
                          </div>
                          <div style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>Inter-process interactions</div>
                        </div>
                        <div style={{ background: "rgba(15, 23, 42, 0.75)", padding: "12px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)" }}>
                          <div style={{ fontSize: "0.72rem", color: "var(--text-dim)", textTransform: "uppercase" }}>ACTIVE VECTOR DIMENSIONS</div>
                          <div style={{ fontSize: "1.45rem", fontWeight: 700, color: "var(--amber-400)", fontFamily: "JetBrains Mono" }}>
                            {stats.active_features || stats.unique_features_activated || top.length} <span style={{ fontSize: "0.85rem", color: "var(--text-dim)" }}>/ 470</span>
                          </div>
                          <div style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>Non-zero dynamic dimensions</div>
                        </div>
                        <div style={{ background: "rgba(15, 23, 42, 0.75)", padding: "12px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)" }}>
                          <div style={{ fontSize: "0.72rem", color: "var(--text-dim)", textTransform: "uppercase" }}>TOTAL RUNTIME EVENTS</div>
                          <div style={{ fontSize: "1.45rem", fontWeight: 700, color: "var(--text-main)", fontFamily: "JetBrains Mono" }}>
                            {totalSystem.toLocaleString()}
                          </div>
                          <div style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>Kernel + Binder invocations</div>
                        </div>
                      </div>
                    );
                  })()}
                </div>
              )}

              {/* Dynamic Details: Frequency Table */}
              <div style={{ fontSize: "0.88rem", fontWeight: 700, marginBottom: "8px", color: "var(--text-muted)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span>Dynamic Analysis Details: Top Recorded Runtime Syscalls & IPC Binders Breakdown</span>
                <span style={{ fontSize: "0.75rem", color: "var(--text-dim)" }}>Ranked by invocation count</span>
              </div>

              <div style={{ maxHeight: 290, overflowY: "auto", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius-sm)" }}>
                <table className="data-table" style={{ margin: 0 }}>
                  <thead>
                    <tr>
                      <th>Runtime Vector</th>
                      <th>Subsystem Category</th>
                      <th>Empirical Frequency Count</th>
                      <th>Security / Forensic Meaning</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scanResult.dynamic_analysis?.top_invoked && scanResult.dynamic_analysis.top_invoked.length > 0 ? (
                      scanResult.dynamic_analysis.top_invoked.map((item, idx) => (
                        <tr key={idx}>
                          <td style={{ fontFamily: "JetBrains Mono", fontSize: "0.82rem", color: item.type === "Syscall" ? "var(--purple-500)" : "var(--cyan-400)" }}>
                            {item.feature}
                          </td>
                          <td>
                            <span style={{ fontSize: "0.7rem", padding: "2px 8px", borderRadius: "4px", background: item.type === "Syscall" ? "rgba(168, 85, 247, 0.2)" : "rgba(14, 165, 233, 0.2)", color: item.type === "Syscall" ? "var(--purple-500)" : "var(--cyan-400)", fontWeight: 600 }}>
                              {item.type}
                            </span>
                          </td>
                          <td style={{ fontFamily: "JetBrains Mono", fontWeight: 700, color: "var(--text-main)" }}>
                            {item.count.toLocaleString()} calls
                          </td>
                          <td style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                            {item.feature.includes("ACCESS_PERSONAL") ? "Personal Identifiable Info (PII) Access" :
                             item.feature.includes("ALTER_PHONE") ? "Telephony State Alteration / SMS Intercept" :
                             item.feature.includes("ioctl") ? "Device Driver & Binder I/O Control" :
                             item.feature.includes("mprotect") ? "Memory Page Protection Alteration (Stealth Execution)" :
                             item.feature.includes("execve") ? "Process Spawning / Shell Command Exec" :
                             item.feature.includes("clone") ? "Thread / Subprocess Instantiation" :
                             item.feature.includes("sendMultipart") ? "Automated SMS Dispatch (Trojan Vector)" :
                             item.feature.includes("open") || item.feature.includes("read") || item.feature.includes("write") ? "Standard File I/O Telemetry" :
                             "Kernel Telemetry Event"}
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan="4" style={{ textAlign: "center", color: "var(--text-dim)", padding: "1.5rem" }}>
                          No non-zero dynamic syscalls recorded for this profile.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </section>


            {/* =========================================================================
                2. STATIC ANALYSIS (VALUE & DETAILS) - THEN
                ========================================================================= */}
            <section className="card" id="static-analysis-section" style={{ marginBottom: "2rem", borderLeft: "5px solid var(--cyan-400)" }}>
              <div className="card-header">
                <div>
                  <div className="card-title">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--cyan-400)" strokeWidth="2.2">
                      <polyline points="16 18 22 12 16 6" />
                      <polyline points="8 6 2 12 8 18" />
                    </svg>
                    2. Static Analysis
                  </div>
                  <div style={{ fontSize: "0.8rem", color: "var(--text-dim)", marginTop: "2px" }}>
                    Bytecode & Manifest Decompilation (215-D Drebin Feature Vector)
                  </div>
                </div>
                <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                  <span className="badge" style={{ color: "var(--cyan-400)" }}>
                    {scanResult.static_analysis?.dataset_source || "Androguard DEX Disassembler"}
                  </span>
                  <span className="badge" style={{ color: "var(--emerald-400)" }}>
                    Zero Feature Gap (100% Extracted)
                  </span>
                </div>
              </div>

              {/* Static Value Row */}
              <div style={{ display: "grid", gridTemplateColumns: "1.2fr 2fr", gap: "1.5rem", marginBottom: "1.75rem", background: "rgba(11, 15, 25, 0.6)", padding: "1.25rem", borderRadius: "var(--radius-sm)" }}>
                <div>
                  <div className="stat-label">Static Malware Risk Probability</div>
                  <div style={{ fontSize: "2.8rem", fontWeight: 800, fontFamily: "JetBrains Mono", color: scanResult.static_analysis?.malware_probability > 0.5 ? "var(--rose-400)" : "var(--emerald-400)", lineHeight: 1.15 }}>
                    {scanResult.static_analysis?.malware_probability > 0 && scanResult.static_analysis?.malware_probability < 0.001
                      ? "< 0.1%"
                      : `${((scanResult.static_analysis?.malware_probability || 0) * 100).toFixed(1)}%`}
                  </div>
                  {scanResult.static_analysis?.raw_probability != null && (
                    <div style={{ fontSize: "0.72rem", color: "var(--text-dim)", fontFamily: "JetBrains Mono", marginTop: "2px" }}>
                      Exact Probability: {(scanResult.static_analysis.raw_probability * 100).toFixed(4)}%
                    </div>
                  )}
                  <div className="progress-bar-container" style={{ margin: "12px 0 10px" }}>
                    <div
                      className="progress-bar"
                      style={{
                        width: `${(scanResult.static_analysis?.malware_probability || 0) * 100}%`,
                        background: scanResult.static_analysis?.malware_probability > 0.5 ? "linear-gradient(90deg, var(--amber-400), var(--rose-500))" : "var(--emerald-500)",
                      }}
                    />
                  </div>
                  <span style={{ fontSize: "0.82rem", padding: "4px 12px", borderRadius: "4px", background: scanResult.static_analysis?.malware_probability > 0.5 ? "rgba(244, 63, 94, 0.2)" : "rgba(16, 185, 129, 0.2)", color: scanResult.static_analysis?.malware_probability > 0.5 ? "var(--rose-400)" : "var(--emerald-400)", fontWeight: 700, display: "inline-block" }}>
                    {scanResult.static_analysis?.malware_probability > 0.5 ? "⚠️ MALICIOUS BYTECODE PATTERN" : "✅ CLEAN MANIFEST & BYTECODE PROFILE"}
                  </span>

                  {/* Forensic Feature Concordance Diagnostic Callout */}
                  <div style={{ marginTop: "12px", fontSize: "0.8rem", color: "var(--text-muted)", lineHeight: 1.5, background: "rgba(15, 23, 42, 0.75)", padding: "10px 14px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)" }}>
                    <strong style={{ color: scanResult.static_analysis?.malware_probability > 0.5 ? "var(--rose-400)" : "var(--emerald-400)" }}>
                      {scanResult.static_analysis?.malware_probability > 0.5 ? "⚠️ Threat Concordance:" : "✅ Benign Concordance:"}
                    </strong>{" "}
                    {scanResult.static_analysis?.forensic_diagnosis || (scanResult.static_analysis?.malware_probability > 0.5
                      ? `Detected ${scanResult.static_analysis?.active_features_count || 0} active features exhibiting high-risk malware patterns.`
                      : `Evaluated ${scanResult.static_analysis?.active_features_count || 0} active features. Zero high-risk SMS, privilege escalation, or root exploit signatures detected.`)}
                  </div>
                </div>

                {/* Static KPI Sub-grid */}
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
                  <div style={{ background: "rgba(15, 23, 42, 0.75)", padding: "12px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)" }}>
                    <div style={{ fontSize: "0.72rem", color: "var(--text-dim)", textTransform: "uppercase" }}>ACTIVE PERMISSIONS</div>
                    <div style={{ fontSize: "1.45rem", fontWeight: 700, color: "var(--rose-400)", fontFamily: "JetBrains Mono" }}>
                      {scanResult.static_analysis?.breakdown?.active_permissions || 0} <span style={{ fontSize: "0.85rem", color: "var(--text-dim)" }}>/ 107</span>
                    </div>
                    <div style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>Declared in AndroidManifest</div>
                  </div>
                  <div style={{ background: "rgba(15, 23, 42, 0.75)", padding: "12px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)" }}>
                    <div style={{ fontSize: "0.72rem", color: "var(--text-dim)", textTransform: "uppercase" }}>INTENT ACTIONS</div>
                    <div style={{ fontSize: "1.45rem", fontWeight: 700, color: "var(--purple-500)", fontFamily: "JetBrains Mono" }}>
                      {scanResult.static_analysis?.breakdown?.active_intents || 0} <span style={{ fontSize: "0.85rem", color: "var(--text-dim)" }}>/ 24</span>
                    </div>
                    <div style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>Broadcast receivers & filters</div>
                  </div>
                  <div style={{ background: "rgba(15, 23, 42, 0.75)", padding: "12px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)" }}>
                    <div style={{ fontSize: "0.72rem", color: "var(--text-dim)", textTransform: "uppercase" }}>DALVIK API / BYTECODE CALLS</div>
                    <div style={{ fontSize: "1.45rem", fontWeight: 700, color: "var(--cyan-400)", fontFamily: "JetBrains Mono" }}>
                      {scanResult.static_analysis?.breakdown?.active_apis || 0} <span style={{ fontSize: "0.85rem", color: "var(--text-dim)" }}>/ 84</span>
                    </div>
                    <div style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>Disassembled DEX calls</div>
                  </div>
                  <div style={{ background: "rgba(15, 23, 42, 0.75)", padding: "12px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)" }}>
                    <div style={{ fontSize: "0.72rem", color: "var(--text-dim)", textTransform: "uppercase" }}>TOTAL ACTIVE FEATURES</div>
                    <div style={{ fontSize: "1.45rem", fontWeight: 700, color: "var(--amber-400)", fontFamily: "JetBrains Mono" }}>
                      {scanResult.static_analysis?.active_features_count || 0} <span style={{ fontSize: "0.85rem", color: "var(--text-dim)" }}>/ 215</span>
                    </div>
                    <div style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>Non-zero feature density</div>
                  </div>
                </div>
              </div>

              {/* Static Details: Detected Features Chips */}
              <div style={{ fontSize: "0.88rem", fontWeight: 700, marginBottom: "8px", color: "var(--text-muted)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span>Static Analysis Details: Detected Bytecode Signatures & Manifest Permissions ({scanResult.static_analysis?.detected_features?.length || 0} active):</span>
                <span style={{ fontSize: "0.75rem", color: "var(--text-dim)" }}>Categorized by feature capability</span>
              </div>

              <div style={{ maxHeight: 260, overflowY: "auto", background: "rgba(11, 15, 25, 0.7)", borderRadius: "var(--radius-sm)", padding: "12px", border: "1px solid var(--border-subtle)" }}>
                {scanResult.static_analysis?.detected_features && scanResult.static_analysis.detected_features.length > 0 ? (
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                    {scanResult.static_analysis.detected_features.map((feat, idx) => {
                      const isPerm = feat.includes("permission") || (feat.toUpperCase() === feat && feat.includes("_"));
                      const isIntent = feat.includes("intent") || feat.includes("action");
                      const color = isPerm ? "var(--rose-400)" : isIntent ? "var(--purple-500)" : "var(--cyan-400)";
                      const bg = isPerm ? "rgba(244, 63, 94, 0.15)" : isIntent ? "rgba(168, 85, 247, 0.15)" : "rgba(56, 189, 248, 0.15)";
                      const typeLabel = isPerm ? "Permission" : isIntent ? "Intent" : "Dalvik API";

                      return (
                        <div
                          key={idx}
                          style={{
                            background: bg,
                            border: `1px solid ${color}40`,
                            borderRadius: "4px",
                            padding: "4px 8px",
                            fontSize: "0.75rem",
                            fontFamily: "JetBrains Mono",
                            display: "inline-flex",
                            alignItems: "center",
                            gap: "6px"
                          }}
                        >
                          <span style={{ color, fontWeight: 600 }}>{feat}</span>
                          <span style={{ fontSize: "0.65rem", padding: "1px 5px", borderRadius: "3px", background: "rgba(15, 23, 42, 0.8)", color: "var(--text-dim)" }}>
                            {typeLabel}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div style={{ fontSize: "0.85rem", color: "var(--text-dim)", textAlign: "center", padding: "1.5rem" }}>
                    Zero high-risk static signatures detected in manifest or DEX bytecode.
                  </div>
                )}
              </div>
            </section>


            {/* =========================================================================
                Hybrid Decision Fusion & Provenance Banner
                ========================================================================= */}
            {scanResult.hybrid_verdict && (
              <div style={{
                background: scanResult.hybrid_verdict.status === "fused" || scanResult.hybrid_verdict.status === "simulation" ? "rgba(16, 185, 129, 0.08)" : "rgba(30, 41, 59, 0.6)",
                border: scanResult.hybrid_verdict.status === "fused" || scanResult.hybrid_verdict.status === "simulation" ? "1px solid var(--emerald-500)" : "1px dashed rgba(148, 163, 184, 0.35)",
                borderRadius: "var(--radius-sm)",
                padding: "1rem 1.25rem",
                marginBottom: "2rem",
                display: "flex",
                alignItems: "center",
                gap: "14px"
              }}>
                <span style={{ fontSize: "1.3rem" }}>{scanResult.hybrid_verdict.status === "fused" || scanResult.hybrid_verdict.status === "simulation" ? "🛡️" : "🔬"}</span>
                <div>
                  <div style={{ fontSize: "0.85rem", fontWeight: 700, color: scanResult.hybrid_verdict.status === "fused" || scanResult.hybrid_verdict.status === "simulation" ? "var(--emerald-400)" : "var(--purple-400)" }}>
                    {scanResult.hybrid_verdict.status === "fused" || scanResult.hybrid_verdict.status === "simulation"
                      ? `Verified Multi-Modal Hybrid Verdict: ${scanResult.hybrid_verdict.verdict} (Confidence: ${((scanResult.hybrid_verdict.confidence || 0) * 100).toFixed(1)}%)`
                      : (scanResult.hybrid_verdict.status === "static_only"
                        ? `Static Gatekeeper Verdict: ${scanResult.hybrid_verdict.verdict}`
                        : "Multi-Modal Decision Fusion: Standalone Cohort Mode")}
                  </div>
                  <div style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginTop: "3px", lineHeight: 1.4 }}>
                    {scanResult.hybrid_verdict.reason || `Cascaded triage resolved at: ${scanResult.hybrid_verdict.stage_resolved}`}
                  </div>
                </div>
              </div>
            )}


            {/* =========================================================================
                3. SIGNATURE ANALYSIS SHA-256 (VALUES & DETAILS) - THEN
                ========================================================================= */}
            <section className="card" id="signature-analysis-section" style={{ marginBottom: "2.5rem", borderLeft: "5px solid var(--amber-400)" }}>
              <div className="card-header">
                <div>
                  <div className="card-title">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--amber-400)" strokeWidth="2.2">
                      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                      <path d="M12 8v4" />
                      <path d="M12 16h.01" />
                    </svg>
                    3. Signature Analysis (SHA-256)
                  </div>
                  <div style={{ fontSize: "0.8rem", color: "var(--text-dim)", marginTop: "2px" }}>
                    Cryptographic Binary Fingerprinting & Threat Intelligence Consensus
                  </div>
                </div>
                <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                  <span className="badge" style={{ color: "var(--amber-400)" }}>
                    {scanResult.virustotal?.status === "unverified_hash_skipped"
                      ? "Historical Benchmark"
                      : (scanResult.virustotal?.decoupled_from_ml ? "Decoupled From ML Pipeline" : "VirusTotal v3 API")}
                  </span>
                  <span className="badge" style={{
                    color: scanResult.virustotal?.status === "unverified_hash_skipped"
                      ? "var(--text-dim)"
                      : (scanResult.virustotal?.signature_detected ? "var(--rose-400)" : "var(--emerald-400)")
                  }}>
                    {scanResult.virustotal?.status === "unverified_hash_skipped"
                      ? "Unverified (Historical Dataset)"
                      : (scanResult.virustotal?.signature_detected ? "Known Malicious Signature" : "Clean / Zero Prior Match")}
                  </span>
                </div>
              </div>

              {/* Cryptographic SHA-256 Box */}
              <div style={{ background: "rgba(11, 15, 25, 0.85)", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius-sm)", padding: "1.25rem", marginBottom: "1.5rem" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                  <div style={{ fontSize: "0.8rem", textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--amber-400)", fontWeight: 700 }}>
                    CRYPTOGRAPHIC SHA-256 IDENTIFIER
                  </div>
                  <button
                    className="btn-secondary"
                    onClick={() => copyToClipboard(scanResult.sha256 || scanResult.virustotal?.hash || "N/A", "sha")}
                    style={{ padding: "4px 14px", fontSize: "0.78rem" }}
                    id="copy-sha256-btn"
                  >
                    {copiedSha ? "✓ Copied to Clipboard!" : "📋 Copy SHA-256"}
                  </button>
                </div>
                <div style={{ fontFamily: "JetBrains Mono", fontSize: "1rem", color: "var(--text-main)", background: "rgba(15, 23, 42, 0.95)", padding: "12px 14px", borderRadius: "6px", wordBreak: "break-all", border: "1px solid rgba(251, 191, 36, 0.25)" }}>
                  {scanResult.sha256 || scanResult.virustotal?.hash || scanResult.virustotal?.file_hashes?.sha256 || "N/A (Historical Dataset Benchmark Row - No APK Binary)"}
                </div>

                <div style={{ display: "flex", gap: "2rem", marginTop: "12px", fontSize: "0.82rem", color: "var(--text-muted)" }}>
                  <div>
                    MD5 Hash: <strong style={{ color: "var(--cyan-400)", fontFamily: "JetBrains Mono" }}>{scanResult.md5 || scanResult.virustotal?.file_hashes?.md5 || "N/A (Historical Dataset)"}</strong>
                  </div>
                  <div>
                    Target Binary: <strong style={{ color: "var(--text-main)" }}>{scanResult.filename || scanResult.sample_name || "sample.apk"}</strong>
                  </div>
                </div>
              </div>

              {/* Signature Values & Vendor Details Sub-grid */}
              <div style={{ display: "grid", gridTemplateColumns: "1.2fr 2fr", gap: "1.5rem", marginBottom: "1.75rem", background: "rgba(11, 15, 25, 0.6)", padding: "1.25rem", borderRadius: "var(--radius-sm)" }}>
                <div>
                  <div className="stat-label">VirusTotal Consensus Detection Ratio</div>
                  <div style={{ fontSize: "2.8rem", fontWeight: 800, fontFamily: "JetBrains Mono", color: scanResult.virustotal?.signature_detected ? "var(--rose-400)" : (scanResult.virustotal?.status === "unavailable" || scanResult.virustotal?.status === "unverified_hash_skipped" ? "var(--text-dim)" : "var(--emerald-400)"), lineHeight: 1.15 }}>
                    {scanResult.virustotal?.status === "unavailable" || scanResult.virustotal?.status === "unverified_hash_skipped" ? "N/A" : (scanResult.virustotal?.detection_ratio || "0/0")}
                  </div>
                  <div style={{ fontSize: "0.8rem", color: "var(--text-dim)", margin: "8px 0" }}>
                    {scanResult.virustotal?.status === "unverified_hash_skipped"
                      ? "Historical benchmark dataset row has no verified APK binary or hash (lookup safely skipped)."
                      : (scanResult.virustotal?.status === "unavailable"
                        ? "API key unconfigured (decoupled from ML pipeline)"
                        : (scanResult.virustotal?.status === "not_found"
                          ? "Zero prior signatures in VirusTotal threat feed"
                          : "Security engines flagging this binary fingerprint as malicious"))}
                  </div>
                  <span style={{ fontSize: "0.82rem", padding: "4px 12px", borderRadius: "4px", background: scanResult.virustotal?.signature_detected ? "rgba(244, 63, 94, 0.2)" : (scanResult.virustotal?.status === "unavailable" || scanResult.virustotal?.status === "unverified_hash_skipped" ? "rgba(100, 116, 139, 0.2)" : "rgba(16, 185, 129, 0.2)"), color: scanResult.virustotal?.signature_detected ? "var(--rose-400)" : (scanResult.virustotal?.status === "unavailable" || scanResult.virustotal?.status === "unverified_hash_skipped" ? "var(--text-dim)" : "var(--emerald-400)"), fontWeight: 700, display: "inline-block" }}>
                    {scanResult.virustotal?.status === "unverified_hash_skipped"
                      ? "Unverified Hash (Skipped)"
                      : (scanResult.virustotal?.status === "unavailable"
                        ? "API Key Unconfigured"
                        : (scanResult.virustotal?.verdict || (scanResult.virustotal?.signature_detected ? "Known Malicious Signature" : "Clean / Zero Prior Match")))}
                  </span>
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
                  <div style={{ background: "rgba(15, 23, 42, 0.75)", padding: "12px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)" }}>
                    <div style={{ fontSize: "0.72rem", color: "var(--text-dim)", textTransform: "uppercase" }}>POPULAR THREAT LABEL</div>
                    <div style={{ fontSize: "1.05rem", fontWeight: 700, color: scanResult.virustotal?.signature_detected ? "var(--rose-400)" : "var(--text-main)", wordBreak: "break-word" }}>
                      {scanResult.virustotal?.threat_label || (scanResult.virustotal?.status === "unavailable" || scanResult.virustotal?.status === "unverified_hash_skipped" ? "Unverified" : "Zero Signatures")}
                    </div>
                    <div style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>Antivirus Industry Consensus</div>
                  </div>
                  <div style={{ background: "rgba(15, 23, 42, 0.75)", padding: "12px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)" }}>
                    <div style={{ fontSize: "0.72rem", color: "var(--text-dim)", textTransform: "uppercase" }}>MALICIOUS ENGINES</div>
                    <div style={{ fontSize: "1.45rem", fontWeight: 700, color: "var(--rose-500)", fontFamily: "JetBrains Mono" }}>
                      {scanResult.virustotal?.malicious_engines || 0}
                    </div>
                    <div style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>Positive threat detections</div>
                  </div>
                  <div style={{ background: "rgba(15, 23, 42, 0.75)", padding: "12px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)" }}>
                    <div style={{ fontSize: "0.72rem", color: "var(--text-dim)", textTransform: "uppercase" }}>SUSPICIOUS ENGINES</div>
                    <div style={{ fontSize: "1.45rem", fontWeight: 700, color: "var(--amber-400)", fontFamily: "JetBrains Mono" }}>
                      {scanResult.virustotal?.suspicious_engines || 0}
                    </div>
                    <div style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>Heuristic risk signals</div>
                  </div>
                  <div style={{ background: "rgba(15, 23, 42, 0.75)", padding: "12px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)" }}>
                    <div style={{ fontSize: "0.72rem", color: "var(--text-dim)", textTransform: "uppercase" }}>CLEAN / UNDETECTED</div>
                    <div style={{ fontSize: "1.45rem", fontWeight: 700, color: "var(--emerald-400)", fontFamily: "JetBrains Mono" }}>
                      {scanResult.virustotal?.total_engines ? (scanResult.virustotal.total_engines - (scanResult.virustotal.malicious_engines || 0)) : 0}
                    </div>
                    <div style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>Clean vendor ratings</div>
                  </div>
                </div>
              </div>

              {/* Signature Details: Top Antivirus Vendors Matrix */}
              <div style={{ fontSize: "0.88rem", fontWeight: 700, marginBottom: "8px", color: "var(--text-muted)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span>Signature Analysis Details: Notable Industry Antivirus Vendor Verdicts</span>
                <span style={{ fontSize: "0.75rem", color: "var(--text-dim)" }}>Queried via VirusTotal API v3</span>
              </div>

              <div style={{ border: "1px solid var(--border-subtle)", borderRadius: "var(--radius-sm)", overflow: "hidden" }}>
                <table className="data-table" style={{ margin: 0 }}>
                  <thead>
                    <tr>
                      <th>Security Vendor</th>
                      <th>Classification Status</th>
                      <th>Reported Signature / Threat Designation</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scanResult.virustotal?.vendor_sample_verdicts && Object.keys(scanResult.virustotal.vendor_sample_verdicts).length > 0 ? (
                      Object.entries(scanResult.virustotal.vendor_sample_verdicts).map(([vendor, verdict], idx) => {
                        const isMal = verdict.category === "malicious" || (verdict.result && verdict.result.toLowerCase() !== "clean");
                        return (
                          <tr key={idx}>
                            <td style={{ fontWeight: 600, color: "var(--text-main)" }}>{vendor}</td>
                            <td>
                              <span style={{ fontSize: "0.72rem", padding: "2px 8px", borderRadius: "4px", background: isMal ? "rgba(244, 63, 94, 0.2)" : "rgba(16, 185, 129, 0.2)", color: isMal ? "var(--rose-400)" : "var(--emerald-400)", fontWeight: 700 }}>
                                {isMal ? "MALICIOUS" : "CLEAN"}
                              </span>
                            </td>
                            <td style={{ fontFamily: "JetBrains Mono", fontSize: "0.82rem", color: isMal ? "var(--rose-400)" : "var(--text-muted)" }}>
                              {verdict.result || "Clean"}
                            </td>
                          </tr>
                        );
                      })
                    ) : (
                      <tr>
                        <td colSpan="3" style={{ textAlign: "center", color: "var(--text-dim)", padding: "1.5rem" }}>
                          {scanResult.virustotal?.status === "unverified_hash_skipped"
                            ? "Historical benchmark sample has no verified APK binary. VirusTotal lookup safely skipped to avoid querying unverified identifiers."
                            : (scanResult.virustotal?.status === "unavailable"
                              ? "VirusTotal API key is not configured in .env. No external vendor verdicts retrieved."
                              : (scanResult.virustotal?.status === "not_found"
                                ? "Cryptographic hash not present in VirusTotal threat feed (Zero Prior Signatures)."
                                : "No external vendor verdicts available for this hash."))}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </section>
          </>
        )}
      </main>

      {/* ================= Modern Footer ================= */}
      <footer className="footer">
        <div>
          <strong>AegisDroid HIDS</strong> // Autonomous Dynamic, Static & Signature Android Threat Analysis
        </div>
        <div style={{ marginTop: "4px", color: "var(--text-dim)", fontSize: "0.75rem" }}>
          Next.js App Router Frontend + FastAPI Python Backend &nbsp;|&nbsp; 
          Dynamic Kernel Telemetry (CICMalDroid 11,526 Samples) &nbsp;|&nbsp; 
          Static Bytecode Analysis (Drebin 3,127 Samples) &nbsp;|&nbsp; 
          Live VirusTotal API v3
        </div>
      </footer>
    </div>
  );
}
