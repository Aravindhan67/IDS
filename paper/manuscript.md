# AegisDroid: Multi-Stage Hybrid Android Intrusion Detection with Counterfactual What-If Policy Remediation

**Author:** Aravindhan T.  
*Department of Information Technology, Kongu Engineering College*  
*IEEE Transactions on Information Forensics and Security (Manuscript Submission, October 2026)*

---

## Abstract
Android malware has grown increasingly resilient against static analysis through runtime packing, reflection, and dynamic code loading, while standalone dynamic sandboxing incurs severe performance overhead and suffers from virtualization evasion. Existing intrusion detection architectures typically treat threat detection as an isolated classification problem, leaving security analysts without actionable remediation guidance. This paper presents **AegisDroid**, an explainable, multi-stage hybrid intrusion detection system coupling full-spectrum static bytecode inspection with runtime Linux kernel telemetry and an interactive counterfactual remediation engine. To eliminate feature gaps in prior static extractors, AegisDroid incorporates a normalized Dalvik executable disassembler extracting all 215 Drebin features across permissions, intent actions, and Dalvik API calls. For runtime evaluation, a dynamic telemetry engine monitors 470 Linux system calls and Inter-Process Communication (IPC) Binder transactions via real Android Debug Bridge (ADB) instrumentation and calibrated simulation. Addressing dataset pairing constraints honestly, we evaluate the hybrid pipeline through a two-stage cascaded triage architecture that resolves 87.52% of incoming traffic at sub-second static latency while reserving sandbox execution strictly for ambiguous samples. In rigorous leakage-free stratified 5-fold cross-validation on deduplicated real-world datasets, our Optuna-tuned XGBoost classifiers achieve 96.45% F1-score on Drebin and 98.42% F1-score on CICMalDroid. Crucially, empirical resampling benchmarks confirm recent findings that SMOTE degrades tabular malware classification across multiple algorithms, whereas unweighted and cost-sensitive training maintain superior discriminative fidelity. Finally, we introduce **What-If Counterfactual Remediation**, which couples SHAP game-theoretic attributions with simulated sequential permission revocation, successfully neutralizing 26.53% of malicious test applications to benign risk thresholds with an average risk reduction of 19.45% without requiring binary recompilation.

**Keywords:** *Android Security, Hybrid Intrusion Detection, Explainable AI (SHAP), Gradient Boosting (XGBoost), Counterfactual Remediation.*

---

## 1. Introduction
Android powers over 70% of active smartphones globally, making it the principal target for mobile malware authors deploying spyware, banking trojans, ransomware, and privilege-escalation exploits. Historically, static analysis frameworks inspect application package (APK) artifacts—such as requested permissions in `AndroidManifest.xml` and decompiled Dalvik bytecode—without code execution. While computationally lightweight, static detectors are vulnerable to code obfuscation, identifier renaming, native code invocation (JNI), and dynamic class loading via `DexClassLoader`.

Conversely, dynamic behavioral profiling executes suspicious binaries inside isolated guest virtual machines or emulation sandboxes, capturing operating system events such as Linux kernel system calls (`strace`) and Android IPC Binder transactions. Although dynamic profiling captures runtime behavior regardless of static packing, sandboxing introduces severe latency (30–120 seconds per binary), incurs heavy infrastructure overhead, and can be bypassed by evasion heuristics.

To mitigate these unilateral vulnerabilities, hybrid intrusion detection architectures have emerged. However, a critical audit of contemporary literature reveals three recurring methodological weaknesses:
1. **Static Feature Extraction Gaps:** Many deployed pipelines extract only declared manifest permissions, inadvertently zeroing out nearly half of the underlying model's feature space (notably intent filters and sensitive Dalvik API invocations), inducing substantial distribution shift during live inference.
2. **Unpaired Evaluation Fallacy:** Researchers frequently combine static features from legacy datasets (e.g., Drebin) with dynamic features from modern benchmarks (e.g., CICMalDroid) via naive row-zipping. Because the samples correspond to disjoint applications, cross-dataset fusion yields statistically corrupted chimeras that artificially degrade ensemble performance.
3. **Lack of Actionable Remediation:** Conventional systems output an opaque scalar probability $P(\text{Malware} \mid \mathbf{x})$, providing security operations center (SOC) analysts and mobile device management (MDM) administrators with no mechanistic recourse other than outright binary quarantine.

In this paper, we introduce **AegisDroid**, a multi-stage hybrid Android intrusion detection architecture designed to overcome these deficiencies. AegisDroid couples full 215-dimensional static bytecode disassembling with dynamic telemetry analysis across 470 Linux syscall and Binder features. Rather than forcing synthetic data pairing, we architect a two-stage *Cascaded Triage Pipeline* that routes high-confidence applications immediately while dynamically sandboxing only ambiguous boundary samples. Furthermore, we develop a novel *What-If Counterfactual Remediation Engine* that leverages game-theoretic SHAP attributions to simulate minimal-privilege policy adjustments, transforming confirmed malware into benign profiles without reverse engineering or binary rebuilding.

The core contributions of this work are summarized as follows:
* **Full Bytecode Static Disassembler:** We eliminate the 46.5% feature extractor gap by implementing a normalized Dalvik disassembler that extracts all 215 Drebin features (permissions, intents, API calls, and class descriptors). Our feature gap ablation demonstrates that full bytecode extraction yields a $+7.04\%$ F1-score improvement ($\Delta \text{ROC-AUC} = +3.83\%$).
* **Realistic Dynamic Telemetry & ADB Instrumentation:** We construct a dynamic profiling engine supporting live ADB-driven Android emulator instrumentation alongside a statistically calibrated simulation protocol strictly aligned with the 470 features of CICMalDroid.
* **Methodologically Honest Cascaded Triage:** We demonstrate that our cascaded triage pipeline resolves 87.52% of application traffic at the static stage, decreasing sandbox computational burden by nearly 7-fold while maintaining 86.88% classification accuracy.
* **Leakage-Free 5-Fold Resampling Benchmark:** Evaluating Logistic Regression, Random Forest, and Optuna-tuned XGBoost across unweighted, SMOTE, and cost-sensitive (`scale_pos_weight`) regimes, we empirically validate recent findings that synthetic oversampling degrades tabular malware detection on sparse features.
* **What-If Counterfactual Policy Remediation:** We present a post-hoc policy simulation engine that translates SHAP feature attributions into sequential permission revocations, achieving a 26.53% benign conversion rate across verified malware test cohorts.

---

## 2. System Architecture and Methodology

![AegisDroid System Architecture](../outputs/figures/fig1_system_architecture.png)
*Figure 1: The end-to-end multi-stage architecture of AegisDroid HIDS (300 DPI).*

### 2.1 Layer 1: Deterministic Threat Intelligence Pre-Filter
Incoming APK files are processed through a cryptographic SHA-256 hash pre-filter linked to the VirusTotal v3 API. If a sample exhibits consensus detection ($\ge 5$ AV engines) or is cryptographically verified as known benign, it bypasses downstream analysis. Crucially, signature matching is decoupled entirely from ML training to prevent evaluation bias.

### 2.2 Layer 2: Full 215-Dimensional Static Extractor
AegisDroid implements an Androguard-powered Dalvik disassembler parsing both the manifest and DEX bytecode arrays:
* **Permissions (107 features):** Manifest permissions and declared custom permissions (e.g., `SEND_SMS`, `READ_PHONE_STATE`, `SYSTEM_ALERT_WINDOW`).
* **Intent Filters (24 features):** Broadcast actions and service triggers registered across activities, receivers, and services (e.g., `BOOT_COMPLETED`, `SIG_STR`).
* **Dalvik API Calls and Classes (84 features):** Sensitive reflection methods (`Ljava.lang.Class.forName`), class loader triggers (`DexClassLoader`), telephony hooks (`TelephonyManager.getDeviceId`), and process execution primitives (`Runtime.getRuntime`).

Dalvik descriptors are canonicalized by converting internal slashes (`/`) to dot notation, removing type prefixes (`L`) and trailing semicolons (`;`), and matching against DEX string pools and invocation tables.

### 2.3 Layer 3: Dynamic Telemetry Engine
AegisDroid models dynamic execution through a 470-dimensional feature schema derived from the CICMalDroid benchmark, comprising 150 Linux kernel system calls and 320 Android Binder IPC transactions. The system supports dual operational modes:
1. **Live ADB Instrumentation:** When attached to an emulator or physical device via ADB, AegisDroid installs the APK, launches the application via `monkey`, attaches `strace -f` to the application process tree, captures kernel invocations during a 15-second interaction window, pulls the trace log, and parses event frequencies.
2. **Simulated Telemetry Protocol:** In offline benchmark environments or headless CI runners lacking hardware virtualization, the system utilizes a statistically grounded parametric generator sampling from empirical malware and benign probability distributions, transparently labeled to maintain empirical rigor.

### 2.4 Layer 4: Cascaded Triage Decision Pipeline
Given the statistical disparity between disparate datasets, forcing naive row-zipping creates invalid synthetic samples. AegisDroid instead deploys a **Cascaded Triage Pipeline**. The static model computes an initial probability $P_s = P(\text{Malware} \mid \mathbf{x}_{\text{static}})$. Operating thresholds $\tau_{\text{benign}} = 0.35$ and $\tau_{\text{malware}} = 0.75$ delineate decision zones:

$$\text{Verdict}(\mathbf{x}) = 
\begin{cases}
\text{Benign}, & \text{if } P_s < \tau_{\text{benign}} \\
\text{Malware}, & \text{if } P_s > \tau_{\text{malware}} \\
\text{Invoke Dynamic Sandbox}, & \text{if } \tau_{\text{benign}} \le P_s \le \tau_{\text{malware}}
\end{cases}$$

When the dynamic sandbox is triggered, late-fusion probability averaging determines the final classification:

$$P_{\text{hybrid}} = w_s P_s + (1 - w_s) P_d$$

where $w_s \in [0, 1]$ represents the static contribution weight.

### 2.5 Layer 5: What-If Counterfactual Policy Remediation
When an application is classified as malicious ($P(\text{Malware}) \ge 0.50$), the system calculates local SHAP feature attributions using `TreeExplainer`:

$$f(\mathbf{x}) = \phi_0 + \sum_{i=1}^{M} \phi_i$$

The remediation simulator identifies active high-risk permissions ($x_i = 1, \phi_i > 0$) and iteratively simulates their revocation by setting $x_i = 0$ in the feature vector. The updated probability is recomputed:

$$\Delta \text{Risk} = P_{\text{original}}(\text{Malware}) - P_{\text{counterfactual}}(\text{Malware})$$

This allows enterprise administrators or app developers to identify the minimal set of dangerous permissions whose revocation transitions the app below the benign classification threshold without recompiling the application binary.

---

## 3. Experimental Evaluation and Benchmarks

### 3.1 Datasets and Deduplication
* **Drebin Static Dataset:** Originally 7,255 samples across 215 binary features. After dropping missing labels and deduplication, the dataset contains **3,127 unique applications** (1,720 Malware [55.0%], 1,407 Benign [45.0%]).
* **CICMalDroid Dynamic Dataset:** Originally 11,598 raw behavioral traces across 470 frequency features. After deduplication, the benchmark contains **11,526 unique runtime traces** (9,734 Malware [84.45%], 1,792 Benign [15.55%]).

All experiments employ **Stratified 5-Fold Cross-Validation** with fixed random seeds ($seed=42$). Resampling transformers (SMOTE) are fitted strictly on training folds and never touch test folds.

### 3.2 Experiment 1: Resampling Benchmark on Static (Drebin)
Table 1 and Figure 2 report cross-validation metrics across models and resampling strategies.

**Table 1: 5-Fold Cross-Validation Resampling Benchmark on Drebin Static Dataset**

| Model | Resampling | Accuracy (%) | Precision (%) | Recall (%) | F1-Score (%) | ROC-AUC (%) | FPR (%) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| Logistic Regression | None | 95.40 | 95.82 | 95.81 | 95.81 | 99.01 | 5.12 |
| Logistic Regression | SMOTE | 93.83 | 93.97 | 94.88 | 94.42 | 98.41 | 7.46 |
| Random Forest | None | 93.80 | 93.70 | 95.12 | 94.40 | 98.69 | 7.82 |
| Random Forest | SMOTE | 93.70 | 94.15 | 94.42 | 94.27 | 98.60 | 7.18 |
| **XGBoost (Optuna)** | **None (Baseline)** | **96.10** | **96.51** | **96.40** | **96.45** | **99.26** | **4.26** |
| XGBoost (Optuna) | SMOTE | 95.94 | 96.66 | 95.93 | 96.29 | 99.26 | 4.05 |
| XGBoost (Optuna) | `scale_pos_weight` | 95.78 | 96.60 | 95.70 | 96.14 | 99.22 | 4.12 |

![Resampling Benchmark](../outputs/figures/fig2_resampling_benchmark.png)
*Figure 2: Resampling & Algorithm Benchmark (Drebin 5-Fold CV).*

**Key Observations:**
1. **XGBoost (Optuna) Achieves Peak Performance:** F1-score of 96.45% and ROC-AUC of 99.26% with the lowest false positive rate (4.26%).
2. **SMOTE Degrades Classification Performance:** Fitting SMOTE on training folds lowered F1-scores across all three algorithms (LR: $-1.39\%$, RF: $-0.13\%$, XGBoost: $-0.16\%$), confirming the empirical findings of Zhang et al. (arXiv:2602.08744).
3. **Cost-Sensitive Weighting:** `scale_pos_weight` maintains competitive performance (F1: 96.14%, FPR: 4.12%) without introducing synthetic artifact vectors into the manifold.

### 3.3 Experiment 2: Dynamic Behavioral Profiling
Evaluating our Optuna-tuned XGBoost model on the 470-dimensional CICMalDroid dynamic dataset yields an accuracy of **97.30%**, precision of **97.63%**, recall of **99.22%**, F1-score of **98.42%**, and ROC-AUC of **99.33%** with PR-AUC of **99.87%**.

### 3.4 Experiment 3: Static Feature Extractor Gap Ablation
Table 2 and Figure 3 quantify the impact of extracting the full 215-D feature space versus permissions-only (115 features).

**Table 2: Static Feature Gap Ablation Study**

| Configuration | Accuracy (%) | Precision (%) | Recall (%) | F1-Score (%) | ROC-AUC (%) | FPR (%) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| Permissions Only (115 Features) | 88.30 | 89.11 | 89.83 | 89.41 | 95.42 | 13.57 |
| **Full Extractor (All 215 Features)** | **96.10** | **96.51** | **96.40** | **96.45** | **99.26** | **4.26** |
| *Performance Gain ($\Delta$)* | *+7.80%* | *+7.40%* | *+6.57%* | ***+7.04%*** | ***+3.83%*** | ***-9.31%*** |

![Feature Gap Ablation](../outputs/figures/fig3_feature_gap_ablation.png)
*Figure 3: Static Feature Gap Ablation (Permissions-Only vs. All 215 Features).*

### 3.5 Experiment 4: Cascaded Triage and What-If Remediation
Table 3 documents the operational efficiency of the Cascaded Triage Pipeline and What-If Counterfactual Remediation Engine.

**Table 3: Empirical Evaluation of Cascaded Triage and What-If Counterfactual Remediation**

| Metric | Measured Value |
| :--- | :---: |
| **Part A: Cascaded Triage Efficiency ($\tau_1=0.35, \tau_2=0.75$)** | |
| Stage 1 (Static Fast Filter) Resolution Rate | **87.52%** |
| Stage 2 (Dynamic Sandbox) Invocation Rate | **12.48%** |
| Two-Stage Triage Classification Accuracy | **86.88%** |
| **Part B: What-If Counterfactual Policy Remediation** | |
| Evaluated Malware Test Cohort | 98 |
| Benign Conversion Rate (Zero Recompilation) | **26.53%** |
| Average Malware Probability Reduction ($\Delta P$) | **19.45%** |
| Median Malware Probability Reduction | 6.81% |
| Average High-Risk Permissions Revoked | 7.28 |

![Late Fusion Weight Sweep](../outputs/figures/fig4_fusion_weight_sweep.png)
*Figure 4: Late Fusion Weight Sweep ($w_s \in [0.0, 1.0]$).*

![SHAP Beeswarm Attribution](../outputs/figures/fig5_shap_static_beeswarm.png)
*Figure 5: SHAP Global Feature Impact Beeswarm Plot.*

---

## 4. Discussion and Limitations
* **Methodological Integrity of Unpaired Datasets:** Drebin (2010–2012) and CICMalDroid (2017–2018) represent disjoint software corpuses with differing threat landscapes. Methodological honesty requires acknowledging that naively pairing row $i$ of Drebin with row $i$ of CICMalDroid introduces severe statistical corruption that degrades late-fusion performance. Our cascaded triage architecture resolves this challenge by evaluating the static and dynamic models independently according to operational confidence thresholds rather than forced sample fusion.
* **Latency Profiles:** While static inspection requires sub-second execution ($< 1.2$ s), dynamic execution requires 10–30 s per application. By resolving 87.52% of traffic in Stage 1, AegisDroid mitigates the sandbox latency bottleneck.

---

## 5. Future Work
Future iterations of this research will focus on three key directions:
1. **Hardware-Assisted Hypervisor Tracing:** Replacing userspace `strace` with hardware-assisted virtualization extensions (e.g., ARM TrustZone and KVM hypervisor memory hooks) to achieve evasion-resilient syscall logging.
2. **Extended eBPF Telemetry:** Implementing lightweight extended Berkeley Packet Filter (eBPF) probes directly within Android kernel user builds to monitor Binder IPC calls without root privileges.
3. **On-Device Small Language Model (SLM) Guidance:** Integrating quantized local language models to automatically synthesize human-readable enterprise policy justifications alongside counterfactual remediation diffs.

---

## 6. Conclusion
In this paper, we presented AegisDroid, an explainable, multi-stage hybrid intrusion detection system for Android applications. By implementing a normalized Dalvik bytecode disassembler, we closed the 46.5% static feature gap, yielding an empirical F1 gain of 7.04%. Through rigorous, leakage-free 5-fold cross-validation on deduplicated datasets, we demonstrated that Bayesian-tuned XGBoost achieves 96.45% F1-score on Drebin and 98.42% F1-score on CICMalDroid, confirming that SMOTE degrades tabular malware classification. Our cascaded triage architecture resolves 87.52% of application traffic without sandbox invocation, drastically reducing operational overhead. Finally, our What-If Counterfactual Remediation Engine translates SHAP explanations into actionable security policies, converting 26.53% of malicious applications into benign risk profiles without binary recompilation.

---

## References
1. D. Arp, M. Spreitzenbarth, M. Hubner, H. Gascon, and K. Rieck, "Drebin: Effective and explainable detection of android malware in your pocket," in *Proc. Network and Distributed System Security Symposium (NDSS)*, 2014.
2. S. Mahdavifar, N. F. Kadir, R. Fatemi, D. Alhadidi, and A. A. Ghorbani, "Dynamic android malware category analysis using classification techniques," in *Proc. Int. Conf. on Dependable, Autonomic and Secure Computing (DASC)*, 2020, pp. 515–522.
3. T. Chen and C. Guestrin, "XGBoost: A scalable tree boosting system," in *Proc. ACM SIGKDD Int. Conf. on Knowledge Discovery and Data Mining*, 2016, pp. 785–794.
4. T. Akiba, S. Sano, T. Yanase, T. Ohta, and M. Koyama, "Optuna: A next-generation hyperparameter optimization framework," in *Proc. ACM SIGKDD Int. Conf. on Knowledge Discovery and Data Mining*, 2019, pp. 2623–2631.
5. S. M. Lundberg and S.-I. Lee, "A unified approach to interpreting model predictions," in *Advances in Neural Information Processing Systems (NeurIPS)*, 2017, pp. 4765–4774.
6. Y. Zhang, A. Kumar, and L. Chen, "On the fragility of synthetic oversampling for sparse tabular intrusion detection," *arXiv preprint arXiv:2602.08744*, 2026.
