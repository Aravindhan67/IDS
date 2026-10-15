"""
Paper Artifacts Generator: 300 DPI Visualizations and LaTeX Tables
Hybrid Android APK Intrusion Detection System (HIDS)
"""

import os
import json
import logging
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Modern academic styling
plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
plt.rcParams.update({
    "font.family": "serif",
    "font.size": 11,
    "axes.labelsize": 12,
    "axes.titlesize": 13,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "legend.fontsize": 10,
    "figure.titlesize": 14
})


def generate_all_artifacts(
    results_path: str = "c:/ids/outputs/results.json",
    fig_dir: str = "c:/ids/outputs/figures",
    tbl_dir: str = "c:/ids/outputs/tables"
):
    os.makedirs(fig_dir, exist_ok=True)
    os.makedirs(tbl_dir, exist_ok=True)
    
    with open(results_path, "r") as f:
        res = json.load(f)
        
    logger.info("Loaded results from %s. Generating 300 DPI figures...", results_path)

    # =========================================================================
    # FIGURE 2: Resampling Benchmark (EXP 1)
    # =========================================================================
    exp1 = res["EXP1_Static_Resampling_Benchmark"]
    models = ["Logistic_Regression", "Random_Forest", "XGBoost_Optuna"]
    labels = ["LR", "RF", "XGBoost"]
    
    f1_none = [next(r["f1_score"] for r in exp1 if r["model"] == m and r["resampling"] == "None") for m in models]
    f1_smote = [next(r["f1_score"] for r in exp1 if r["model"] == m and r["resampling"] == "SMOTE") for m in models]
    
    # scale_pos_weight is for XGBoost only
    f1_spw = next(r["f1_score"] for r in exp1 if r["model"] == "XGBoost_Optuna" and r["resampling"] == "scale_pos_weight")
    
    x = np.arange(len(labels))
    width = 0.28
    
    fig, ax = plt.subplots(figsize=(8, 5), dpi=300)
    rects1 = ax.bar(x - width/2, [round(v*100, 2) for v in f1_none], width, label="Baseline (None)", color="#2b5c8f", edgecolor="black")
    rects2 = ax.bar(x + width/2, [round(v*100, 2) for v in f1_smote], width, label="SMOTE (Train Only)", color="#d95f02", edgecolor="black")
    
    # Add single bar for scale_pos_weight on XGBoost
    ax.bar(2 + width*1.5, round(f1_spw*100, 2), width, label="scale_pos_weight", color="#2ca02c", hatch="//", edgecolor="black")
    
    ax.set_ylabel("F1-Score (%)")
    ax.set_title("Resampling & Algorithm Benchmark (Drebin 5-Fold CV)", pad=12)
    ax.set_xticks([0, 1, 2 + width*0.5])
    ax.set_xticklabels(["Logistic Regression", "Random Forest", "XGBoost (Optuna)"])
    ax.set_ylim(90, 98)
    ax.legend(loc="lower right")
    
    # Label bars
    for rect in rects1:
        h = rect.get_height()
        ax.annotate(f"{h:.1f}%", xy=(rect.get_x() + rect.get_width() / 2, h), xytext=(0, 3),
                    textcoords="offset points", ha="center", va="bottom", fontsize=9)
    for rect in rects2:
        h = rect.get_height()
        ax.annotate(f"{h:.1f}%", xy=(rect.get_x() + rect.get_width() / 2, h), xytext=(0, 3),
                    textcoords="offset points", ha="center", va="bottom", fontsize=9)
                    
    plt.tight_layout()
    f2_path = os.path.join(fig_dir, "fig2_resampling_benchmark.png")
    plt.savefig(f2_path, dpi=300)
    plt.close()
    logger.info("Saved Figure 2 to %s", f2_path)

    # =========================================================================
    # FIGURE 3: Feature Gap Ablation (EXP 3)
    # =========================================================================
    exp3 = res["EXP3_Feature_Gap_Ablation"]
    metrics_names = ["Accuracy", "F1-Score", "ROC-AUC"]
    full_vals = [
        exp3["Full_215_Features"]["accuracy"] * 100,
        exp3["Full_215_Features"]["f1_score"] * 100,
        exp3["Full_215_Features"]["roc_auc"] * 100
    ]
    perm_vals = [
        exp3["Permissions_Only_115_Features"]["accuracy"] * 100,
        exp3["Permissions_Only_115_Features"]["f1_score"] * 100,
        exp3["Permissions_Only_115_Features"]["roc_auc"] * 100
    ]
    
    x3 = np.arange(len(metrics_names))
    width3 = 0.35
    
    fig, ax = plt.subplots(figsize=(7.5, 4.8), dpi=300)
    r1 = ax.bar(x3 - width3/2, perm_vals, width3, label="115 Permissions-Only (Flawed Extractor)", color="#e7298a", edgecolor="black")
    r2 = ax.bar(x3 + width3/2, full_vals, width3, label="All 215 Features (Full Bytecode + Intents)", color="#1b9e77", edgecolor="black")
    
    ax.set_ylabel("Score (%)")
    ax.set_title("Static Feature Gap Ablation (Reviewer 2 Point 4 Resolution)", pad=12)
    ax.set_xticks(x3)
    ax.set_xticklabels(metrics_names)
    ax.set_ylim(85, 101)
    ax.legend(loc="upper left")
    
    for rect in r1:
        h = rect.get_height()
        ax.annotate(f"{h:.1f}%", xy=(rect.get_x() + rect.get_width() / 2, h), xytext=(0, 3),
                    textcoords="offset points", ha="center", va="bottom", fontsize=9)
    for rect in r2:
        h = rect.get_height()
        ax.annotate(f"{h:.1f}%", xy=(rect.get_x() + rect.get_width() / 2, h), xytext=(0, 3),
                    textcoords="offset points", ha="center", va="bottom", fontsize=9, fontweight="bold")
                    
    plt.tight_layout()
    f3_path = os.path.join(fig_dir, "fig3_feature_gap_ablation.png")
    plt.savefig(f3_path, dpi=300)
    plt.close()
    logger.info("Saved Figure 3 to %s", f3_path)

    # =========================================================================
    # FIGURE 4: Late Fusion Weight Sweep (EXP 5)
    # =========================================================================
    exp5 = res["EXP5_Fusion_Weight_Sweep"]
    ws = [item["w_static"] for item in exp5]
    f1_sweep = [item["f1_score"] * 100 for item in exp5]
    auc_sweep = [item["roc_auc"] * 100 for item in exp5]
    
    fig, ax1 = plt.subplots(figsize=(8, 4.8), dpi=300)
    color = "#1f77b4"
    ax1.set_xlabel("Static Model Weight (w_s)")
    ax1.set_ylabel("F1-Score (%)", color=color)
    line1 = ax1.plot(ws, f1_sweep, color=color, marker="o", linewidth=2.2, label="F1-Score")
    ax1.tick_params(axis="y", labelcolor=color)
    
    ax2 = ax1.twinx()
    color2 = "#2ca02c"
    ax2.set_ylabel("ROC-AUC (%)", color=color2)
    line2 = ax2.plot(ws, auc_sweep, color=color2, marker="s", linestyle="--", linewidth=2.2, label="ROC-AUC")
    ax2.tick_params(axis="y", labelcolor=color2)
    
    lines = line1 + line2
    labels = [l.get_label() for l in lines]
    ax1.legend(lines, labels, loc="center right")
    plt.title("Late Fusion Weight Sweep (w_s vs. w_d)", pad=12)
    
    plt.tight_layout()
    f4_path = os.path.join(fig_dir, "fig4_fusion_weight_sweep.png")
    plt.savefig(f4_path, dpi=300)
    plt.close()
    logger.info("Saved Figure 4 to %s", f4_path)

    # =========================================================================
    # LaTeX Tables Generation
    # =========================================================================
    # Table 1: Benchmark
    t1_code = r"""\begin{table}[t]
\centering
\caption{5-Fold Cross-Validation Resampling Benchmark on Drebin Static Dataset}
\label{tab:resampling_benchmark}
\begin{tabular}{llccccc}
\hline
\textbf{Model} & \textbf{Resampling} & \textbf{Accuracy (\%)} & \textbf{Precision (\%)} & \textbf{Recall (\%)} & \textbf{F1 (\%)} & \textbf{ROC-AUC (\%)} \\
\hline
"""
    for r in exp1:
        m_disp = r["model"].replace("_", " ")
        t1_code += f"{m_disp} & {r['resampling']} & {r['accuracy']*100:.2f} & {r['precision']*100:.2f} & {r['recall']*100:.2f} & {r['f1_score']*100:.2f} & {r['roc_auc']*100:.2f} \\\\\n"
    t1_code += r"""\hline
\end{tabular}
\end{table}
"""
    t1_path = os.path.join(tbl_dir, "table1_resampling_benchmark.tex")
    with open(t1_path, "w") as f:
        f.write(t1_code)
        
    # Table 2: Feature Gap & Mock Ablations
    t2_code = r"""\begin{table}[t]
\centering
\caption{Ablation Studies Addressing Reviewer 2 Methodological Points}
\label{tab:ablations}
\begin{tabular}{lccccc}
\hline
\textbf{Configuration} & \textbf{Accuracy (\%)} & \textbf{Precision (\%)} & \textbf{Recall (\%)} & \textbf{F1 (\%)} & \textbf{ROC-AUC (\%)} \\
\hline
\multicolumn{6}{l}{\textbf{Static Feature Extractor Gap (Reviewer 2, Point 4)}} \\
"""
    p_acc = exp3['Permissions_Only_115_Features']['accuracy']*100
    p_prec = exp3['Permissions_Only_115_Features']['precision']*100
    p_rec = exp3['Permissions_Only_115_Features']['recall']*100
    p_f1 = exp3['Permissions_Only_115_Features']['f1_score']*100
    p_auc = exp3['Permissions_Only_115_Features']['roc_auc']*100
    
    f_acc = exp3['Full_215_Features']['accuracy']*100
    f_prec = exp3['Full_215_Features']['precision']*100
    f_rec = exp3['Full_215_Features']['recall']*100
    f_f1 = exp3['Full_215_Features']['f1_score']*100
    f_auc = exp3['Full_215_Features']['roc_auc']*100
    
    d_f1 = exp3['Delta_F1']*100
    d_auc = exp3['Delta_ROC_AUC']*100

    t2_code += f"Permissions Only (115 Features) & {p_acc:.2f} & {p_prec:.2f} & {p_rec:.2f} & {p_f1:.2f} & {p_auc:.2f} \\\\\n"
    t2_code += f"Full Extractor (All 215 Features) & \\textbf{{{f_acc:.2f}}} & \\textbf{{{f_prec:.2f}}} & \\textbf{{{f_rec:.2f}}} & \\textbf{{{f_f1:.2f}}} & \\textbf{{{f_auc:.2f}}} \\\\\n"
    t2_code += f"\\textit{{Delta ($\\Delta$)}} & \\textit{{+{d_f1:.2f}\\%}} & \\textit{{--}} & \\textit{{--}} & \\textit{{+{d_f1:.2f}\\%}} & \\textit{{+{d_auc:.2f}\\%}} \\\\\n"
    t2_code += r"""\hline
\end{tabular}
\end{table}
"""
    t2_path = os.path.join(tbl_dir, "table2_feature_gap_ablation.tex")
    with open(t2_path, "w") as f:
        f.write(t2_code)
        
    logger.info("All publication figures and LaTeX tables successfully generated in %s and %s!", fig_dir, tbl_dir)


if __name__ == "__main__":
    generate_all_artifacts()
