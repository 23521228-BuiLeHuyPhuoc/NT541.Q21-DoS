"""
Task 1.10 - Metrics: tinh TPR/FPR/F1 tu benchmark results,
xuat benchmark.csv va 3 bieu do (300 dpi).
"""
import json, glob, csv, os, sys
from collections import defaultdict

try:
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    import matplotlib.pyplot as plt
    import numpy as np
    HAS_MPL = True
except ImportError:
    HAS_MPL = False
    print("[WARN] matplotlib khong co, chi xuat CSV (khong ve bieu do)")

# ============================================================
# 1. Doc input
# ============================================================
RESULTS_DIR = 'results/raw'
OUTPUT_DIR = 'results'
SCENARIOS_ORDER = ['s01_syn', 's02_udp', 's03_icmp', 's04_http',
                   's05_dns_ampl', 's06_ip_spoof', 's07_slowloris', 's08_flash_crowd']

def load_results():
    files = sorted(glob.glob(os.path.join(RESULTS_DIR, 'run_*.json')))
    runs = defaultdict(list)
    for f in files:
        try:
            data = json.load(open(f))
            runs[data['scenario']].append(data)
        except Exception:
            pass
    return runs

# ============================================================
# 2-3. Confusion matrix per scenario
# ============================================================
def confusion(alerts, attack_window, total_duration=300, win=1.0):
    """
    Chia timeline thanh cac window 1s.
    alerts: list timestamp cua cac alert.
    attack_window: [start_ts, end_ts] (tuyet doi).
    Tra ve tp, fn, fp, tn (so window).
    """
    tp = fn = fp = tn = 0
    start = attack_window[0]
    t = 0.0
    while t < total_duration:
        abs_t = start + t
        in_attack = attack_window[0] <= abs_t <= attack_window[1]
        has_alert = any(abs_t <= a <= abs_t + win for a in alerts)

        if in_attack and has_alert:
            tp += 1
        elif in_attack and not has_alert:
            fn += 1
        elif not in_attack and has_alert:
            fp += 1
        else:
            tn += 1
        t += win
    return tp, fn, fp, tn


def compute_scenario_metrics(scenario_runs):
    """Tinh metrics trung binh cho 1 scenario tu nhieu lan chay."""
    if not scenario_runs:
        return None

    expected = scenario_runs[0].get('expected_alert', True)
    det_lats = [r['detect_latency'] for r in scenario_runs if r.get('detect_latency') is not None]
    mit_lats = [r['mitigate_latency'] for r in scenario_runs if r.get('mitigate_latency') is not None]

    avg_det = sum(det_lats) / len(det_lats) if det_lats else 0
    avg_mit = sum(mit_lats) / len(mit_lats) if mit_lats else 0

    # Gop confusion matrix tu tat ca runs
    total_tp = total_fn = total_fp = total_tn = 0
    for run in scenario_runs:
        aw = run.get('attack_window', [0, 300])
        duration = aw[1] - aw[0] if aw[1] > aw[0] else 300

        # Alert timestamps = thoi diem phat hien
        alerts = []
        if run.get('detect_latency') is not None:
            alerts.append(aw[0] + run['detect_latency'])
        if run.get('mitigate_latency') is not None:
            alerts.append(aw[0] + run['mitigate_latency'])

        if not expected:
            # Normal scenario: khong nen co alert nao
            # Moi window la TN neu khong co alert, FP neu co
            n_windows = int(duration)
            if alerts:
                total_fp += 1
                total_tn += n_windows - 1
            else:
                total_tn += n_windows
        else:
            tp, fn, fp, tn = confusion(alerts, aw, duration)
            total_tp += tp
            total_fn += fn
            total_fp += fp
            total_tn += tn

    # Tinh metrics
    tpr = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else (1.0 if not expected else 0.0)
    fpr = total_fp / (total_fp + total_tn) if (total_fp + total_tn) > 0 else 0.0
    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else (1.0 if not expected else 0.0)
    f1 = 2 * (precision * tpr) / (precision + tpr) if (precision + tpr) > 0 else 0.0

    return {
        'tp': total_tp, 'fn': total_fn, 'fp': total_fp, 'tn': total_tn,
        'tpr': round(tpr, 4), 'fpr': round(fpr, 4), 'f1': round(f1, 4),
        'detect_latency_avg': round(avg_det, 3),
        'mitigate_latency_avg': round(avg_mit, 3),
        'runs': len(scenario_runs),
        'expected_alert': expected
    }

# ============================================================
# 4. Xuat benchmark.csv
# ============================================================
def write_csv(all_metrics):
    csv_path = os.path.join(OUTPUT_DIR, 'benchmark.csv')
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(csv_path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['scenario', 'runs', 'TPR', 'FPR', 'F1',
                     'detect_latency_avg', 'mitigate_latency_avg',
                     'TP', 'FN', 'FP', 'TN'])
        for sc in SCENARIOS_ORDER:
            m = all_metrics.get(sc)
            if m is None:
                w.writerow([sc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            else:
                w.writerow([sc, m['runs'], m['tpr'], m['fpr'], m['f1'],
                            m['detect_latency_avg'], m['mitigate_latency_avg'],
                            m['tp'], m['fn'], m['fp'], m['tn']])
    print(f"[OK] Da ghi {csv_path} ({len(SCENARIOS_ORDER)} dong)")

# ============================================================
# 5. Ve 3 bieu do
# ============================================================
def plot_figures(all_metrics):
    if not HAS_MPL:
        print("[SKIP] Khong co matplotlib, bo qua ve bieu do")
        return

    figs_dir = os.path.join(OUTPUT_DIR, 'figs')
    os.makedirs(figs_dir, exist_ok=True)

    labels = [s.replace('_', '\n') for s in SCENARIOS_ORDER]
    short_labels = ['S01', 'S02', 'S03', 'S04', 'S05', 'S06', 'S07', 'S08']

    tpr_vals = [all_metrics.get(s, {}).get('tpr', 0) for s in SCENARIOS_ORDER]
    fpr_vals = [all_metrics.get(s, {}).get('fpr', 0) for s in SCENARIOS_ORDER]

    # --- Fig 1: Confusion Matrix 2x4 subplot ---
    fig, axes = plt.subplots(2, 4, figsize=(16, 8))
    fig.suptitle('Confusion Matrix per Scenario', fontsize=16, fontweight='bold')

    for idx, sc in enumerate(SCENARIOS_ORDER):
        ax = axes[idx // 4][idx % 4]
        m = all_metrics.get(sc)
        if m is None:
            cm = np.array([[0, 0], [0, 0]])
        else:
            cm = np.array([[m['tn'], m['fp']], [m['fn'], m['tp']]])

        im = ax.imshow(cm, cmap='Blues', aspect='auto')
        ax.set_title(short_labels[idx], fontsize=11, fontweight='bold')
        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(['Pred -', 'Pred +'], fontsize=8)
        ax.set_yticklabels(['True -', 'True +'], fontsize=8)

        for i in range(2):
            for j in range(2):
                color = 'white' if cm[i, j] > cm.max() / 2 else 'black'
                ax.text(j, i, str(cm[i, j]), ha='center', va='center',
                        fontsize=12, fontweight='bold', color=color)

    plt.tight_layout(rect=[0, 0, 1, 0.95])
    path1 = os.path.join(figs_dir, 'confusion_matrix.png')
    plt.savefig(path1, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[OK] {path1}")

    # --- Fig 2: TPR bar chart ---
    fig, ax = plt.subplots(figsize=(10, 5))
    colors = ['#2ecc71' if v >= 0.92 else '#e74c3c' for v in tpr_vals]
    bars = ax.bar(short_labels, tpr_vals, color=colors, edgecolor='black', linewidth=0.5)
    ax.set_ylim(0, 1.15)
    ax.set_ylabel('True Positive Rate', fontsize=12)
    ax.set_title('TPR per Scenario (target >= 0.92)', fontsize=14, fontweight='bold')
    ax.axhline(y=0.92, color='red', linestyle='--', linewidth=1.5, label='Target 92%')
    ax.legend(fontsize=10)
    for bar, val in zip(bars, tpr_vals):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                f'{val:.2f}', ha='center', va='bottom', fontsize=10, fontweight='bold')
    plt.tight_layout()
    path2 = os.path.join(figs_dir, 'tpr_bar.png')
    plt.savefig(path2, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[OK] {path2}")

    # --- Fig 3: FPR bar chart ---
    fig, ax = plt.subplots(figsize=(10, 5))
    colors = ['#2ecc71' if v <= 0.05 else '#e74c3c' for v in fpr_vals]
    bars = ax.bar(short_labels, fpr_vals, color=colors, edgecolor='black', linewidth=0.5)
    ax.set_ylim(0, max(max(fpr_vals) * 1.5, 0.1))
    ax.set_ylabel('False Positive Rate', fontsize=12)
    ax.set_title('FPR per Scenario (target <= 5%)', fontsize=14, fontweight='bold')
    ax.axhline(y=0.05, color='red', linestyle='--', linewidth=1.5, label='Target 5%')
    ax.legend(fontsize=10)
    for bar, val in zip(bars, fpr_vals):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.002,
                f'{val:.3f}', ha='center', va='bottom', fontsize=10, fontweight='bold')
    plt.tight_layout()
    path3 = os.path.join(figs_dir, 'fpr_bar.png')
    plt.savefig(path3, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[OK] {path3}")


# ============================================================
# Main
# ============================================================
def main():
    print("[*] Task 1.10 - Metrics\n")

    # 1. Doc input
    runs = load_results()
    total = sum(len(v) for v in runs.values())
    print(f"[*] Doc {total} runs tu {len(runs)} scenarios\n")

    # 2-3. Tinh metrics
    all_metrics = {}
    print(f"{'Scenario':<20} | {'Runs':>4} | {'TPR':>6} | {'FPR':>6} | {'F1':>6} | {'Detect':>8} | {'Mitigate':>8}")
    print("-" * 80)

    for sc in SCENARIOS_ORDER:
        m = compute_scenario_metrics(runs.get(sc, []))
        if m:
            all_metrics[sc] = m
            det_s = f"{m['detect_latency_avg']:.3f}s" if m['detect_latency_avg'] else "N/A"
            mit_s = f"{m['mitigate_latency_avg']:.3f}s" if m['mitigate_latency_avg'] else "N/A"
            print(f"{sc:<20} | {m['runs']:>4} | {m['tpr']:>6.2f} | {m['fpr']:>6.4f} | {m['f1']:>6.2f} | {det_s:>8} | {mit_s:>8}")
        else:
            print(f"{sc:<20} |    0 |    N/A |    N/A |    N/A |      N/A |      N/A")

    print("-" * 80)

    # 4. Xuat CSV
    write_csv(all_metrics)

    # 5. Ve bieu do
    plot_figures(all_metrics)

    print("\n[DONE] Task 1.10 hoan tat!")


if __name__ == '__main__':
    main()
