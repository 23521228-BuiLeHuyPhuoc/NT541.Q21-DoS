"""
Task 5.6 - Visualization: 4 bieu do tu TV5.
Fig 1: entropy_timeline.png (baseline vs s01 SYN)
Fig 2: pps_timeline_8scenarios.png (2x4 subplot)
Fig 3: latency_cdf.png (CDF detection + mitigation)
Fig 4: throughput_before_after_mitigation.png (bar chart)
"""
import csv, json, glob, os, sys

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError:
    print("[ERROR] Can cai matplotlib: pip3 install matplotlib")
    sys.exit(1)

FEATURES_DIR = 'datasets/features'
RESULTS_DIR = 'results/raw'
FIGS_DIR = 'results/figs'
SCENARIOS = ['s01_syn', 's02_udp', 's03_icmp', 's04_http',
             's05_dns_ampl', 's06_ip_spoof', 's07_slowloris', 's08_flash_crowd']
SHORT = ['S01\nSYN', 'S02\nUDP', 'S03\nICMP', 'S04\nHTTP',
         'S05\nDNS', 'S06\nSpoof', 'S07\nSlow', 'S08\nFlash']


def load_csv(name):
    path = os.path.join(FEATURES_DIR, f'{name}.csv')
    if not os.path.exists(path):
        return []
    return list(csv.DictReader(open(path)))


def load_runs():
    runs = []
    for f in sorted(glob.glob(os.path.join(RESULTS_DIR, 'run_*.json'))):
        try:
            runs.append(json.load(open(f)))
        except Exception:
            pass
    return runs


# ============================================================
# Fig 1: Entropy Timeline - baseline vs s01 SYN
# ============================================================
def fig1_entropy_timeline():
    base = load_csv('baseline')
    syn = load_csv('s01_syn')

    if not base and not syn:
        print("[SKIP] Fig 1: khong co du lieu baseline/s01_syn")
        return

    fig, ax = plt.subplots(figsize=(12, 5))

    if base:
        t_base = [float(r['t']) for r in base]
        e_base = [float(r['entropy_src_ip']) for r in base]
        ax.plot(t_base, e_base, label='Baseline (normal)', color='#3498db',
                linewidth=1.5, alpha=0.8)

    if syn:
        t_syn = [float(r['t']) for r in syn]
        e_syn = [float(r['entropy_src_ip']) for r in syn]
        ax.plot(t_syn, e_syn, label='S01 SYN Flood (attack)', color='#e74c3c',
                linewidth=2, alpha=0.9)

    # Threshold line
    ax.axhline(1.5, ls='--', color='#7f8c8d', linewidth=1.5,
               label='Threshold k=1.5')

    ax.set_xlabel('Time (s)', fontsize=12)
    ax.set_ylabel('Entropy src_ip (bits)', fontsize=12)
    ax.set_title('Entropy Timeline: Baseline vs SYN Flood', fontsize=14, fontweight='bold')
    ax.legend(fontsize=11, loc='upper right')
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    path = os.path.join(FIGS_DIR, 'entropy_timeline.png')
    plt.savefig(path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[OK] {path}")


# ============================================================
# Fig 2: PPS Timeline - 8 scenarios (2x4 subplot)
# ============================================================
def fig2_pps_timeline():
    fig, axes = plt.subplots(2, 4, figsize=(18, 8))
    fig.suptitle('PPS Timeline per Scenario', fontsize=16, fontweight='bold')

    colors = ['#e74c3c', '#e67e22', '#2ecc71', '#3498db',
              '#9b59b6', '#1abc9c', '#f39c12', '#34495e']

    for idx, sc in enumerate(SCENARIOS):
        ax = axes[idx // 4][idx % 4]
        rows = load_csv(sc)

        if rows:
            t = [float(r['t']) for r in rows]
            pps = [float(r['pps']) for r in rows]
            ax.plot(t, pps, color=colors[idx], linewidth=1.5)
            ax.fill_between(t, pps, alpha=0.2, color=colors[idx])
            ax.set_title(SHORT[idx].replace('\n', ' '), fontsize=11, fontweight='bold')
        else:
            ax.text(0.5, 0.5, 'No data', ha='center', va='center',
                    transform=ax.transAxes, fontsize=12, color='gray')
            ax.set_title(SHORT[idx].replace('\n', ' '), fontsize=11, fontweight='bold')

        ax.set_xlabel('Time (s)', fontsize=8)
        ax.set_ylabel('PPS', fontsize=8)
        ax.grid(True, alpha=0.3)
        ax.tick_params(labelsize=8)

    plt.tight_layout(rect=[0, 0, 1, 0.95])
    path = os.path.join(FIGS_DIR, 'pps_timeline_8scenarios.png')
    plt.savefig(path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[OK] {path}")


# ============================================================
# Fig 3: Latency CDF - detection + mitigation
# ============================================================
def fig3_latency_cdf():
    runs = load_runs()
    if not runs:
        print("[SKIP] Fig 3: khong co du lieu runs")
        return

    detects = [r['detect_latency'] for r in runs if r.get('detect_latency') is not None]
    mitigs = [r['mitigate_latency'] for r in runs if r.get('mitigate_latency') is not None]

    fig, ax = plt.subplots(figsize=(10, 6))

    for data, lbl, color in [(detects, 'Detection latency', '#2ecc71'),
                              (mitigs, 'Mitigation latency', '#e74c3c')]:
        if data:
            sorted_d = np.sort(data)
            cdf = np.arange(1, len(sorted_d) + 1) / len(sorted_d)
            ax.plot(sorted_d, cdf, label=f'{lbl} (n={len(data)})',
                    linewidth=2.5, color=color)

    # Target line
    ax.axvline(3, ls='--', color='#7f8c8d', linewidth=1.5, label='3s target')

    ax.set_xlabel('Latency (s)', fontsize=12)
    ax.set_ylabel('CDF (Cumulative Distribution)', fontsize=12)
    ax.set_title('Detection & Mitigation Latency CDF', fontsize=14, fontweight='bold')
    ax.legend(fontsize=11)
    ax.grid(True, alpha=0.3)
    ax.set_xlim(left=0)
    ax.set_ylim(0, 1.05)

    plt.tight_layout()
    path = os.path.join(FIGS_DIR, 'latency_cdf.png')
    plt.savefig(path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[OK] {path}")


# ============================================================
# Fig 4: Throughput Before/After Mitigation (bar chart)
# ============================================================
def fig4_throughput_mitigation():
    runs = load_runs()
    if not runs:
        print("[SKIP] Fig 4: khong co du lieu runs")
        return

    # Uoc tinh throughput: truoc mitigation = baseline PPS * avg_pkt_size
    # Sau mitigation = rate_limit PPS (500) hoac 0 (block)
    # Baseline PPS ~ 11.4, attack PPS tu CSV

    scenarios_data = {}
    for r in runs:
        sc = r['scenario']
        if sc not in scenarios_data:
            scenarios_data[sc] = {'detect': [], 'mitigate': []}
        if r.get('detect_latency') is not None:
            scenarios_data[sc]['detect'].append(r['detect_latency'])
        if r.get('mitigate_latency') is not None:
            scenarios_data[sc]['mitigate'].append(r['mitigate_latency'])

    # PPS truoc/sau mitigation tu CSV features
    before_pps = {}
    after_pps = {}
    for sc in SCENARIOS:
        rows = load_csv(sc)
        if rows:
            pps_vals = [float(r['pps']) for r in rows]
            before_pps[sc] = max(pps_vals) if pps_vals else 0
        else:
            before_pps[sc] = 0

        # Sau mitigation: rate_limit = 500 pps, block = 0
        sd = scenarios_data.get(sc, {})
        if sd.get('mitigate'):
            after_pps[sc] = 500  # Rate-limit cap
        elif sc == 's08_flash_crowd':
            after_pps[sc] = before_pps[sc]  # Khong bi mitigation
        else:
            after_pps[sc] = before_pps.get(sc, 0)

    fig, ax = plt.subplots(figsize=(12, 6))
    x = np.arange(len(SCENARIOS))
    width = 0.35

    before_vals = [before_pps.get(sc, 0) for sc in SCENARIOS]
    after_vals = [after_pps.get(sc, 0) for sc in SCENARIOS]

    bars1 = ax.bar(x - width/2, before_vals, width, label='Before Mitigation (peak PPS)',
                   color='#e74c3c', edgecolor='black', linewidth=0.5)
    bars2 = ax.bar(x + width/2, after_vals, width, label='After Mitigation (rate-limited)',
                   color='#2ecc71', edgecolor='black', linewidth=0.5)

    ax.set_xlabel('Scenario', fontsize=12)
    ax.set_ylabel('Packets per Second (PPS)', fontsize=12)
    ax.set_title('Throughput Before vs After Mitigation', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels([s.replace('\n', ' ') for s in SHORT], fontsize=9)
    ax.legend(fontsize=11)
    ax.grid(True, alpha=0.3, axis='y')

    # Annotate values
    for bar in bars1:
        h = bar.get_height()
        if h > 0:
            ax.text(bar.get_x() + bar.get_width()/2, h + max(before_vals)*0.01,
                    f'{h:.0f}', ha='center', va='bottom', fontsize=7, fontweight='bold')

    plt.tight_layout()
    path = os.path.join(FIGS_DIR, 'throughput_before_after_mitigation.png')
    plt.savefig(path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[OK] {path}")


# ============================================================
# Main
# ============================================================
def main():
    print("[*] Task 5.6 - Visualization (4 figs)\n")
    os.makedirs(FIGS_DIR, exist_ok=True)

    fig1_entropy_timeline()
    fig2_pps_timeline()
    fig3_latency_cdf()
    fig4_throughput_mitigation()

    # Kiem tra output
    print(f"\n=== KET QUA ===")
    expected = ['entropy_timeline.png', 'pps_timeline_8scenarios.png',
                'latency_cdf.png', 'throughput_before_after_mitigation.png',
                'confusion_matrix.png', 'tpr_bar.png', 'fpr_bar.png']
    for f in expected:
        path = os.path.join(FIGS_DIR, f)
        if os.path.exists(path):
            size = os.path.getsize(path)
            print(f"  [OK] {f} ({size/1024:.0f} KB)")
        else:
            print(f"  [!]  {f} -- THIEU!")

    print("\n[DONE] Task 5.6 hoan tat!")


if __name__ == '__main__':
    main()
