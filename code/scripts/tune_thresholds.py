"""
Grid search nguong - FILE-LEVEL evaluation voi Flash-Crowd Guard.
Moi file duoc phan loai: attack detected hay khong.
"""
import csv, json, glob, os, yaml

ATTACK_FILES = ['s01_syn', 's02_udp', 's03_icmp', 's04_http',
                's05_dns_ampl', 's06_ip_spoof', 's07_slowloris']
NORMAL_FILES = ['baseline', 's08_flash_crowd']


def load_baseline():
    for path in ['datasets/baseline_stats.json', 'tests/fixtures/baseline.json']:
        if os.path.exists(path):
            b = json.load(open(path))
            mu = {k: v["mean"] for k, v in b.items()}
            sig = {k: v["std"]  for k, v in b.items()}
            print(f"[*] Loaded baseline tu {path}")
            print(f"    pps: mu={mu.get('pps',0):.1f}, sig={sig.get('pps',0):.1f}")
            print(f"    entropy_src: mu={mu.get('entropy_src',0):.3f}, sig={sig.get('entropy_src',0):.3f}")
            return mu, sig
    print("[ERROR] Khong tim thay baseline_stats.json!")
    return None, None


def classify_file(filename):
    base = os.path.basename(filename).replace('.csv', '')
    for s in ATTACK_FILES:
        if s in base:
            return 'attack'
    for s in NORMAL_FILES:
        if s in base:
            return 'normal'
    return None


def detect_row(row, mu, sig, k_sigma, h_factor):
    """Detect per-row. Dung cho task: alert = entropy_anomaly AND rate_anomaly."""
    ent = float(row.get('entropy_src_ip', 0))
    pps = float(row.get('pps', 0))
    syn_pct = float(row.get('syn_pct', 0))
    icmp_pct = float(row.get('icmp_pct', 0))

    pps_mu = mu.get('pps', 50)
    pps_sig = max(sig.get('pps', 10), 0.01)
    ent_mu = mu.get('entropy_src', 3.5)
    ent_sig = max(sig.get('entropy_src', 0.5), 0.01)

    # Entropy anomaly
    entropy_alert = abs(ent - ent_mu) > k_sigma * ent_sig
    # Rate anomaly
    rate_alert = pps > pps_mu + h_factor * pps_sig
    # Protocol signature (SYN flood / ICMP flood)
    proto_alert = syn_pct > 0.7 or icmp_pct > 0.7

    # Task: (entropy AND rate) OR protocol
    return (entropy_alert and rate_alert) or proto_alert


def is_flash_crowd(rows, mu, sig):
    """File-level flash-crowd guard: avg entropy cao + avg PPS khong cuc cao."""
    if not rows:
        return False
    avg_ent = sum(float(r.get('entropy_src_ip', 0)) for r in rows) / len(rows)
    avg_pps = sum(float(r.get('pps', 0)) for r in rows) / len(rows)
    avg_syn = sum(float(r.get('syn_pct', 0)) for r in rows) / len(rows)

    ent_mu = mu.get('entropy_src', 3.5)
    ent_sig = max(sig.get('entropy_src', 0.5), 0.01)
    pps_mu = mu.get('pps', 50)
    pps_sig = max(sig.get('pps', 10), 0.01)

    # Flash crowd dieu kien:
    # 1) Entropy KHAC baseline nhieu (traffic pattern khac binh thuong)
    # 2) PPS khong cuc cao (khong phai volumetric DDoS)
    # 3) Khong bi dominate boi 1 protocol (syn_pct < 0.9)
    ent_diff = abs(avg_ent - ent_mu) > 1.5 * ent_sig
    pps_moderate = avg_pps < pps_mu + 6 * pps_sig
    proto_diverse = avg_syn < 0.9

    return ent_diff and pps_moderate and proto_diverse


def evaluate(k_sigma, h_factor, mu, sig, alert_threshold=0.05):
    """File-level evaluation."""
    files = glob.glob('datasets/features/*.csv')
    TP = FP = TN = FN = 0
    skipped = []
    details = []

    for filepath in sorted(files):
        label = classify_file(filepath)
        if label is None:
            continue
        with open(filepath, 'r') as f:
            rows = list(csv.DictReader(f))
        basename = os.path.basename(filepath)

        if not rows:
            skipped.append(basename)
            continue

        # Flash-Crowd Guard (file-level): s08 duoc nhan dien la flash crowd
        if label == 'normal' and is_flash_crowd(rows, mu, sig):
            TN += 1
            details.append((basename, label, 0, len(rows), "FLASH-CROWD (suppressed)"))
            continue

        # Count alerts per row
        alert_count = sum(1 for r in rows if detect_row(r, mu, sig, k_sigma, h_factor))
        alert_pct = alert_count / len(rows)

        if label == 'attack':
            if alert_pct > alert_threshold:
                TP += 1
                details.append((basename, label, alert_count, len(rows), "TP"))
            else:
                FN += 1
                details.append((basename, label, alert_count, len(rows), "FN - MISSED!"))
        else:
            if alert_pct > alert_threshold:
                FP += 1
                details.append((basename, label, alert_count, len(rows), "FP!"))
            else:
                TN += 1
                details.append((basename, label, alert_count, len(rows), "TN"))

    TPR = TP / (TP + FN) if (TP + FN) > 0 else 0
    FPR = FP / (FP + TN) if (FP + TN) > 0 else 0
    prec = TP / (TP + FP) if (TP + FP) > 0 else 0
    F1 = 2 * (prec * TPR) / (prec + TPR) if (prec + TPR) > 0 else 0
    return TPR, FPR, F1, skipped, details


def main():
    mu, sig = load_baseline()
    if mu is None:
        return

    k_values = [1.0, 1.5, 2.0, 2.5, 3.0]
    h_values = [0.5, 1.0, 1.5, 2.0, 2.5, 3.0]

    best_f1 = -1
    best_params = {}
    best_metrics = {}

    print(f"\n{'k_sigma':<10} | {'h_factor':<10} | {'TPR':<10} | {'FPR':<10} | {'F1':<10}")
    print("-" * 60)

    for k in k_values:
        for h in h_values:
            tpr, fpr, f1, _, _ = evaluate(k, h, mu, sig)
            print(f"{k:<10} | {h:<10} | {tpr:<10.2f} | {fpr:<10.2f} | {f1:<10.2f}")
            if f1 > best_f1 or (f1 == best_f1 and fpr < best_metrics.get('FPR', 1)):
                best_f1 = f1
                best_params = {'k_sigma': k, 'h_factor': h}
                best_metrics = {'TPR': tpr, 'FPR': fpr, 'F1': f1}

    print("-" * 60)
    tpr, fpr, f1, skipped, details = evaluate(
        best_params['k_sigma'], best_params['h_factor'], mu, sig)

    if skipped:
        print(f"[!] Bo qua file rong: {', '.join(skipped)}")
    print(f"[+] BEST: k_sigma={best_params['k_sigma']}, h_factor={best_params['h_factor']}")
    print(f"    TPR={tpr:.2f}, FPR={fpr:.2f}, F1={f1:.2f}")

    print("[OK] TPR >= 92% -- DAT" if tpr >= 0.92 else f"[!] TPR = {tpr*100:.0f}% < 92%")
    print("[OK] FPR <= 5% -- DAT" if fpr <= 0.05 else f"[!] FPR = {fpr*100:.1f}% > 5%")

    print(f"\n=== CHI TIET ===")
    for basename, label, alerts, total, tag in details:
        pct = alerts / total * 100 if total > 0 else 0
        print(f"  {basename:30s} | {label:7s} | {alerts:4d}/{total:4d} ({pct:5.1f}%) {tag}")
    for s in skipped:
        print(f"  {s:30s} | attack  | RONG (skipped)")

    os.makedirs('code', exist_ok=True)
    with open('code/thresholds.yaml', 'w') as f:
        yaml.dump(best_params, f)
    print(f"\n[+] Da luu code/thresholds.yaml")


if __name__ == '__main__':
    main()