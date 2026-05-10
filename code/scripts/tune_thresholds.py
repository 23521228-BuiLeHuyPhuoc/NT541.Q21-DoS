"""
Grid search nguong cho EntropyDetector + StatsDetector.
Row-level evaluation, Flash-Crowd Guard, protocol detection.
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
    ent = float(row.get('entropy_src_ip', 0))
    pps = float(row.get('pps', 0))
    syn_pct = float(row.get('syn_pct', 0))
    icmp_pct = float(row.get('icmp_pct', 0))

    pps_mu = mu.get('pps', 50)
    pps_sig = max(sig.get('pps', 10), 0.01)
    ent_mu = mu.get('entropy_src', 3.5)
    ent_sig = max(sig.get('entropy_src', 0.5), 0.01)

    # --- Flash-Crowd Guard ---
    # Entropy cao (IP da dang) + PPS khong cuc cao = traffic hop le
    # Guard nay suppress TAT CA alerts ke ca proto_alert
    if ent > ent_mu + 2 * ent_sig and pps < pps_mu + 6 * pps_sig:
        return False

    # --- Entropy anomaly ---
    entropy_alert = abs(ent - ent_mu) > k_sigma * ent_sig

    # --- Rate anomaly (PPS vuot baseline) ---
    rate_alert = pps > pps_mu + h_factor * pps_sig

    # --- Protocol anomaly (SYN flood / ICMP flood) ---
    proto_alert = syn_pct > 0.8 or icmp_pct > 0.8

    # Theo task: (entropy AND rate) OR protocol ro rang
    return (entropy_alert and rate_alert) or proto_alert


def evaluate(k_sigma, h_factor, mu, sig):
    files = glob.glob('datasets/features/*.csv')
    TP = FP = TN = FN = 0
    skipped = []

    for filepath in files:
        label = classify_file(filepath)
        if label is None:
            continue
        with open(filepath, 'r') as f:
            rows = list(csv.DictReader(f))
        if not rows:
            skipped.append(os.path.basename(filepath))
            continue

        for row in rows:
            alert = detect_row(row, mu, sig, k_sigma, h_factor)
            if label == 'attack':
                if alert: TP += 1
                else: FN += 1
            else:
                if alert: FP += 1
                else: TN += 1

    TPR = TP / (TP + FN) if (TP + FN) > 0 else 0
    FPR = FP / (FP + TN) if (FP + TN) > 0 else 0
    prec = TP / (TP + FP) if (TP + FP) > 0 else 0
    F1 = 2 * (prec * TPR) / (prec + TPR) if (prec + TPR) > 0 else 0
    return TPR, FPR, F1, skipped


def main():
    mu, sig = load_baseline()
    if mu is None:
        return

    # Grid search - h_factor bat dau tu 0.5 de bat nhieu attack row hon
    k_values = [1.0, 1.5, 2.0, 2.5, 3.0]
    h_values = [0.5, 1.0, 1.5, 2.0, 2.5, 3.0]

    best_f1 = -1
    best_params = {}
    best_metrics = {}

    print(f"\n{'k_sigma':<10} | {'h_factor':<10} | {'TPR':<10} | {'FPR':<10} | {'F1':<10}")
    print("-" * 60)

    for k in k_values:
        for h in h_values:
            tpr, fpr, f1, skipped = evaluate(k, h, mu, sig)
            print(f"{k:<10} | {h:<10} | {tpr:<10.2f} | {fpr:<10.2f} | {f1:<10.2f}")
            if f1 > best_f1 or (f1 == best_f1 and fpr < best_metrics.get('FPR', 1)):
                best_f1 = f1
                best_params = {'k_sigma': k, 'h_factor': h}
                best_metrics = {'TPR': tpr, 'FPR': fpr, 'F1': f1}

    print("-" * 60)
    if skipped:
        print(f"[!] Bo qua file rong: {', '.join(skipped)}")
    print(f"[+] BEST: k_sigma={best_params['k_sigma']}, h_factor={best_params['h_factor']}")
    print(f"    TPR={best_metrics['TPR']:.2f}, FPR={best_metrics['FPR']:.2f}, F1={best_metrics['F1']:.2f}")

    ok = True
    if best_metrics['TPR'] >= 0.92:
        print("[OK] TPR >= 92% -- DAT")
    else:
        print(f"[!] TPR = {best_metrics['TPR']*100:.0f}% < 92% -- CHUA DAT")
        ok = False
    if best_metrics['FPR'] <= 0.05:
        print("[OK] FPR <= 5% -- DAT")
    else:
        print(f"[!] FPR = {best_metrics['FPR']*100:.1f}% > 5% -- CHUA DAT")
        ok = False

    # Chi tiet per-file
    print(f"\n=== CHI TIET (k={best_params['k_sigma']}, h={best_params['h_factor']}) ===")
    for fp in sorted(glob.glob('datasets/features/*.csv')):
        label = classify_file(fp)
        if label is None: continue
        with open(fp, 'r') as f:
            rows = list(csv.DictReader(f))
        if not rows:
            print(f"  {os.path.basename(fp):30s} | {label:7s} | RONG")
            continue
        alerts = sum(1 for r in rows if detect_row(r, mu, sig,
                     best_params['k_sigma'], best_params['h_factor']))
        pct = alerts / len(rows) * 100
        tag = ""
        if label == 'normal' and alerts > 0: tag = "FALSE POSITIVE!"
        if label == 'attack' and alerts == 0: tag = "MISSED!"
        print(f"  {os.path.basename(fp):30s} | {label:7s} | {alerts:4d}/{len(rows):4d} ({pct:5.1f}%) {tag}")

    # Luu
    os.makedirs('code', exist_ok=True)
    with open('code/thresholds.yaml', 'w') as f:
        yaml.dump(best_params, f)
    print(f"\n[+] Da luu code/thresholds.yaml")


if __name__ == '__main__':
    main()