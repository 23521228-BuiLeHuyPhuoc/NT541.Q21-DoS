"""
Grid search nguong cho EntropyDetector + StatsDetector.
Danh gia ROW-LEVEL (tung dong CSV) thay vi file-level de co do phan giai cao hon.
Tich hop Flash-Crowd Guard cho s08.
"""
import csv, json, glob, os, yaml

# === GROUND TRUTH ===
# Attack scenarios: moi ROW trong cac file nay la attack traffic
ATTACK_FILES = ['s01_syn', 's02_udp', 's03_icmp', 's04_http',
                's05_dns_ampl', 's06_ip_spoof', 's07_slowloris']
# Normal scenarios: moi ROW trong cac file nay la normal traffic
NORMAL_FILES = ['baseline', 's08_flash_crowd']


def load_baseline():
    for path in ['datasets/baseline_stats.json', 'tests/fixtures/baseline.json']:
        if os.path.exists(path):
            b = json.load(open(path))
            mu = {k: v["mean"] for k, v in b.items()}
            sig = {k: v["std"]  for k, v in b.items()}
            print(f"[*] Loaded baseline tu {path}")
            print(f"    Keys: {list(mu.keys())}")
            print(f"    pps: mu={mu.get('pps',0):.1f}, sig={sig.get('pps',0):.1f}")
            print(f"    entropy_src: mu={mu.get('entropy_src',0):.3f}, sig={sig.get('entropy_src',0):.3f}")
            return mu, sig
    print("[ERROR] Khong tim thay baseline_stats.json!")
    return None, None


def classify_file(filename):
    """Xac dinh file la attack hay normal."""
    base = os.path.basename(filename).replace('.csv', '')
    for s in ATTACK_FILES:
        if s in base:
            return 'attack'
    for s in NORMAL_FILES:
        if s in base:
            return 'normal'
    return None


def detect_row(row, mu, sig, k_sigma, h_factor):
    """Mo phong detection pipeline cho 1 row CSV. Tra ve True neu alert."""
    ent = float(row.get('entropy_src_ip', 0))
    pps = float(row.get('pps', 0))
    syn_pct = float(row.get('syn_pct', 0))
    icmp_pct = float(row.get('icmp_pct', 0))

    # --- Flash-Crowd Guard ---
    # Entropy cao (nhieu IP da dang) + PPS khong qua cao = traffic hop le
    pps_mu = mu.get('pps', 50)
    pps_sig = sig.get('pps', 10)
    if ent > 4.0 and pps < pps_mu + h_factor * pps_sig:
        return False  # Flash crowd, khong phai attack

    # --- Entropy anomaly ---
    ent_mu = mu.get('entropy_src', 3.5)
    ent_sig = max(sig.get('entropy_src', 0.5), 0.01)
    entropy_alert = abs(ent - ent_mu) > k_sigma * ent_sig

    # --- Rate anomaly (PPS) ---
    rate_alert = pps > pps_mu + h_factor * pps_sig

    # --- Protocol anomaly (SYN flood / ICMP flood) ---
    proto_alert = syn_pct > 0.7 or icmp_pct > 0.7

    # Ket hop: entropy HOAC rate HOAC protocol bat thuong
    return entropy_alert or rate_alert or proto_alert


def evaluate(k_sigma, h_factor, mu, sig):
    """Danh gia ROW-LEVEL tren tat ca CSV files."""
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
                if alert:
                    TP += 1
                else:
                    FN += 1
            else:  # normal
                if alert:
                    FP += 1
                else:
                    TN += 1

    TPR = TP / (TP + FN) if (TP + FN) > 0 else 0
    FPR = FP / (FP + TN) if (FP + TN) > 0 else 0
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    F1 = 2 * (precision * TPR) / (precision + TPR) if (precision + TPR) > 0 else 0

    return TPR, FPR, F1, skipped


def main():
    mu, sig = load_baseline()
    if mu is None:
        return

    k_values = [1.0, 1.5, 2.0, 2.5, 3.0]
    h_values = [3, 4, 5, 6]

    best_f1 = -1
    best_params = {}
    best_metrics = {}
    first_skipped = None

    print(f"\n{'k_sigma':<10} | {'h_factor':<10} | {'TPR':<10} | {'FPR':<10} | {'F1_Score':<10}")
    print("-" * 60)

    for k in k_values:
        for h in h_values:
            tpr, fpr, f1, skipped = evaluate(k, h, mu, sig)
            if first_skipped is None and skipped:
                first_skipped = skipped
            print(f"{k:<10} | {h:<10} | {tpr:<10.2f} | {fpr:<10.2f} | {f1:<10.2f}")

            if f1 > best_f1 or (f1 == best_f1 and fpr < best_metrics.get('FPR', 1)):
                best_f1 = f1
                best_params = {'k_sigma': k, 'h_factor': h}
                best_metrics = {'TPR': tpr, 'FPR': fpr, 'F1': f1}

    print("-" * 60)
    if first_skipped:
        print(f"[!] Bo qua file rong: {', '.join(first_skipped)}")
    print(f"[+] BEST: k_sigma={best_params['k_sigma']}, h_factor={best_params['h_factor']}")
    print(f"    TPR={best_metrics['TPR']:.2f}, FPR={best_metrics['FPR']:.2f}, F1={best_metrics['F1']:.2f}")

    # Kiem tra target
    if best_metrics['TPR'] >= 0.92:
        print("[OK] TPR >= 92% -- DAT")
    else:
        print(f"[!] TPR = {best_metrics['TPR']*100:.0f}% < 92% -- CHUA DAT")
    if best_metrics['FPR'] <= 0.05:
        print("[OK] FPR <= 5% -- DAT")
    else:
        print(f"[!] FPR = {best_metrics['FPR']*100:.0f}% > 5% -- CHUA DAT")

    # Chi tiet per-file voi best params
    print("\n=== CHI TIET TUNG FILE (best params) ===")
    files = sorted(glob.glob('datasets/features/*.csv'))
    for filepath in files:
        label = classify_file(filepath)
        if label is None:
            continue
        with open(filepath, 'r') as f:
            rows = list(csv.DictReader(f))
        if not rows:
            print(f"  {os.path.basename(filepath):30s} | {label:7s} | RONG (0 rows)")
            continue
        alerts = sum(1 for r in rows if detect_row(r, mu, sig,
                     best_params['k_sigma'], best_params['h_factor']))
        pct = alerts / len(rows) * 100
        status = "ALERT" if alerts > 0 else "OK"
        if label == 'normal' and alerts > 0:
            status = "FALSE POSITIVE!"
        if label == 'attack' and alerts == 0:
            status = "MISSED!"
        print(f"  {os.path.basename(filepath):30s} | {label:7s} | {alerts:4d}/{len(rows):4d} rows ({pct:5.1f}%) {status}")

    # Luu cau hinh
    os.makedirs('code', exist_ok=True)
    with open('code/thresholds.yaml', 'w') as f:
        yaml.dump(best_params, f)
    print(f"\n[+] Da luu cau hinh toi uu vao code/thresholds.yaml")


if __name__ == '__main__':
    main()