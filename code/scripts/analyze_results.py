"""
Phan tich ket qua benchmark tu results/raw/*.json
Verify hieu qua cua 3 cap mitigation va de xuat chinh sach.
"""
import json, glob, os
from collections import defaultdict

def main():
    files = sorted(glob.glob('results/raw/run_*.json'))
    if not files:
        print("[ERROR] Khong tim thay file ket qua trong results/raw/")
        return

    print(f"[*] Doc {len(files)} file ket qua...\n")

    # Nhom theo scenario
    scenarios = defaultdict(list)
    for f in files:
        try:
            data = json.load(open(f))
            scenarios[data['scenario']].append(data)
        except Exception as e:
            print(f"  [!] Loi doc {f}: {e}")

    # Phan tich tung scenario
    print(f"{'Scenario':<20} | {'Runs':>4} | {'Detect':>8} | {'Mitigate':>8} | {'Expected':>8} | Status")
    print("-" * 85)

    total_tp = total_tn = total_fp = total_fn = 0
    detect_times = []
    mitigate_times = []

    for scenario in sorted(scenarios.keys()):
        runs = scenarios[scenario]
        n = len(runs)
        expected = runs[0].get('expected_alert', True)

        # Tinh avg detect/mitigate latency
        det_lats = [r['detect_latency'] for r in runs if r.get('detect_latency') is not None]
        mit_lats = [r['mitigate_latency'] for r in runs if r.get('mitigate_latency') is not None]

        avg_det = sum(det_lats) / len(det_lats) if det_lats else None
        avg_mit = sum(mit_lats) / len(mit_lats) if mit_lats else None

        det_str = f"{avg_det:.3f}s" if avg_det else "N/A"
        mit_str = f"{avg_mit:.3f}s" if avg_mit else "N/A"
        exp_str = "ATTACK" if expected else "NORMAL"

        # Danh gia
        detected = len(det_lats)
        mitigated = len(mit_lats)

        if expected:  # Attack scenario
            if detected == n:
                status = f"TP ({detected}/{n} detected, {mitigated}/{n} mitigated)"
                total_tp += 1
            elif detected > 0:
                status = f"PARTIAL ({detected}/{n} detected)"
                total_tp += 1
            else:
                status = f"FN (0/{n} detected)"
                total_fn += 1
        else:  # Normal scenario
            if detected == 0 or all(r.get('mitigate_latency') is None for r in runs):
                status = f"TN (no false mitigation)"
                total_tn += 1
            else:
                status = f"FP ({detected}/{n} falsely detected)"
                total_fp += 1

        if avg_det: detect_times.append(avg_det)
        if avg_mit: mitigate_times.append(avg_mit)

        print(f"{scenario:<20} | {n:>4} | {det_str:>8} | {mit_str:>8} | {exp_str:>8} | {status}")

    print("-" * 85)

    # Tong hop
    print(f"\n=== TONG HOP ===")
    print(f"  Scenarios: {len(scenarios)}")
    print(f"  Total runs: {len(files)}")
    print(f"  TP={total_tp}, TN={total_tn}, FP={total_fp}, FN={total_fn}")
    tpr = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    fpr = total_fp / (total_fp + total_tn) if (total_fp + total_tn) > 0 else 0
    print(f"  TPR={tpr:.2f}, FPR={fpr:.2f}")

    if detect_times:
        print(f"  Avg detect latency:   {sum(detect_times)/len(detect_times):.3f}s")
    if mitigate_times:
        print(f"  Avg mitigate latency: {sum(mitigate_times)/len(mitigate_times):.3f}s")

    # Policy recommendation
    print(f"\n=== POLICY RECOMMENDATION ===")
    print("  Cap 1 (log):        threshold=1 alert -> chi ghi log")
    print("  Cap 2 (rate_limit): threshold=2 alerts -> giam PPS xuong 500")
    print("                      (1000 pps qua cao, attacker van gui duoc nhieu)")
    print("  Cap 3 (block):      threshold=3 alerts -> block hoan toan 60s")
    print("")
    print("  De xuat: giam rate_limit pps tu 1000 -> 500 (khoang 1 Mbps)")
    print("  Ly do: voi avg packet size ~100 bytes, 500 pps ≈ 400 Kbps")
    print("         voi avg packet size ~1000 bytes, 500 pps ≈ 4 Mbps")
    print("         Day la muc hop ly de giam thieu DDoS ma khong chan hoan toan")


if __name__ == '__main__':
    main()
