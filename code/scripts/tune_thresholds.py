import csv, json, glob, os, yaml

def evaluate(k_sigma, h_factor):
    # Load baseline
    try:
        b = json.load(open('datasets/baseline_stats.json'))
        mu = {k: v["mean"] for k,v in b.items()}
        sig = {k: v["std"] for k,v in b.items()}
    except Exception:
        print("Lỗi: Không tìm thấy datasets/baseline_stats.json")
        return 0, 0, 0

    files = glob.glob('datasets/features/*.csv')
    TP = FP = TN = FN = 0

    for file in files:
        # baseline và s08 (flash crowd) được coi là mạng bình thường (không được báo động)
        is_attack = not ('s08' in file or 'baseline' in file)
        
        with open(file, 'r') as f:
            reader = csv.DictReader(f)
            alerts_in_file = 0
            total_rows = 0
            
            for row in reader:
                total_rows += 1
                alert = False
                
                # Mô phỏng Entropy Detector
                ent = float(row.get('entropy_src_ip', 0))
                if abs(ent - mu.get('entropy_src', 0)) > k_sigma * sig.get('entropy_src', 1):
                    alert = True
                
                # Mô phỏng Stats Detector (Z-score đơn giản cho PPS)
                pps = float(row.get('pps', 0))
                if abs(pps - mu.get('pps', 0)) > h_factor * sig.get('pps', 1):
                    alert = True

                if alert:
                    alerts_in_file += 1

            # Đánh giá file này
            if is_attack:
                if alerts_in_file > (total_rows * 0.1): # Cảnh báo > 10% số dòng là bắt được
                    TP += 1
                else:
                    FN += 1
            else:
                if alerts_in_file > (total_rows * 0.1): # Cảnh báo > 10% ở mạng bình thường là báo giả
                    FP += 1
                else:
                    TN += 1

    TPR = TP / (TP + FN) if (TP + FN) > 0 else 0
    FPR = FP / (FP + TN) if (FP + TN) > 0 else 0
    
    # Tính F1 Score
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    F1 = 2 * (precision * TPR) / (precision + TPR) if (precision + TPR) > 0 else 0
    
    return TPR, FPR, F1

def main():
    k_values =[1.0, 1.5, 2.0, 2.5, 3.0]
    h_values = [3, 4, 5, 6]
    
    best_f1 = -1
    best_params = {}
    best_metrics = {}

    print(f"{'k_sigma':<10} | {'h_factor':<10} | {'TPR':<10} | {'FPR':<10} | {'F1_Score':<10}")
    print("-" * 60)

    for k in k_values:
        for h in h_values:
            tpr, fpr, f1 = evaluate(k, h)
            print(f"{k:<10} | {h:<10} | {tpr:<10.2f} | {fpr:<10.2f} | {f1:<10.2f}")
            
            if f1 > best_f1:
                best_f1 = f1
                best_params = {'k_sigma': k, 'h_factor': h}
                best_metrics = {'TPR': tpr, 'FPR': fpr, 'F1': f1}

    print("-" * 60)
    print(f"[+] BEST PARAMS: {best_params} (F1: {best_metrics['F1']:.2f}, TPR: {best_metrics['TPR']:.2f}, FPR: {best_metrics['FPR']:.2f})")

    # Lưu cấu hình tốt nhất vào yaml
    os.makedirs('code', exist_ok=True)
    with open('code/thresholds.yaml', 'w') as f:
        yaml.dump(best_params, f)
    print("[+] Đã lưu cấu hình tối ưu vào code/thresholds.yaml")

if __name__ == '__main__':
    main()