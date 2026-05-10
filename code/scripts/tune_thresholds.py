import csv, json, glob, os, yaml

def evaluate(k_sigma, h_factor):
    # Load baseline
    try:
        b = json.load(open('datasets/baseline_stats.json'))
        mu = {k: v["mean"] for k,v in b.items()}
        sig = {k: v["std"] for k,v in b.items()}
    except Exception:
        print("Loi: Khong tim thay datasets/baseline_stats.json")
        return 0, 0, 0

    files = glob.glob('datasets/features/*.csv')
    TP = FP = TN = FN = 0

    for file in files:
        # baseline va s08 (flash crowd) duoc coi la mang binh thuong (khong duoc bao dong)
        is_attack = not ('s08' in file or 'baseline' in file)
        
        with open(file, 'r') as f:
            reader = csv.DictReader(f)
            alerts_in_file = 0
            total_rows = 0
            
            for row in reader:
                total_rows += 1
                alert = False
                
                # Mo phong Entropy Detector
                ent = float(row.get('entropy_src_ip', 0))
                if abs(ent - mu.get('entropy_src', 0)) > k_sigma * sig.get('entropy_src', 1):
                    alert = True
                
                # Mo phong Stats Detector (Z-score don gian cho PPS)
                pps = float(row.get('pps', 0))
                if abs(pps - mu.get('pps', 0)) > h_factor * sig.get('pps', 1):
                    alert = True

                if alert:
                    alerts_in_file += 1

            # Danh gia file nay
            if is_attack:
                if alerts_in_file > (total_rows * 0.1): # Canh bao > 10% so dong la bat duoc
                    TP += 1
                else:
                    FN += 1
            else:
                if alerts_in_file > (total_rows * 0.1): # Canh bao > 10% o mang binh thuong la bao gia
                    FP += 1
                else:
                    TN += 1

    TPR = TP / (TP + FN) if (TP + FN) > 0 else 0
    FPR = FP / (FP + TN) if (FP + TN) > 0 else 0
    
    # Tinh F1 Score
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

    # Luu cau hinh tot nhat vao yaml
    os.makedirs('code', exist_ok=True)
    with open('code/thresholds.yaml', 'w') as f:
        yaml.dump(best_params, f)
    print("[+] Da luu cau hinh toi uu vao code/thresholds.yaml")

if __name__ == '__main__':
    main()