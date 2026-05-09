import time
import requests
import csv
import os
import matplotlib.pyplot as plt
from concurrent.futures import ThreadPoolExecutor

ALERT = "http://localhost:8081/api/alert"

def send_alert(ip):
    # Gửi 3 alert cho 1 IP
    for _ in range(3):
        try:
            requests.post(ALERT, json={"src_ip": ip, "attack": "bench"}, timeout=1)
        except requests.exceptions.RequestException:
            pass

def measure_flowmod_batch(n, src_pool):
    print(f"[*] Đang đo đạc độ trễ cài đặt {n} FlowMods...")
    t0 = time.time()
    
    # Dùng 20 luồng (threads) để gửi request song song
    with ThreadPoolExecutor(max_workers=20) as executor:
        for i in range(n):
            ip = src_pool[i % len(src_pool)]
            executor.submit(send_alert, ip)
            
    return time.time() - t0

# ... (Phần vẽ biểu đồ giữ nguyên)

def main():
    # Đảm bảo thư mục tồn tại
    os.makedirs('results/figs', exist_ok=True)
    csv_path = 'results/benchmark_mitigation.csv'
    
    n_values =[1, 10, 100, 1000]
    latencies =[]

    # 1. Đo đạc và ghi vào CSV
    print("=== BẮT ĐẦU BENCHMARK MITIGATION (FLOWMOD LATENCY) ===")
    with open(csv_path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['n_flows', 'install_latency_s', 'avg_per_flow_ms'])
        
        # Tạo danh sách 1000 IP giả lập
        pool =[f"10.99.{i//256}.{i%256}" for i in range(1000)]
        
        for n in n_values:
            t = measure_flowmod_batch(n, pool)
            latencies.append(t)
            avg_ms = round((t * 1000) / n, 2)
            print(f"  -> {n} flows mất {round(t, 3)}s (Trung bình: {avg_ms} ms/flow)")
            w.writerow([n, round(t, 3), avg_ms])
            time.sleep(1) # Nghỉ một chút giữa các đợt test

    print(f"[+] Đã lưu kết quả vào: {csv_path}")

    # 2. Vẽ biểu đồ (Bước 3)
    plt.figure(figsize=(8, 5))
    # Chuyển n_values thành chuỗi để vẽ biểu đồ cột cho đều khoảng cách
    x_labels = [str(n) for n in n_values]
    bars = plt.bar(x_labels, latencies, color='skyblue', edgecolor='black')
    
    plt.title('Mitigation Benchmark: FlowMod Installation Latency', fontsize=14)
    plt.xlabel('Number of FlowMods Installed', fontsize=12)
    plt.ylabel('Total Latency (Seconds)', fontsize=12)
    plt.grid(axis='y', linestyle='--', alpha=0.7)

    # Thêm text giá trị lên đầu mỗi cột
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval + (max(latencies)*0.02), 
                 f"{round(yval, 2)}s", ha='center', va='bottom', fontweight='bold')

    fig_path = 'results/figs/mitigation_benchmark.png'
    plt.savefig(fig_path, dpi=300, bbox_inches='tight')
    print(f"[+] Đã lưu biểu đồ vào: {fig_path}")

if __name__ == '__main__':
    main()