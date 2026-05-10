import time
import requests
import csv
import os
import matplotlib.pyplot as plt
from concurrent.futures import ThreadPoolExecutor, as_completed

ALERT = "http://localhost:8081/api/alert"

# Tao session de reuse TCP connection (tranh tao ket noi moi moi lan)
session = requests.Session()
adapter = requests.adapters.HTTPAdapter(
    pool_connections=50,
    pool_maxsize=50,
)
session.mount("http://", adapter)

def send_alert(ip):
    """Gui 1 alert duy nhat cho 1 IP — du de trigger FlowMod."""
    try:
        session.post(ALERT, json={"src_ip": ip, "attack": "bench"}, timeout=2)
    except requests.exceptions.RequestException:
        pass

def measure_flowmod_batch(n, src_pool):
    print(f"[*] Dang do dac do tre cai dat {n} FlowMods...")
    # Dung so threads phu hop voi batch size, toi da 50
    workers = min(n, 50)
    t0 = time.time()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = []
        for i in range(n):
            ip = src_pool[i % len(src_pool)]
            futures.append(executor.submit(send_alert, ip))
        # Doi tat ca hoan thanh
        for f in as_completed(futures):
            f.result()

    return time.time() - t0

def main():
    # Dam bao thu muc ton tai
    os.makedirs('results/figs', exist_ok=True)
    csv_path = 'results/benchmark_mitigation.csv'

    n_values = [1, 10, 100, 1000]
    latencies = []

    # 1. Do dac va ghi vao CSV
    print("=== BAT DAU BENCHMARK MITIGATION (FLOWMOD LATENCY) ===")
    with open(csv_path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['n_flows', 'install_latency_s', 'avg_per_flow_ms'])

        # Tao danh sach 1000 IP duy nhat de tranh trung lap
        pool = [f"10.99.{i//256}.{i%256}" for i in range(1000)]

        for n in n_values:
            t = measure_flowmod_batch(n, pool)
            latencies.append(t)
            avg_ms = round((t * 1000) / n, 2)
            print(f"  -> {n} flows mat {round(t, 3)}s (Trung binh: {avg_ms} ms/flow)")
            w.writerow([n, round(t, 3), avg_ms])
            time.sleep(1)  # Nghi mot chut giua cac dot test

    print(f"[+] Da luu ket qua vao: {csv_path}")

    # 2. Ve bieu do (Buoc 3)
    plt.figure(figsize=(8, 5))
    # Chuyen n_values thanh chuoi de ve bieu do cot cho deu khoang cach
    x_labels = [str(n) for n in n_values]
    bars = plt.bar(x_labels, latencies, color='skyblue', edgecolor='black')

    plt.title('Mitigation Benchmark: FlowMod Installation Latency', fontsize=14)
    plt.xlabel('Number of FlowMods Installed', fontsize=12)
    plt.ylabel('Total Latency (Seconds)', fontsize=12)
    plt.grid(axis='y', linestyle='--', alpha=0.7)

    # Them text gia tri len dau moi cot
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval + (max(latencies)*0.02),
                 f"{round(yval, 2)}s", ha='center', va='bottom', fontweight='bold')

    fig_path = 'results/figs/mitigation_benchmark.png'
    plt.savefig(fig_path, dpi=300, bbox_inches='tight')
    print(f"[+] Da luu bieu do vao: {fig_path}")

if __name__ == '__main__':
    main()