#!/bin/bash
# Không dùng set -e để tránh dừng toàn bộ nếu 1 kịch bản fail

# Khai báo 8 kịch bản tấn công
for s in s01_syn s02_udp s03_icmp s04_http s05_dns_ampl s06_ip_spoof s07_slowloris s08_flash_crowd; do
    # Chạy mỗi kịch bản 3 lần
    for run in 1 2 3; do
        echo "=== $s run $run ==="
        sudo python3 code/run_scenario.py $s || echo "[WARN] $s run $run thoát với lỗi, tiếp tục..."
        sleep 15
    done
done

echo "=== HOÀN TẤT TẤT CẢ KỊCH BẢN ==="