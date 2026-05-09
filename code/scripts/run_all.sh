#!/bin/bash
set -e

# Khai báo 8 kịch bản tấn công
for s in s01_syn s02_udp s03_icmp s04_http s05_dns_ampl s06_spoof s07_slowloris s08_flashcrowd; do
    # Chạy mỗi kịch bản 3 lần
    for run in 1 2 3; do
        echo "=== $s run $run ==="
        sudo python3 code/run_scenario.py $s
        sleep 5
    done
done