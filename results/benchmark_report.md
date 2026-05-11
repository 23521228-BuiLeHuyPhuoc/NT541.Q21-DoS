# Báo cáo Benchmark — Hệ thống SDN DDoS Detection & Mitigation

**Thời gian chạy:** 2026-05-10 23:28:48

**Tổng số kịch bản:** 8

---

## 1. Bảng tổng hợp kết quả

| Kịch bản | Entropy (TB) | PPS (TB) | PPS (Max) | Phát hiện | Loại phát hiện | Chặn IP | Chặn MAC | Thời gian PH (s) |
|----------|-------------|---------|----------|-----------|---------------|---------|---------|-----------------|
| SYN Flood | 0.13 | 18257.1 | 54831.6 | [OK] | s01_syn_flood | 10.0.1.10 | — | 3.6 |
| UDP Flood | 0.065 | 23456.0 | 37093.6 | [OK] | s02_udp_flood | 10.0.1.10 | — | 1.0 |
| ICMP Flood | 0.065 | 23892.0 | 39079.6 | [OK] | s03_icmp_flood | 10.0.1.10 | — | 1.6 |
| HTTP Flood | 0.13 | 112.2 | 273.7 | [OK] | s04_http_flood | 10.0.1.10 | — | 3.1 |
| DNS Amplification | 1.5791 | 122.4 | 658.1 | [OK] | s05_dns_ampl | 10.0.1.10 | 00:00:00:00:00:01 | 2.7 |
| IP Spoof Flood | 1.38 | 41.7 | 288.8 | [OK] | spoofed_flood, s06_ip_spoof | 10.0.1.10 | 00:00:00:00:00:01 | 2.9 |
| Slowloris | 1.235 | 1.2 | 23.3 | [OK] | spoofed_flood | 10.0.1.10 | 00:00:00:00:00:01 | 0 |
| Flash Crowd | 0.7463 | 97.4 | 255.5 | [X] | — | — | — | — |

## 2. Phân tích Protocol

| Kịch bản | TCP (%) | UDP (%) | ICMP (%) | SYN (%) |
|----------|---------|---------|----------|---------|
| SYN Flood | 0.9 | 0.0 | 0.0 | 0.0 |
| UDP Flood | 0.138 | 0.812 | 0.0 | 0.0 |
| ICMP Flood | 0.082 | 0.287 | 0.581 | 0.0 |
| HTTP Flood | 0.24 | 0.323 | 0.337 | 0.0 |
| DNS Amplification | 0.0 | 0.15 | 0.0 | 0.0 |
| IP Spoof Flood | 0.15 | 0.0 | 0.0 | 0.0 |
| Slowloris | 0.05 | 0.0 | 0.0 | 0.0 |
| Flash Crowd | 0.5 | 0.0 | 0.0 | 0.0 |

## 3. Phân tích Entropy

| Kịch bản | Baseline | Tấn công (TB) | Tấn công (Min) | Tấn công (Max) | Sau tấn công |
|----------|----------|--------------|----------------|----------------|-------------|
| SYN Flood | 1.3 | 0.13 | -0.0 | 1.3 | 1.17 |
| UDP Flood | 1.3 | 0.065 | -0.0 | 1.3 | 1.17 |
| ICMP Flood | 1.3 | 0.065 | -0.0 | 1.3 | 1.17 |
| HTTP Flood | 1.3 | 0.13 | -0.0 | 1.3 | 1.3 |
| DNS Amplification | 1.3 | 1.5791 | 1.3 | 3.4812 | 1.3 |
| IP Spoof Flood | 1.3 | 1.38 | 1.3 | 2.0 | 2.07 |
| Slowloris | 4.38 | 1.235 | 0.0 | 1.3 | 1.3 |
| Flash Crowd | 1.3 | 0.7463 | -0.0 | 1.3 | 1.3 |

## 4. Phân tích Mitigation

| Kịch bản | Số IP bị chặn | Số MAC bị chặn | Số alert | Actions |
|----------|--------------|----------------|----------|---------|
| SYN Flood | 1 | 0 | 3 | Logged, Rate-Limited, Blocked |
| UDP Flood | 1 | 0 | 3 | Logged, Rate-Limited, Blocked |
| ICMP Flood | 1 | 0 | 3 | Logged, Rate-Limited, Blocked |
| HTTP Flood | 1 | 0 | 3 | Logged, Rate-Limited, Blocked |
| DNS Amplification | 1 | 1 | 3 | Logged, Rate-Limited, Blocked |
| IP Spoof Flood | 1 | 1 | 6 | Logged, Rate-Limited, Blocked |
| Slowloris | 1 | 1 | 3 | Logged, Rate-Limited, Blocked |
| Flash Crowd | 0 | 0 | 0 | — |

## 5. Đánh giá độ chính xác

| Metric | Giá trị |
|--------|---------|
| True Positive (TP) | 7 |
| True Negative (TN) | 1 |
| False Positive (FP) | 0 |
| False Negative (FN) | 0 |
| **Accuracy** | **100.0%** |
| **Precision** | **100.0%** |
| **Recall** | **100.0%** |
| **F1-Score** | **100.0%** |

### Confusion Matrix

|  | Predicted Attack | Predicted Normal |
|--|-----------------|-----------------|
| **Actual Attack** | TP = 7 | FN = 0 |
| **Actual Normal** | FP = 0 | TN = 1 |

---

## 6. Chi tiết từng kịch bản

### SYN Flood (`s01_syn`)

- **Kết quả phát hiện:** [OK] Phát hiện (mong đợi: Phát hiện)
- **Loại tấn công phát hiện:** s01_syn_flood
- **Entropy trung bình (khi tấn công):** 0.13
- **PPS trung bình:** 18257.1 | PPS max: 54831.6
- **Protocol:** TCP=0.9, UDP=0.0, ICMP=0.0
- **IP bị chặn:** 10.0.1.10
- **MAC bị chặn:** Không
- **Unique IPs:** avg=0.9, max=1
- **Thời gian phát hiện:** 3.6s sau khi bắt đầu tấn công

### UDP Flood (`s02_udp`)

- **Kết quả phát hiện:** [OK] Phát hiện (mong đợi: Phát hiện)
- **Loại tấn công phát hiện:** s02_udp_flood
- **Entropy trung bình (khi tấn công):** 0.065
- **PPS trung bình:** 23456.0 | PPS max: 37093.6
- **Protocol:** TCP=0.138, UDP=0.812, ICMP=0.0
- **IP bị chặn:** 10.0.1.10
- **MAC bị chặn:** Không
- **Unique IPs:** avg=0.9, max=1
- **Thời gian phát hiện:** 1.0s sau khi bắt đầu tấn công

### ICMP Flood (`s03_icmp`)

- **Kết quả phát hiện:** [OK] Phát hiện (mong đợi: Phát hiện)
- **Loại tấn công phát hiện:** s03_icmp_flood
- **Entropy trung bình (khi tấn công):** 0.065
- **PPS trung bình:** 23892.0 | PPS max: 39079.6
- **Protocol:** TCP=0.082, UDP=0.287, ICMP=0.581
- **IP bị chặn:** 10.0.1.10
- **MAC bị chặn:** Không
- **Unique IPs:** avg=0.9, max=1
- **Thời gian phát hiện:** 1.6s sau khi bắt đầu tấn công

### HTTP Flood (`s04_http`)

- **Kết quả phát hiện:** [OK] Phát hiện (mong đợi: Phát hiện)
- **Loại tấn công phát hiện:** s04_http_flood
- **Entropy trung bình (khi tấn công):** 0.13
- **PPS trung bình:** 112.2 | PPS max: 273.7
- **Protocol:** TCP=0.24, UDP=0.323, ICMP=0.337
- **IP bị chặn:** 10.0.1.10
- **MAC bị chặn:** Không
- **Unique IPs:** avg=0.9, max=1
- **Thời gian phát hiện:** 3.1s sau khi bắt đầu tấn công

### DNS Amplification (`s05_dns_ampl`)

- **Kết quả phát hiện:** [OK] Phát hiện (mong đợi: Phát hiện)
- **Loại tấn công phát hiện:** s05_dns_ampl
- **Entropy trung bình (khi tấn công):** 1.5791
- **PPS trung bình:** 122.4 | PPS max: 658.1
- **Protocol:** TCP=0.0, UDP=0.15, ICMP=0.0
- **IP bị chặn:** 10.0.1.10
- **MAC bị chặn:** 00:00:00:00:00:01
- **Unique IPs:** avg=1.6, max=17
- **Thời gian phát hiện:** 2.7s sau khi bắt đầu tấn công

### IP Spoof Flood (`s06_ip_spoof`)

- **Kết quả phát hiện:** [OK] Phát hiện (mong đợi: Phát hiện)
- **Loại tấn công phát hiện:** spoofed_flood, s06_ip_spoof
- **Entropy trung bình (khi tấn công):** 1.38
- **PPS trung bình:** 41.7 | PPS max: 288.8
- **Protocol:** TCP=0.15, UDP=0.0, ICMP=0.0
- **IP bị chặn:** 10.0.1.10
- **MAC bị chặn:** 00:00:00:00:00:01
- **Unique IPs:** avg=0.6, max=4
- **Thời gian phát hiện:** 2.9s sau khi bắt đầu tấn công

### Slowloris (`s07_slowloris`)

- **Kết quả phát hiện:** [OK] Phát hiện (mong đợi: Phát hiện)
- **Loại tấn công phát hiện:** spoofed_flood
- **Entropy trung bình (khi tấn công):** 1.235
- **PPS trung bình:** 1.2 | PPS max: 23.3
- **Protocol:** TCP=0.05, UDP=0.0, ICMP=0.0
- **IP bị chặn:** 10.0.1.10
- **MAC bị chặn:** 00:00:00:00:00:01
- **Unique IPs:** avg=0.1, max=1
- **Thời gian phát hiện:** 0s sau khi bắt đầu tấn công

### Flash Crowd (`s08_flash_crowd`)

- **Kết quả phát hiện:** [OK] Không phát hiện (mong đợi: Không phát hiện)
- **Loại tấn công phát hiện:** Không
- **Entropy trung bình (khi tấn công):** 0.7463
- **PPS trung bình:** 97.4 | PPS max: 255.5
- **Protocol:** TCP=0.5, UDP=0.0, ICMP=0.0
- **IP bị chặn:** Không
- **MAC bị chặn:** Không
- **Unique IPs:** avg=0.8, max=2

---

## 7. Kết luận

- Hệ thống đạt **Accuracy = 100.0%**, **F1-Score = 100.0%** trên 8 kịch bản test.
- **True Positive:** 7/7 kịch bản tấn công được phát hiện chính xác.
- **True Negative:** 1/1 kịch bản bình thường không bị báo nhầm.
- Hệ thống sử dụng **3 cấp mitigation** (Log → Rate-Limit → Block) cho phản ứng linh hoạt.
- Tấn công IP Spoofing/DNS Amplification được xử lý bằng **chặn MAC** (thay vì IP giả mạo).
