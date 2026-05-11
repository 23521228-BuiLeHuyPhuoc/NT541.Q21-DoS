# Báo cáo Benchmark — Hệ thống SDN DDoS Detection & Mitigation

**Thời gian chạy:** 2026-05-10 20:30:13

**Tổng số kịch bản:** 8

---

## 1. Bảng tổng hợp kết quả

| Kịch bản | Entropy (TB) | PPS (TB) | PPS (Max) | Phát hiện | Loại phát hiện | Chặn IP | Chặn MAC | Thời gian PH (s) |
|----------|-------------|---------|----------|-----------|---------------|---------|---------|-----------------|
| SYN Flood | 1.2145 | 79699.4 | 531329.2 | [OK] | s01_syn_flood | 10.0.1.10 | — | 29.4 |
| UDP Flood | 0.065 | 25673.2 | 41925.9 | [OK] | single_src_flood | 10.0.1.10 | — | 1.2 |
| ICMP Flood | 0.065 | 27038.6 | 42651.2 | [OK] | single_src_flood | 10.0.1.10 | — | 2.1 |
| HTTP Flood | 0.065 | 162.4 | 260.6 | [X] | — | — | — | — |
| DNS Amplification | 1.3143 | 70.7 | 565.2 | [OK] | s05_dns_ampl | 10.0.1.10 | 00:00:00:00:00:01 | 3.0 |
| IP Spoof Flood | 5.2364 | 5044.2 | 9999.0 | [OK] | s06_ip_spoof, spoofed_flood | 10.0.2.10, 10.0.1.10 | 00:00:00:00:00:01, 00:00:00:00:00:05 | 3.5 |
| Slowloris | 0.7325 | 31.5 | 125.1 | [OK] | s07_slowloris | 10.0.1.10 | — | 3.6 |
| Flash Crowd | 0.7306 | 47.7 | 186.6 | [OK] | s04_http_flood | 10.0.1.10 | — | 4.0 |

## 2. Phân tích Protocol

| Kịch bản | TCP (%) | UDP (%) | ICMP (%) | SYN (%) |
|----------|---------|---------|----------|---------|
| SYN Flood | 0.1 | 0.0 | 0.0 | 0.0 |
| UDP Flood | 0.0 | 0.0 | 0.0 | 0.0 |
| ICMP Flood | 0.0 | 0.0 | 0.0 | 0.0 |
| HTTP Flood | 0.0 | 0.0 | 0.0 | 0.0 |
| DNS Amplification | 0.0 | 0.05 | 0.0 | 0.0 |
| IP Spoof Flood | 0.55 | 0.0 | 0.0 | 0.5 |
| Slowloris | 0.137 | 0.0 | 0.0 | 0.0 |
| Flash Crowd | 0.085 | 0.0 | 0.0 | 0.0 |

## 3. Phân tích Entropy

| Kịch bản | Baseline | Tấn công (TB) | Tấn công (Min) | Tấn công (Max) | Sau tấn công |
|----------|----------|--------------|----------------|----------------|-------------|
| SYN Flood | 1.3 | 1.2145 | 0.4447 | 1.3 | 1.3 |
| UDP Flood | 1.3 | 0.065 | -0.0 | 1.3 | 0.91 |
| ICMP Flood | 1.3 | 0.065 | -0.0 | 1.3 | 1.04 |
| HTTP Flood | 1.3 | 0.065 | -0.0 | 1.3 | 1.17 |
| DNS Amplification | 1.3 | 1.3143 | 1.3 | 1.585 | 1.3 |
| IP Spoof Flood | 1.3 | 5.2364 | 1.3 | 9.0 | 2.84 |
| Slowloris | 1.3 | 0.7325 | -0.0 | 1.3 | 1.3 |
| Flash Crowd | 1.3 | 0.7306 | -0.0 | 1.3 | 1.3 |

## 4. Phân tích Mitigation

| Kịch bản | Số IP bị chặn | Số MAC bị chặn | Số alert | Actions |
|----------|--------------|----------------|----------|---------|
| SYN Flood | 1 | 0 | 3 | Logged, Rate-Limited, Blocked |
| UDP Flood | 1 | 0 | 3 | Logged, Rate-Limited, Blocked |
| ICMP Flood | 1 | 0 | 3 | Logged, Rate-Limited, Blocked |
| HTTP Flood | 0 | 0 | 0 | — |
| DNS Amplification | 1 | 1 | 3 | Logged, Rate-Limited, Blocked |
| IP Spoof Flood | 2 | 2 | 12 | Logged, Rate-Limited, Blocked |
| Slowloris | 1 | 0 | 3 | Logged, Rate-Limited, Blocked |
| Flash Crowd | 1 | 0 | 3 | Logged, Rate-Limited, Blocked |

## 5. Đánh giá độ chính xác

| Metric | Giá trị |
|--------|---------|
| True Positive (TP) | 6 |
| True Negative (TN) | 0 |
| False Positive (FP) | 1 |
| False Negative (FN) | 1 |
| **Accuracy** | **75.0%** |
| **Precision** | **85.7%** |
| **Recall** | **85.7%** |
| **F1-Score** | **85.7%** |

### Confusion Matrix

|  | Predicted Attack | Predicted Normal |
|--|-----------------|-----------------|
| **Actual Attack** | TP = 6 | FN = 1 |
| **Actual Normal** | FP = 1 | TN = 0 |

---

## 6. Chi tiết từng kịch bản

### SYN Flood (`s01_syn`)

- **Kết quả phát hiện:** [OK] Phát hiện (mong đợi: Phát hiện)
- **Loại tấn công phát hiện:** s01_syn_flood
- **Entropy trung bình (khi tấn công):** 1.2145
- **PPS trung bình:** 79699.4 | PPS max: 531329.2
- **Protocol:** TCP=0.1, UDP=0.0, ICMP=0.0
- **IP bị chặn:** 10.0.1.10
- **MAC bị chặn:** Không
- **Unique IPs:** avg=1.2, max=12
- **Thời gian phát hiện:** 29.4s sau khi bắt đầu tấn công

### UDP Flood (`s02_udp`)

- **Kết quả phát hiện:** [OK] Phát hiện (mong đợi: Phát hiện)
- **Loại tấn công phát hiện:** single_src_flood
- **Entropy trung bình (khi tấn công):** 0.065
- **PPS trung bình:** 25673.2 | PPS max: 41925.9
- **Protocol:** TCP=0.0, UDP=0.0, ICMP=0.0
- **IP bị chặn:** 10.0.1.10
- **MAC bị chặn:** Không
- **Unique IPs:** avg=0.9, max=1
- **Thời gian phát hiện:** 1.2s sau khi bắt đầu tấn công

### ICMP Flood (`s03_icmp`)

- **Kết quả phát hiện:** [OK] Phát hiện (mong đợi: Phát hiện)
- **Loại tấn công phát hiện:** single_src_flood
- **Entropy trung bình (khi tấn công):** 0.065
- **PPS trung bình:** 27038.6 | PPS max: 42651.2
- **Protocol:** TCP=0.0, UDP=0.0, ICMP=0.0
- **IP bị chặn:** 10.0.1.10
- **MAC bị chặn:** Không
- **Unique IPs:** avg=0.9, max=1
- **Thời gian phát hiện:** 2.1s sau khi bắt đầu tấn công

### HTTP Flood (`s04_http`)

- **Kết quả phát hiện:** [X] Không phát hiện (mong đợi: Phát hiện)
- **Loại tấn công phát hiện:** Không
- **Entropy trung bình (khi tấn công):** 0.065
- **PPS trung bình:** 162.4 | PPS max: 260.6
- **Protocol:** TCP=0.0, UDP=0.0, ICMP=0.0
- **IP bị chặn:** Không
- **MAC bị chặn:** Không
- **Unique IPs:** avg=0.9, max=1

### DNS Amplification (`s05_dns_ampl`)

- **Kết quả phát hiện:** [OK] Phát hiện (mong đợi: Phát hiện)
- **Loại tấn công phát hiện:** s05_dns_ampl
- **Entropy trung bình (khi tấn công):** 1.3143
- **PPS trung bình:** 70.7 | PPS max: 565.2
- **Protocol:** TCP=0.0, UDP=0.05, ICMP=0.0
- **IP bị chặn:** 10.0.1.10
- **MAC bị chặn:** 00:00:00:00:00:01
- **Unique IPs:** avg=0.1, max=3
- **Thời gian phát hiện:** 3.0s sau khi bắt đầu tấn công

### IP Spoof Flood (`s06_ip_spoof`)

- **Kết quả phát hiện:** [OK] Phát hiện (mong đợi: Phát hiện)
- **Loại tấn công phát hiện:** s06_ip_spoof, spoofed_flood
- **Entropy trung bình (khi tấn công):** 5.2364
- **PPS trung bình:** 5044.2 | PPS max: 9999.0
- **Protocol:** TCP=0.55, UDP=0.0, ICMP=0.0
- **IP bị chặn:** 10.0.2.10, 10.0.1.10
- **MAC bị chặn:** 00:00:00:00:00:01, 00:00:00:00:00:05
- **Unique IPs:** avg=4999.9, max=9999
- **Thời gian phát hiện:** 3.5s sau khi bắt đầu tấn công

### Slowloris (`s07_slowloris`)

- **Kết quả phát hiện:** [OK] Phát hiện (mong đợi: Phát hiện)
- **Loại tấn công phát hiện:** s07_slowloris
- **Entropy trung bình (khi tấn công):** 0.7325
- **PPS trung bình:** 31.5 | PPS max: 125.1
- **Protocol:** TCP=0.137, UDP=0.0, ICMP=0.0
- **IP bị chặn:** 10.0.1.10
- **MAC bị chặn:** Không
- **Unique IPs:** avg=0.7, max=2
- **Thời gian phát hiện:** 3.6s sau khi bắt đầu tấn công

### Flash Crowd (`s08_flash_crowd`)

- **Kết quả phát hiện:** [X] Phát hiện (mong đợi: Không phát hiện)
- **Loại tấn công phát hiện:** s04_http_flood
- **Entropy trung bình (khi tấn công):** 0.7306
- **PPS trung bình:** 47.7 | PPS max: 186.6
- **Protocol:** TCP=0.085, UDP=0.0, ICMP=0.0
- **IP bị chặn:** 10.0.1.10
- **MAC bị chặn:** Không
- **Unique IPs:** avg=0.7, max=2
- **Thời gian phát hiện:** 4.0s sau khi bắt đầu tấn công

---

## 7. Kết luận

- Hệ thống đạt **Accuracy = 75.0%**, **F1-Score = 85.7%** trên 8 kịch bản test.
- **True Positive:** 6/7 kịch bản tấn công được phát hiện chính xác.
- **True Negative:** 0/1 kịch bản bình thường không bị báo nhầm.
- [!] **False Positive:** 1 truong hop traffic binh thuong bi nhan nham la tan cong.
- [!] **False Negative:** 1 truong hop tan cong khong duoc phat hien.
- Hệ thống sử dụng **3 cấp mitigation** (Log → Rate-Limit → Block) cho phản ứng linh hoạt.
- Tấn công IP Spoofing/DNS Amplification được xử lý bằng **chặn MAC** (thay vì IP giả mạo).
