# Báo cáo Benchmark — Hệ thống SDN DDoS Detection & Mitigation

**Thời gian chạy:** 2026-05-10 22:54:02

**Tổng số kịch bản:** 8

---

## 1. Bảng tổng hợp kết quả

| Kịch bản | Entropy (TB) | PPS (TB) | PPS (Max) | Phát hiện | Loại phát hiện | Chặn IP | Chặn MAC | Thời gian PH (s) |
|----------|-------------|---------|----------|-----------|---------------|---------|---------|-----------------|
| SYN Flood | 0.195 | 20445.4 | 98894.9 | [OK] | s04_http_flood, s01_syn_flood | 10.0.1.10 | — | 5.8 |
| UDP Flood | 0.065 | 24238.4 | 40872.5 | [OK] | s02_udp_flood | 10.0.1.10 | — | 1.9 |
| ICMP Flood | 0.065 | 24940.2 | 39470.1 | [OK] | s03_icmp_flood | 10.0.1.10 | — | 1.7 |
| HTTP Flood | 0.065 | 123.9 | 205.1 | [OK] | s04_http_flood | 10.0.1.10 | — | 2.5 |
| DNS Amplification | 1.4648 | 96.3 | 692.6 | [OK] | s05_dns_ampl | 10.0.1.10 | 00:00:00:00:00:01 | 2.6 |
| IP Spoof Flood | 1.305 | 99.2 | 563.1 | [OK] | spoofed_flood, s06_ip_spoof | 10.0.2.10, 10.0.1.10 | 00:00:00:00:00:01, 00:00:00:00:00:05 | 2.6 |
| Slowloris | 0.585 | 14.4 | 80.4 | [OK] | s07_slowloris | 10.0.1.10 | — | 11.9 |
| Flash Crowd | 0.585 | 56.2 | 136.2 | [OK] | s07_slowloris | 10.0.1.10 | — | 2.9 |

## 2. Phân tích Protocol

| Kịch bản | TCP (%) | UDP (%) | ICMP (%) | SYN (%) |
|----------|---------|---------|----------|---------|
| SYN Flood | 0.85 | 0.0 | 0.0 | 0.0 |
| UDP Flood | 0.131 | 0.819 | 0.0 | 0.0 |
| ICMP Flood | 0.076 | 0.325 | 0.549 | 0.0 |
| HTTP Flood | 0.326 | 0.335 | 0.288 | 0.0 |
| DNS Amplification | 0.0 | 0.1 | 0.0 | 0.0 |
| IP Spoof Flood | 0.15 | 0.0 | 0.0 | 0.0 |
| Slowloris | 0.241 | 0.166 | 0.143 | 0.0 |
| Flash Crowd | 0.197 | 0.19 | 0.163 | 0.0 |

## 3. Phân tích Entropy

| Kịch bản | Baseline | Tấn công (TB) | Tấn công (Min) | Tấn công (Max) | Sau tấn công |
|----------|----------|--------------|----------------|----------------|-------------|
| SYN Flood | 1.3 | 0.195 | -0.0 | 1.3 | 0.0 |
| UDP Flood | 1.3 | 0.065 | -0.0 | 1.3 | 0.91 |
| ICMP Flood | 1.3 | 0.065 | -0.0 | 1.3 | 1.04 |
| HTTP Flood | 1.3 | 0.065 | -0.0 | 1.3 | 0.91 |
| DNS Amplification | 1.3 | 1.4648 | 1.3 | 3.2359 | 1.3 |
| IP Spoof Flood | 1.3 | 1.305 | 1.0 | 2.0 | 7.46 |
| Slowloris | 1.3 | 0.585 | -0.0 | 1.3 | 1.3 |
| Flash Crowd | 1.3 | 0.585 | -0.0 | 1.3 | 1.3 |

## 4. Phân tích Mitigation

| Kịch bản | Số IP bị chặn | Số MAC bị chặn | Số alert | Actions |
|----------|--------------|----------------|----------|---------|
| SYN Flood | 1 | 0 | 6 | Rate-Limited, Logged, Blocked |
| UDP Flood | 1 | 0 | 3 | Rate-Limited, Logged, Blocked |
| ICMP Flood | 1 | 0 | 3 | Rate-Limited, Logged, Blocked |
| HTTP Flood | 1 | 0 | 3 | Rate-Limited, Logged, Blocked |
| DNS Amplification | 1 | 1 | 3 | Rate-Limited, Logged, Blocked |
| IP Spoof Flood | 2 | 2 | 12 | Rate-Limited, Logged, Blocked |
| Slowloris | 1 | 0 | 3 | Rate-Limited, Logged, Blocked |
| Flash Crowd | 1 | 0 | 3 | Rate-Limited, Logged, Blocked |

## 5. Đánh giá độ chính xác

| Metric | Giá trị |
|--------|---------|
| True Positive (TP) | 7 |
| True Negative (TN) | 0 |
| False Positive (FP) | 1 |
| False Negative (FN) | 0 |
| **Accuracy** | **87.5%** |
| **Precision** | **87.5%** |
| **Recall** | **100.0%** |
| **F1-Score** | **93.3%** |

### Confusion Matrix

|  | Predicted Attack | Predicted Normal |
|--|-----------------|-----------------|
| **Actual Attack** | TP = 7 | FN = 0 |
| **Actual Normal** | FP = 1 | TN = 0 |

---

## 6. Chi tiết từng kịch bản

### SYN Flood (`s01_syn`)

- **Kết quả phát hiện:** [OK] Phát hiện (mong đợi: Phát hiện)
- **Loại tấn công phát hiện:** s04_http_flood, s01_syn_flood
- **Entropy trung bình (khi tấn công):** 0.195
- **PPS trung bình:** 20445.4 | PPS max: 98894.9
- **Protocol:** TCP=0.85, UDP=0.0, ICMP=0.0
- **IP bị chặn:** 10.0.1.10
- **MAC bị chặn:** Không
- **Unique IPs:** avg=0.8, max=1
- **Thời gian phát hiện:** 5.8s sau khi bắt đầu tấn công

### UDP Flood (`s02_udp`)

- **Kết quả phát hiện:** [OK] Phát hiện (mong đợi: Phát hiện)
- **Loại tấn công phát hiện:** s02_udp_flood
- **Entropy trung bình (khi tấn công):** 0.065
- **PPS trung bình:** 24238.4 | PPS max: 40872.5
- **Protocol:** TCP=0.131, UDP=0.819, ICMP=0.0
- **IP bị chặn:** 10.0.1.10
- **MAC bị chặn:** Không
- **Unique IPs:** avg=0.9, max=1
- **Thời gian phát hiện:** 1.9s sau khi bắt đầu tấn công

### ICMP Flood (`s03_icmp`)

- **Kết quả phát hiện:** [OK] Phát hiện (mong đợi: Phát hiện)
- **Loại tấn công phát hiện:** s03_icmp_flood
- **Entropy trung bình (khi tấn công):** 0.065
- **PPS trung bình:** 24940.2 | PPS max: 39470.1
- **Protocol:** TCP=0.076, UDP=0.325, ICMP=0.549
- **IP bị chặn:** 10.0.1.10
- **MAC bị chặn:** Không
- **Unique IPs:** avg=0.9, max=1
- **Thời gian phát hiện:** 1.7s sau khi bắt đầu tấn công

### HTTP Flood (`s04_http`)

- **Kết quả phát hiện:** [OK] Phát hiện (mong đợi: Phát hiện)
- **Loại tấn công phát hiện:** s04_http_flood
- **Entropy trung bình (khi tấn công):** 0.065
- **PPS trung bình:** 123.9 | PPS max: 205.1
- **Protocol:** TCP=0.326, UDP=0.335, ICMP=0.288
- **IP bị chặn:** 10.0.1.10
- **MAC bị chặn:** Không
- **Unique IPs:** avg=0.9, max=1
- **Thời gian phát hiện:** 2.5s sau khi bắt đầu tấn công

### DNS Amplification (`s05_dns_ampl`)

- **Kết quả phát hiện:** [OK] Phát hiện (mong đợi: Phát hiện)
- **Loại tấn công phát hiện:** s05_dns_ampl
- **Entropy trung bình (khi tấn công):** 1.4648
- **PPS trung bình:** 96.3 | PPS max: 692.6
- **Protocol:** TCP=0.0, UDP=0.1, ICMP=0.0
- **IP bị chặn:** 10.0.1.10
- **MAC bị chặn:** 00:00:00:00:00:01
- **Unique IPs:** avg=0.9, max=11
- **Thời gian phát hiện:** 2.6s sau khi bắt đầu tấn công

### IP Spoof Flood (`s06_ip_spoof`)

- **Kết quả phát hiện:** [OK] Phát hiện (mong đợi: Phát hiện)
- **Loại tấn công phát hiện:** spoofed_flood, s06_ip_spoof
- **Entropy trung bình (khi tấn công):** 1.305
- **PPS trung bình:** 99.2 | PPS max: 563.1
- **Protocol:** TCP=0.15, UDP=0.0, ICMP=0.0
- **IP bị chặn:** 10.0.2.10, 10.0.1.10
- **MAC bị chặn:** 00:00:00:00:00:01, 00:00:00:00:00:05
- **Unique IPs:** avg=0.5, max=5
- **Thời gian phát hiện:** 2.6s sau khi bắt đầu tấn công

### Slowloris (`s07_slowloris`)

- **Kết quả phát hiện:** [OK] Phát hiện (mong đợi: Phát hiện)
- **Loại tấn công phát hiện:** s07_slowloris
- **Entropy trung bình (khi tấn công):** 0.585
- **PPS trung bình:** 14.4 | PPS max: 80.4
- **Protocol:** TCP=0.241, UDP=0.166, ICMP=0.143
- **IP bị chặn:** 10.0.1.10
- **MAC bị chặn:** Không
- **Unique IPs:** avg=0.6, max=1
- **Thời gian phát hiện:** 11.9s sau khi bắt đầu tấn công

### Flash Crowd (`s08_flash_crowd`)

- **Kết quả phát hiện:** [X] Phát hiện (mong đợi: Không phát hiện)
- **Loại tấn công phát hiện:** s07_slowloris
- **Entropy trung bình (khi tấn công):** 0.585
- **PPS trung bình:** 56.2 | PPS max: 136.2
- **Protocol:** TCP=0.197, UDP=0.19, ICMP=0.163
- **IP bị chặn:** 10.0.1.10
- **MAC bị chặn:** Không
- **Unique IPs:** avg=0.6, max=1
- **Thời gian phát hiện:** 2.9s sau khi bắt đầu tấn công

---

## 7. Kết luận

- Hệ thống đạt **Accuracy = 87.5%**, **F1-Score = 93.3%** trên 8 kịch bản test.
- **True Positive:** 7/7 kịch bản tấn công được phát hiện chính xác.
- **True Negative:** 0/1 kịch bản bình thường không bị báo nhầm.
- [!] **False Positive:** 1 truong hop traffic binh thuong bi nhan nham la tan cong.
- Hệ thống sử dụng **3 cấp mitigation** (Log → Rate-Limit → Block) cho phản ứng linh hoạt.
- Tấn công IP Spoofing/DNS Amplification được xử lý bằng **chặn MAC** (thay vì IP giả mạo).
