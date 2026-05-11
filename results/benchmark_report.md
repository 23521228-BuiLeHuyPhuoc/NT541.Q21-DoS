# Báo cáo Benchmark — Hệ thống SDN DDoS Detection & Mitigation

**Thời gian chạy:** 2026-05-10 21:07:56

**Tổng số kịch bản:** 8

---

## 1. Bảng tổng hợp kết quả

| Kịch bản | Entropy (TB) | PPS (TB) | PPS (Max) | Phát hiện | Loại phát hiện | Chặn IP | Chặn MAC | Thời gian PH (s) |
|----------|-------------|---------|----------|-----------|---------------|---------|---------|-----------------|
| SYN Flood | 0.195 | 23122.4 | 104580.3 | [OK] | s01_syn_flood | 10.0.1.10 | — | 5.9 |
| UDP Flood | 0.065 | 25822.2 | 30622.3 | [OK] | single_src_flood | 10.0.1.10 | — | 1.0 |
| ICMP Flood | 0.065 | 25329.3 | 44311.7 | [OK] | single_src_flood | 10.0.1.10 | — | 1.0 |
| HTTP Flood | 0.065 | 104.8 | 171.1 | [X] | — | — | — | — |
| DNS Amplification | 1.4032 | 115.0 | 636.2 | [OK] | s05_dns_ampl | 10.0.1.10 | 00:00:00:00:00:01 | 2.5 |
| IP Spoof Flood | 2.1722 | 1124.6 | 9999.0 | [OK] | spoofed_flood, s06_ip_spoof | 10.0.1.10 | 00:00:00:00:00:01 | 3.8 |
| Slowloris | 0.585 | 37.2 | 94.5 | [X] | — | — | — | — |
| Flash Crowd | 0.6513 | 59.2 | 166.0 | [OK] | s07_slowloris | 10.0.1.10 | — | 2.6 |

## 2. Phân tích Protocol

| Kịch bản | TCP (%) | UDP (%) | ICMP (%) | SYN (%) |
|----------|---------|---------|----------|---------|
| SYN Flood | 0.116 | 0.0 | 0.0 | 0.0 |
| UDP Flood | 0.0 | 0.0 | 0.0 | 0.0 |
| ICMP Flood | 0.0 | 0.0 | 0.0 | 0.0 |
| HTTP Flood | 0.0 | 0.0 | 0.0 | 0.0 |
| DNS Amplification | 0.0 | 0.1 | 0.0 | 0.0 |
| IP Spoof Flood | 0.2 | 0.0 | 0.0 | 0.1 |
| Slowloris | 0.0 | 0.0 | 0.0 | 0.0 |
| Flash Crowd | 0.172 | 0.0 | 0.0 | 0.0 |

## 3. Phân tích Entropy

| Kịch bản | Baseline | Tấn công (TB) | Tấn công (Min) | Tấn công (Max) | Sau tấn công |
|----------|----------|--------------|----------------|----------------|-------------|
| SYN Flood | 1.3 | 0.195 | -0.0 | 1.3 | 0.91 |
| UDP Flood | 1.3 | 0.065 | -0.0 | 1.3 | 0.91 |
| ICMP Flood | 1.3 | 0.065 | -0.0 | 1.3 | 1.04 |
| HTTP Flood | 1.3 | 0.065 | -0.0 | 1.3 | 1.17 |
| DNS Amplification | 1.3 | 1.4032 | 1.0 | 3.6645 | 1.3 |
| IP Spoof Flood | 1.3 | 2.1722 | 1.3 | 9.0 | 1.3 |
| Slowloris | 1.3 | 0.585 | -0.0 | 1.3 | 1.3 |
| Flash Crowd | 1.3 | 0.6513 | -0.0 | 1.3 | 1.3 |

## 4. Phân tích Mitigation

| Kịch bản | Số IP bị chặn | Số MAC bị chặn | Số alert | Actions |
|----------|--------------|----------------|----------|---------|
| SYN Flood | 1 | 0 | 3 | Blocked, Rate-Limited, Logged |
| UDP Flood | 1 | 0 | 3 | Blocked, Rate-Limited, Logged |
| ICMP Flood | 1 | 0 | 3 | Blocked, Rate-Limited, Logged |
| HTTP Flood | 0 | 0 | 0 | — |
| DNS Amplification | 1 | 1 | 3 | Blocked, Rate-Limited, Logged |
| IP Spoof Flood | 1 | 1 | 6 | Blocked, Rate-Limited, Logged |
| Slowloris | 0 | 0 | 0 | — |
| Flash Crowd | 1 | 0 | 3 | Blocked, Rate-Limited, Logged |

## 5. Đánh giá độ chính xác

| Metric | Giá trị |
|--------|---------|
| True Positive (TP) | 5 |
| True Negative (TN) | 0 |
| False Positive (FP) | 1 |
| False Negative (FN) | 2 |
| **Accuracy** | **62.5%** |
| **Precision** | **83.3%** |
| **Recall** | **71.4%** |
| **F1-Score** | **76.9%** |

### Confusion Matrix

|  | Predicted Attack | Predicted Normal |
|--|-----------------|-----------------|
| **Actual Attack** | TP = 5 | FN = 2 |
| **Actual Normal** | FP = 1 | TN = 0 |

---

## 6. Chi tiết từng kịch bản

### SYN Flood (`s01_syn`)

- **Kết quả phát hiện:** [OK] Phát hiện (mong đợi: Phát hiện)
- **Loại tấn công phát hiện:** s01_syn_flood
- **Entropy trung bình (khi tấn công):** 0.195
- **PPS trung bình:** 23122.4 | PPS max: 104580.3
- **Protocol:** TCP=0.116, UDP=0.0, ICMP=0.0
- **IP bị chặn:** 10.0.1.10
- **MAC bị chặn:** Không
- **Unique IPs:** avg=0.8, max=1
- **Thời gian phát hiện:** 5.9s sau khi bắt đầu tấn công

### UDP Flood (`s02_udp`)

- **Kết quả phát hiện:** [OK] Phát hiện (mong đợi: Phát hiện)
- **Loại tấn công phát hiện:** single_src_flood
- **Entropy trung bình (khi tấn công):** 0.065
- **PPS trung bình:** 25822.2 | PPS max: 30622.3
- **Protocol:** TCP=0.0, UDP=0.0, ICMP=0.0
- **IP bị chặn:** 10.0.1.10
- **MAC bị chặn:** Không
- **Unique IPs:** avg=0.9, max=1
- **Thời gian phát hiện:** 1.0s sau khi bắt đầu tấn công

### ICMP Flood (`s03_icmp`)

- **Kết quả phát hiện:** [OK] Phát hiện (mong đợi: Phát hiện)
- **Loại tấn công phát hiện:** single_src_flood
- **Entropy trung bình (khi tấn công):** 0.065
- **PPS trung bình:** 25329.3 | PPS max: 44311.7
- **Protocol:** TCP=0.0, UDP=0.0, ICMP=0.0
- **IP bị chặn:** 10.0.1.10
- **MAC bị chặn:** Không
- **Unique IPs:** avg=0.9, max=1
- **Thời gian phát hiện:** 1.0s sau khi bắt đầu tấn công

### HTTP Flood (`s04_http`)

- **Kết quả phát hiện:** [X] Không phát hiện (mong đợi: Phát hiện)
- **Loại tấn công phát hiện:** Không
- **Entropy trung bình (khi tấn công):** 0.065
- **PPS trung bình:** 104.8 | PPS max: 171.1
- **Protocol:** TCP=0.0, UDP=0.0, ICMP=0.0
- **IP bị chặn:** Không
- **MAC bị chặn:** Không
- **Unique IPs:** avg=0.9, max=1

### DNS Amplification (`s05_dns_ampl`)

- **Kết quả phát hiện:** [OK] Phát hiện (mong đợi: Phát hiện)
- **Loại tấn công phát hiện:** s05_dns_ampl
- **Entropy trung bình (khi tấn công):** 1.4032
- **PPS trung bình:** 115.0 | PPS max: 636.2
- **Protocol:** TCP=0.0, UDP=0.1, ICMP=0.0
- **IP bị chặn:** 10.0.1.10
- **MAC bị chặn:** 00:00:00:00:00:01
- **Unique IPs:** avg=0.8, max=13
- **Thời gian phát hiện:** 2.5s sau khi bắt đầu tấn công

### IP Spoof Flood (`s06_ip_spoof`)

- **Kết quả phát hiện:** [OK] Phát hiện (mong đợi: Phát hiện)
- **Loại tấn công phát hiện:** spoofed_flood, s06_ip_spoof
- **Entropy trung bình (khi tấn công):** 2.1722
- **PPS trung bình:** 1124.6 | PPS max: 9999.0
- **Protocol:** TCP=0.2, UDP=0.0, ICMP=0.0
- **IP bị chặn:** 10.0.1.10
- **MAC bị chặn:** 00:00:00:00:00:01
- **Unique IPs:** avg=1000.4, max=9999
- **Thời gian phát hiện:** 3.8s sau khi bắt đầu tấn công

### Slowloris (`s07_slowloris`)

- **Kết quả phát hiện:** [X] Không phát hiện (mong đợi: Phát hiện)
- **Loại tấn công phát hiện:** Không
- **Entropy trung bình (khi tấn công):** 0.585
- **PPS trung bình:** 37.2 | PPS max: 94.5
- **Protocol:** TCP=0.0, UDP=0.0, ICMP=0.0
- **IP bị chặn:** Không
- **MAC bị chặn:** Không
- **Unique IPs:** avg=0.6, max=1

### Flash Crowd (`s08_flash_crowd`)

- **Kết quả phát hiện:** [X] Phát hiện (mong đợi: Không phát hiện)
- **Loại tấn công phát hiện:** s07_slowloris
- **Entropy trung bình (khi tấn công):** 0.6513
- **PPS trung bình:** 59.2 | PPS max: 166.0
- **Protocol:** TCP=0.172, UDP=0.0, ICMP=0.0
- **IP bị chặn:** 10.0.1.10
- **MAC bị chặn:** Không
- **Unique IPs:** avg=0.8, max=2
- **Thời gian phát hiện:** 2.6s sau khi bắt đầu tấn công

---

## 7. Kết luận

- Hệ thống đạt **Accuracy = 62.5%**, **F1-Score = 76.9%** trên 8 kịch bản test.
- **True Positive:** 5/7 kịch bản tấn công được phát hiện chính xác.
- **True Negative:** 0/1 kịch bản bình thường không bị báo nhầm.
- [!] **False Positive:** 1 truong hop traffic binh thuong bi nhan nham la tan cong.
- [!] **False Negative:** 2 truong hop tan cong khong duoc phat hien.
- Hệ thống sử dụng **3 cấp mitigation** (Log → Rate-Limit → Block) cho phản ứng linh hoạt.
- Tấn công IP Spoofing/DNS Amplification được xử lý bằng **chặn MAC** (thay vì IP giả mạo).
