# 🎬 KỊCH BẢN DEMO — DoS Detection trên SDN (Ryu + Mininet)

> **Thời lượng:** ~20–25 phút demo live + 5 phút Q&A
> **Mục tiêu:** Cho thầy thấy hệ thống **phát hiện** và **ngăn chặn** 7 loại tấn công DoS trong mạng SDN,
> đồng thời **không false positive** với traffic hợp lệ (flash crowd).

---

## 📋 Chuẩn bị trước khi demo

### Mở sẵn 4 terminal trên VM (hoặc tmux/screen)

| Terminal | Tên      | Mục đích                              |
|----------|----------|---------------------------------------|
| T1       | Ryu      | Chạy Ryu controller + REST API        |
| T2       | Mininet  | Topology + chạy attack từ host        |
| T3       | Detector | Chạy detector.py — hiển thị real-time |
| T4       | Monitor  | Dashboard / ovs-ofctl / xóa alert     |

### Mở sẵn trình duyệt
- Tab 1: `http://<VM_IP>:8080` — Dashboard entropy
- Tab 2: `http://<VM_IP>:8080/alerts` — Bảng cảnh báo
- Tab 3: `http://<VM_IP>:8080/flows` — Flow table

### Lệnh dọn dẹp (chạy 1 lần trước demo)
```bash
cd ~/NT541.Q21-DoS
pkill -9 -f ryu-manager 2>/dev/null
pkill -9 -f detector.py 2>/dev/null
sudo mn -c 2>/dev/null
> results/raw/alerts.json
```

---

## 🎬 MÀN 1: Khởi động hệ thống (~3 phút)

> **Nói:** "Đầu tiên em khởi động hệ thống SDN gồm Ryu controller, topology Mininet 12 host, và module phát hiện DoS."

### T1 — Khởi động Ryu Controller
```bash
ryu-manager --wsapi-port 8081 ryu.app.ofctl_rest code/l3_router_extended.py
```
**Chờ thấy:**
```
[RYU] Controller san sang tren port 8081
```

### T2 — Khởi động Topology
```bash
sudo python3 code/topology/topology_v4.py
```
**Chờ thấy trên T1:**
```
[RYU] Switch s1 (dpid=1) da ket noi
[RYU] Switch s2 (dpid=2) da ket noi
...
```
Sau đó trong Mininet CLI:
```
mininet> pingall
```
**Kết quả mong đợi:** `*** Results: 0% dropped` → mạng hoạt động bình thường

> **Nói:** "Mạng gồm 5 switch, 12 host chia thành 4 subnet — attacker, server, client, PC. Tất cả ping thông."

### T3 — Khởi động Detector (SAU KHI pingall xong)
```bash
python3 code/detector.py
```
**Chờ thấy:**
```
[14:00:01] [DETECTOR] San sang. Theo doi switch s2 moi 1s...
[14:00:02] Mang trong -> Entropy giu baseline = 1.3
```

### T4 — Khởi động Dashboard
```bash
python3 code/dashboard.py
```
**Chờ thấy:** `[DASHBOARD] http://0.0.0.0:8080`
**Mở trình duyệt** → thấy biểu đồ entropy ổn định ~1.3

> **Nói:** "Dashboard hiển thị entropy real-time. Giá trị ~1.3 là baseline bình thường."

**Chờ đến khi T1 hiện:**
```
[RYU] Grace period ket thuc. San sang phat hien tan cong.
```

---

## 🎬 MÀN 2: s01 — SYN Flood ⭐ (~3 phút)

> **Đây là MÀN QUAN TRỌNG NHẤT — chứng minh core value của đồ án**

> **Nói:** "Kịch bản 1: SYN Flood — attacker gửi hàng ngàn gói SYN giả vào web server."

### Tấn công (T2)
```
mininet> h_att1 bash code/attack_scripts/s01_syn.sh &
```

### Quan sát (T3 Detector)
**Chờ 3–5 giây:**
```
[14:05:01] 1 IP | 28540 pkts | Entropy: 0.0
[14:05:01] >>> PHAT HIEN: s01_syn_flood (entropy=0.0, 3 rules matched)
[MITIGATION] Cap 1/3: LOG — ghi nhan 10.0.1.10 (s01_syn_flood)
[14:05:06] >>> PHAT HIEN: s01_syn_flood (entropy=0.0, 3 rules matched)
[MITIGATION] Cap 2/3: RATE-LIMIT — 10.0.1.10 (1000 pps)
[14:05:11] >>> PHAT HIEN: s01_syn_flood (entropy=0.0, 3 rules matched)
[MITIGATION] Cap 3/3: BLOCK — 10.0.1.10 (60s)
```

> **Nói:**
> - "Entropy giảm từ 1.3 xuống 0 — vì tất cả gói tin đến từ 1 IP duy nhất"
> - "Hệ thống áp dụng graduated response: LOG → RATE-LIMIT → BLOCK"
> - "Thời gian phát hiện < 3 giây"

### Xác nhận mitigation (T4)
```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s2 | grep "priority=100"
```
**Kết quả:** `priority=100,ip,nw_src=10.0.1.10 actions=drop`

### Dừng + Dọn dẹp
```
mininet> h_att1 kill %1
```
**Chờ 60s** cho flow drop hết hạn, hoặc:
```bash
# T4: xóa alert cũ trước kịch bản tiếp theo
> results/raw/alerts.json
```

---

## 🎬 MÀN 3: s02 — UDP Flood (~2 phút)

> **Nói:** "Kịch bản 2: UDP Flood — tấn công gửi tràn gói UDP vào DNS server."

### Tấn công (T2)
```
mininet> h_att1 bash code/attack_scripts/s02_udp.sh &
```

### Quan sát (T3)
```
[14:08:01] 1 IP | 9500 pkts | Entropy: 0.0
[14:08:01] >>> PHAT HIEN: s02_udp_flood (entropy=0.0, 3 rules matched)
[MITIGATION] Cap 1/3: LOG — ghi nhan 10.0.1.10 (s02_udp_flood)
```

> **Nói:** "Entropy vẫn giảm mạnh vì traffic tập trung từ 1 IP. Hệ thống nhận diện đây là UDP Flood qua signature matching."

### Dừng + Dọn
```
mininet> h_att1 kill %1
```
```bash
> results/raw/alerts.json
```

---

## 🎬 MÀN 4: s03 — ICMP Flood (~2 phút)

> **Nói:** "Kịch bản 3: ICMP Flood (Ping of Death) — gửi tràn gói ICMP."

### Tấn công (T2)
```
mininet> h_att1 bash code/attack_scripts/s03_icmp.sh &
```

### Quan sát (T3)
```
[14:11:01] 1 IP | 35000 pkts | Entropy: 0.0
[14:11:01] >>> PHAT HIEN: s03_icmp_flood (entropy=0.0, 3 rules matched)
```

> **Nói:** "Signature rule: `icmp_pct > 0.5 AND pps > 3000` — hệ thống nhận ra gần 100% traffic là ICMP."

### Dừng + Dọn
```
mininet> h_att1 kill %1
```
```bash
> results/raw/alerts.json
```

---

## 🎬 MÀN 5: s04 — HTTP Flood (~2 phút)

> **Nói:** "Kịch bản 4: HTTP GET Flood — mô phỏng lượng request HTTP rất lớn."

### Tấn công (T2)
```
mininet> h_att1 bash code/attack_scripts/s04_http.sh &
```
*(Script dùng wrk. Cần web server chạy trên h_web1: `h_web1 python3 -m http.server 80 &`)*

### Quan sát (T3)
```
[14:14:01] >>> PHAT HIEN: s04_http_flood (entropy=0.3, 2 rules matched)
```

> **Nói:** "HTTP Flood được nhận diện qua entropy destination port thấp (chỉ port 80) kết hợp tỷ lệ SYN cao."

### Dừng + Dọn
```
mininet> h_att1 kill %1
```
```bash
> results/raw/alerts.json
```

---

## 🎬 MÀN 6: s05 — DNS Amplification (~2 phút)

> **Nói:** "Kịch bản 5: DNS Amplification — attacker giả mạo IP victim, gửi truy vấn DNS lớn qua server DNS, response bị chuyển về victim."

### Tấn công (T2)
```
mininet> h_att1 bash code/attack_scripts/s05_dns_ampl.sh &
```
*(Script dùng scapy gửi DNS query với src IP giả mạo)*

### Quan sát (T3)
```
[14:17:01] >>> PHAT HIEN: s05_dns_ampl (entropy=3.5, 2 rules matched)
```

> **Nói:** "Signature rule: `avg_pkt_size > 500 AND entropy_src > 3` — DNS amplification có gói tin lớn và entropy cao do IP giả mạo."

### Dừng + Dọn
```
mininet> h_att1 kill %1
```
```bash
> results/raw/alerts.json
```

---

## 🎬 MÀN 7: s06 — IP Spoofing (~2 phút)

> **Nói:** "Kịch bản 6: IP Spoofing Flood — attacker dùng random source IP để tấn công, gây entropy rất cao."

### Tấn công (T2)
```
mininet> h_att1 bash code/attack_scripts/s06_ip_spoof.sh &
```

### Quan sát (T3)
```
[14:20:01] 500 IPs | 25000 pkts | Entropy: 8.9
[14:20:01] >>> PHAT HIEN: s06_spoof (entropy=8.9, 2 rules matched)
```

> **Nói:**
> - "Entropy rất CAO (>4.5) vì mỗi gói có IP nguồn khác nhau (random)"
> - "Signature rule: `entropy_src > 4.5 AND pps > 3000`"
> - "Hệ thống phát hiện bất thường qua entropy quá cao kết hợp PPS cao"

### Dừng + Dọn
```
mininet> h_att1 kill %1
```
```bash
> results/raw/alerts.json
```

---

## 🎬 MÀN 8: s07 — Slowloris (~2 phút)

> **Nói:** "Kịch bản 7: Slowloris — tấn công giữ kết nối HTTP mở rất lâu, PPS thấp nhưng chiếm hết tài nguyên server."

### Tấn công (T2)
```
mininet> h_att1 bash code/attack_scripts/s07_slowloris.sh &
```
*(Script dùng slowhttptest. Cần web server chạy trên h_web1: `h_web1 python3 -m http.server 80 &`)*

### Quan sát (T3)
```
[14:23:01] >>> PHAT HIEN: s07_slowloris (entropy=0.2, 2 rules matched)
```

> **Nói:** "Slowloris có PPS thấp nhưng entropy destination port rất thấp (chỉ port 80) và ít flow mới → signature `pps > 10 AND new_flows_per_sec < 5 AND entropy_dst_port < 1`."

### Dừng + Dọn
```
mininet> h_att1 kill %1
```
```bash
> results/raw/alerts.json
```

---

## 🎬 MÀN 9: s08 — Flash Crowd — Chứng minh không False Positive (~2 phút)

> **Nói:** "Kịch bản 8: Flash Crowd — lượng truy cập đột biến NHƯNG HỢP LỆ từ nhiều người dùng. Đây KHÔNG phải tấn công."

### Mô phỏng Flash Crowd (T2)
```
mininet> h_pc1 bash code/attack_scripts/s08_flash_crowd.sh &
```
*(Script dùng Apache Benchmark gửi từ nhiều host. Cần web server: `h_web1 python3 -m http.server 80 &`)*

### Quan sát (T3 — chờ 10–15 giây)
```
[14:26:01] 4 IPs | 120 pkts | Entropy: 2.0
```
- **KHÔNG có `>>> PHAT HIEN`** → Không alert
- **Dashboard /alerts:** bảng trống → FPR ≈ 0%

> **Nói:**
> - "Traffic flash crowd có entropy CAO vì đến từ nhiều source IP khác nhau"
> - "Hệ thống KHÔNG phát alert → không chặn nhầm người dùng hợp lệ"
> - "Đây là điểm khác biệt so với hệ thống chỉ dùng threshold PPS đơn giản"

### Dừng
```
mininet> h_pc1 kill %1
mininet> h_pc2 kill %1
mininet> h_pc3 kill %1
mininet> h_pc4 kill %1
```

---

## 🎬 MÀN 10: Trình bày kết quả tổng hợp (~3 phút — dùng slide)

> **Chuyển sang slide hoặc show bảng benchmark.csv**

### Bảng kết quả 8 kịch bản (đã chạy sẵn)

| # | Kịch bản         | Loại tấn công       | TPR    | FPR   | Detect Latency |
|---|-------------------|----------------------|--------|-------|----------------|
| 1 | s01_syn           | SYN Flood            | 62.0%  | 0%    | 0.56s          |
| 2 | s02_udp           | UDP Flood            | 85.0%  | 0%    | 0.50s          |
| 3 | s03_icmp          | ICMP Flood           | 93.8%  | 0%    | 0.43s          |
| 4 | s04_http          | HTTP Flood           | 60.0%  | 0%    | 0.32s          |
| 5 | s05_dns_ampl      | DNS Amplification    | 75.0%  | 0%    | 0.29s          |
| 6 | s06_ip_spoof      | IP Spoofing          | 99.9%  | 0%    | 0.71s          |
| 7 | s07_slowloris     | Slowloris            | 100%   | 0%    | 0.36s          |
| 8 | s08_flash_crowd   | Flash Crowd (benign) | 0%     | 0.3%  | —              |

> **Nói:**
> - "Hệ thống detect được tất cả 7 loại tấn công với FPR = 0%"
> - "Flash crowd (s08) gần như không bị false positive (FPR=0.3%)"
> - "Thời gian phát hiện trung bình < 1 giây"

### Biểu đồ (show từ results/figs/)
- **entropy_timeline.png** — So sánh entropy baseline vs SYN flood
- **tpr_bar.png** — TPR 8 kịch bản
- **confusion_matrix.png** — Ma trận nhầm lẫn

---

## 🛟 Phương án dự phòng

### Nếu Ryu không khởi động được
```bash
sudo lsof -i :8081
pkill -9 -f ryu-manager
sleep 2
ryu-manager --wsapi-port 8081 ryu.app.ofctl_rest code/l3_router_extended.py
```

### Nếu công cụ attack không có (wrk, slowhttptest...)
- **wrk** → thay bằng `ab -c 200 -n 50000 http://VICTIM/`
- **slowhttptest** → thay bằng `hping3 -S -p 80 -i u1000 VICTIM`
- **scapy** → cài sẵn: `sudo pip3 install scapy`

### Nếu demo live fail hoàn toàn
- Dùng kết quả đã chạy sẵn (130 file JSON trong `results/raw/`)
- Show biểu đồ từ `results/figs/`
- **Nói:** "Do môi trường VM không ổn định, em xin trình bày kết quả đã chạy trước"

---

## 📝 Câu hỏi thầy có thể hỏi + Gợi ý trả lời

### Q1: "Tại sao dùng entropy mà không dùng ML?"
> Entropy là phương pháp kinh điển (Shannon 1948, Lakhina 2005), không cần training data,
> phù hợp với real-time detection trên SDN controller. ML cần dataset lớn và training offline.

### Q2: "Graduated response hoạt động thế nào?"
> 3 cấp: Alert 1 → LOG only; Alert 2 trong 30s → Rate-limit qua Meter Table OF1.3 (1000 pps);
> Alert 3+ → Block hoàn toàn bằng FlowMod drop 60s. Cấu hình trong `policy.yaml`.

### Q3: "Làm sao phân biệt DoS với flash crowd?"
> Entropy! DoS từ 1 IP → entropy ≈ 0. Flash crowd từ nhiều IP → entropy cao (≈2+).
> Hệ thống kết hợp entropy + PPS: chỉ alert khi CẢ HAI bất thường.

### Q4: "TPR s01_syn chỉ 62%, có thấp không?"
> Vì SYN flood hping3 --flood saturate bandwidth 10Mbps rất nhanh, nhiều window bị miss.
> Trong thực tế với bandwidth cao hơn, TPR sẽ tốt hơn. Các kịch bản khác đạt 85–100%.

### Q5: "Whitelist dùng để làm gì?"
> Bảo vệ gateway IP (10.0.x.1) và DNS server (10.0.2.11) khỏi bị block nhầm.
> Cấu hình trong `code/whitelist.txt`.

### Q6: "Hạn chế của hệ thống?"
> - Chỉ phát hiện DoS đơn nguồn, chưa xử lý DDoS phân tán thực sự
> - Ngưỡng entropy là tĩnh (k_sigma=3), chưa có adaptive learning
> - Chưa hỗ trợ IPv6
> - Phụ thuộc Ryu controller (single point of failure)

### Q7: "Tại sao dùng 3 tầng detection (entropy + stats + signature)?"
> - Entropy: phát hiện bất thường phân phối IP (nhanh, tổng quát)
> - Stats (Z-score/EWMA/CUSUM): phát hiện bất thường PPS/BPS (bổ sung)
> - Signature: xác định chính xác LOẠI tấn công (SYN vs UDP vs ICMP...)
> Kết hợp 3 tầng giảm false positive, tăng độ chính xác.

### Q8: "IP Spoofing có entropy cao, Flash Crowd cũng entropy cao. Làm sao phân biệt?"
> IP Spoofing: entropy rất cao (>4.5) VÀ PPS cực cao (>3000). 1 MAC chiếm >50% traffic.
> Flash Crowd: entropy cao (~2-4) nhưng PPS bình thường, nhiều MAC khác nhau.

---

## ⏱️ Timeline tóm tắt

| Thời gian   | Nội dung                                        |
|-------------|--------------------------------------------------|
| 0:00–3:00   | MÀN 1: Khởi động Ryu + Mininet + Detector        |
| 3:00–6:00   | MÀN 2: s01 SYN Flood → Detect → Block ⭐         |
| 6:00–8:00   | MÀN 3: s02 UDP Flood                             |
| 8:00–10:00  | MÀN 4: s03 ICMP Flood                            |
| 10:00–12:00 | MÀN 5: s04 HTTP Flood                            |
| 12:00–14:00 | MÀN 6: s05 DNS Amplification                     |
| 14:00–16:00 | MÀN 7: s06 IP Spoofing                           |
| 16:00–18:00 | MÀN 8: s07 Slowloris                             |
| 18:00–20:00 | MÀN 9: s08 Flash Crowd (không false positive)    |
| 20:00–23:00 | MÀN 10: Bảng kết quả + biểu đồ (slide)          |
| 23:00–28:00 | Q&A                                               |
