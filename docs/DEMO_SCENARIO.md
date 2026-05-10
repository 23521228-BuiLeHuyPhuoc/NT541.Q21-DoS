# 🎬 KỊCH BẢN DEMO — DoS Detection trên SDN (Ryu + Mininet)

> **Thời lượng:** ~12–15 phút demo live + 5 phút trình bày kết quả (slide)
> **Mục tiêu:** Cho thầy thấy hệ thống **phát hiện** và **ngăn chặn** tấn công DoS trong mạng SDN,
> đồng thời **không false positive** với traffic hợp lệ (flash crowd).

---

## 📋 Chuẩn bị trước khi demo

### Mở sẵn 4 terminal trên VM (hoặc tmux/screen)

| Terminal | Tên      | Mục đích                              |
|----------|----------|---------------------------------------|
| T1       | Ryu      | Chạy Ryu controller + REST API        |
| T2       | Mininet  | Topology + chạy attack từ host        |
| T3       | Detector | Chạy detector.py — hiển thị real-time |
| T4       | Monitor  | Kiểm tra flow / Dashboard / ovs-ofctl |

### Mở sẵn trình duyệt
- Tab 1: `http://<VM_IP>:8080` — Dashboard entropy
- Tab 2: `http://<VM_IP>:8080/alerts` — Bảng cảnh báo
- Tab 3: `http://<VM_IP>:8080/flows` — Flow table

### Lệnh dọn dẹp (chạy 1 lần trước demo)
```bash
# Trên VM, tại thư mục project:
cd ~/NT541.Q21-DoS

# Kill hết tiến trình cũ
pkill -9 -f ryu-manager 2>/dev/null
pkill -9 -f detector.py 2>/dev/null
sudo mn -c 2>/dev/null

# Xóa log cũ để alerts/flows trống khi bắt đầu
> results/raw/alerts.json
```

---

## 🎬 MÀN 1: Khởi động hệ thống (~3 phút)

> **Nói:** "Đầu tiên em khởi động hệ thống SDN gồm Ryu controller, topology Mininet 12 host, và module phát hiện DoS."

### T1 — Khởi động Ryu Controller
```bash
ryu-manager --wsapi-port 8081 ryu.app.ofctl_rest code/l3_router_extended.py
```
**Chờ thấy:** `connected socket:...` hoặc không lỗi → Ryu sẵn sàng

### T2 — Khởi động Topology
```bash
sudo python3 code/topology/topology_v4.py
```
**Chờ 8–10s**, sau đó trong Mininet CLI:
```
mininet> pingall
```
**Kết quả mong đợi:** `*** Results: 0% dropped` → mạng hoạt động bình thường

> **Nói:** "Mạng gồm 5 switch, 12 host chia thành 4 subnet — attacker, server, client, PC. Tất cả ping thông."

### T3 — Khởi động Detector (SAU KHI pingall xong)
```bash
python3 code/detector.py
```
**Chờ thấy output:** `Mang trong -> Entropy giu baseline = 3.4` → detector đang poll flow stats mỗi 1s

> **Lưu ý:** Detector có 2 cơ chế chống false positive:
> - **Warmup 10 chu kỳ đầu**: bỏ qua alert để flow table ổn định
> - **Ngưỡng traffic tối thiểu (50 pkts)**: không alert khi traffic quá thấp (pingall chỉ ~12 gói)
> Nếu thấy dòng `[SKIP] Traffic qua thap...` → đây là hành vi đúng, không phải lỗi.

### T4 — Khởi động Dashboard
```bash
python3 code/dashboard.py
```
**Mở trình duyệt:** `http://<VM_IP>:8080` — thấy biểu đồ entropy ổn định ~3.4

> **Nói:** "Dashboard hiển thị entropy real-time. Giá trị ~3.4 là baseline bình thường."

---

## 🎬 MÀN 2: Tấn công SYN Flood — Phát hiện + Ngăn chặn (~5 phút) ⭐

> **Đây là MÀN QUAN TRỌNG NHẤT — chứng minh core value của đồ án**

> **Nói:** "Bây giờ em sẽ mô phỏng tấn công SYN Flood từ host attacker (h_att1) vào web server (h_web1)."

### Bước 1 — Kích hoạt tấn công (T2 - Mininet CLI)
```
mininet> h_att1 hping3 -S -p 80 --flood 10.0.2.10 &
```

### Bước 2 — Quan sát Detector (T3)
**Chờ 3–5 giây**, detector sẽ hiện:
```
[13:45:01] Mang co 1 IPs | Goi tin (giay nay): 28540 | Entropy: 0.0
[ALERT] ... s01_syn_flood ... severity=CRITICAL
```

> **Nói với thầy:**
> - "Entropy giảm từ 3.4 xuống gần 0 — vì tất cả gói tin đến từ 1 IP duy nhất"
> - "Hệ thống phát hiện qua 3 tầng: entropy anomaly + statistical anomaly + signature matching"
> - "Thời gian phát hiện < 3 giây"

### Bước 3 — Quan sát Dashboard (trình duyệt)
- **Tab entropy:** đồ thị tụt xuống 0 → rõ ràng bất thường
- **Tab alerts:** xuất hiện dòng alert mới với severity CRITICAL, action = Blocked

> **Nói:** "Dashboard cập nhật real-time, thầy có thể thấy entropy giảm mạnh."

### Bước 4 — Xác nhận Mitigation (T4)
```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s2 | grep "priority=100"
```
**Kết quả mong đợi:**
```
priority=100,ip,nw_src=10.0.1.10 actions=drop
```

> **Nói:**
> - "Hệ thống áp dụng graduated response 3 cấp theo policy.yaml:"
> - "Cấp 1 LOG → Cấp 2 RATE-LIMIT (Meter Table) → Cấp 3 BLOCK (FlowMod drop)"
> - "Sau 3 alert liên tiếp, IP attacker bị block hoàn toàn bằng OpenFlow rule"

### Bước 5 — Dừng tấn công (T2)
```
mininet> h_att1 kill %1
```

**Chờ ~60s** — flow drop tự hết hạn (hard_timeout=60s), blacklist auto-release

> **Nói:** "Flow drop có timeout 60 giây, sau đó IP attacker được tự động gỡ chặn."

---

## 🎬 MÀN 3: Flash Crowd — Chứng minh không False Positive (~3 phút)

> **Nói:** "Một thách thức lớn của hệ thống phát hiện DoS là phân biệt tấn công với flash crowd — lượng truy cập đột biến nhưng hợp lệ từ nhiều người dùng."

### Bước 1 — Xóa alert cũ để dễ quan sát
```bash
# T4
> results/raw/alerts.json
```
Refresh tab alerts trên Dashboard → bảng trống

### Bước 2 — Mô phỏng Flash Crowd (T2 - Mininet CLI)
```
mininet> h_pc1 wget -q -O /dev/null http://10.0.2.10/ &
mininet> h_pc2 wget -q -O /dev/null http://10.0.2.10/ &
mininet> h_pc3 wget -q -O /dev/null http://10.0.2.10/ &
mininet> h_pc4 wget -q -O /dev/null http://10.0.2.10/ &
```
*(Hoặc nếu có ab: `h_pc1 ab -c 10 -n 500 http://10.0.2.10/ &` cho mỗi host)*

### Bước 3 — Quan sát (chờ 10–15 giây)
- **T3 Detector:** Entropy vẫn cao (~3.0+) vì traffic đến từ **nhiều IP khác nhau**
- **Dashboard alerts:** **KHÔNG có alert mới** → FPR ≈ 0%

> **Nói:**
> - "Traffic flash crowd có entropy cao vì đến từ nhiều source IP"
> - "Hệ thống KHÔNG phát alert → không chặn nhầm người dùng hợp lệ"
> - "Đây là điểm khác biệt so với hệ thống chỉ dùng threshold PPS đơn giản"

### Bước 4 — Dừng flash crowd
```
mininet> h_pc1 kill %1
mininet> h_pc2 kill %1
mininet> h_pc3 kill %1
mininet> h_pc4 kill %1
```

---

## 🎬 MÀN 4: Trình bày kết quả tổng hợp (~3 phút — dùng slide)

> **Chuyển sang slide hoặc show bảng benchmark.csv**

### Bảng kết quả 8 kịch bản (đã chạy sẵn)

| Kịch bản         | Loại tấn công      | TPR    | FPR   | Detect Latency |
|-------------------|---------------------|--------|-------|----------------|
| s01_syn           | SYN Flood           | 62.0%  | 0%    | 0.56s          |
| s02_udp           | UDP Flood           | 85.0%  | 0%    | 0.50s          |
| s03_icmp          | ICMP Flood          | 93.8%  | 0%    | 0.43s          |
| s04_http          | HTTP Flood          | 60.0%  | 0%    | 0.32s          |
| s05_dns_ampl      | DNS Amplification   | 75.0%  | 0%    | 0.29s          |
| s06_ip_spoof      | IP Spoofing         | 99.9%  | 0%    | 0.71s          |
| s07_slowloris     | Slowloris           | 100%   | 0%    | 0.36s          |
| s08_flash_crowd   | Flash Crowd (benign)| 0%     | 0.3%  | —              |

> **Nói:**
> - "Hệ thống detect được tất cả 7 loại tấn công, FPR gần bằng 0"
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
# Kiểm tra port 8081 bị chiếm
sudo lsof -i :8081
# Kill tiến trình chiếm port
pkill -9 -f ryu-manager
sleep 2
# Thử lại
ryu-manager --wsapi-port 8081 ryu.app.ofctl_rest code/l3_router_extended.py
```

### Nếu detector không phát hiện (không có alert)
- Kiểm tra Ryu REST: `curl http://localhost:8081/stats/flow/2 | head`
- Kiểm tra detector log: `tail -5 results/raw/detector.log`
- **Backup:** Show kết quả sẵn từ `results/benchmark.csv` + biểu đồ `results/figs/`

### Nếu demo live fail hoàn toàn
- Dùng kết quả đã chạy sẵn (130 file JSON trong `results/raw/`)
- Show biểu đồ từ `results/figs/` (8 hình đã render)
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
> Entropy! DoS từ 1 IP → entropy ≈ 0. Flash crowd từ nhiều IP → entropy cao (≈3+).
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

---

## ⏱️ Timeline tóm tắt

| Thời gian | Nội dung                                      |
|-----------|-----------------------------------------------|
| 0:00–3:00 | MÀN 1: Khởi động Ryu + Mininet + Detector     |
| 3:00–8:00 | MÀN 2: SYN Flood → Detect → Block ⭐          |
| 8:00–11:00| MÀN 3: Flash Crowd → Không false positive      |
| 11:00–15:00| MÀN 4: Bảng kết quả + biểu đồ (slide)        |
| 15:00–20:00| Q&A                                           |
