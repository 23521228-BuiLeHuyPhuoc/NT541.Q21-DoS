# GIẢI THÍCH LOGIC - HỆ THỐNG SDN DDoS DETECTION & MITIGATION

## 1. Kiến trúc tổng thể

```
                    +------------------+
                    |   Dashboard      |   (Flask :8080)
                    |   index.html     |
                    |   alerts.html    |
                    |   flows.html     |
                    +--------+---------+
                             |
                     /api/stats, /api/block, /api/unblock
                             |
+------------------+         |         +--------------------+
|  Detector        |  /api/alert       | Ryu Controller     |
|  detector.py     +-------->|-------->| l3_router_test.py  |
|                  |         |         | l3_router_extended |
|  - entropy.py    |         |         |                    |
|  - stats.py      |         |         | - Spoof detection  |
|  - signature_    |         |         | - Flow management  |
|    matcher.py    |         |         | - Mitigation       |
+--------+---------+         |         +---------+----------+
         |                   |                   |
    Đọc flow stats      /api/entropy        OpenFlow 1.3
    từ Ryu REST API          |                   |
         |                   |         +---------+----------+
         +-------------------+-------->|  OVS Switches      |
                                       |  s1, s2, s3, s4    |
                                       +--------------------+
```

---

## 2. Detection Engine (3 tầng)

Hệ thống phát hiện dựa trên 3 detection engine độc lập, hoạt động song song:

### 2.1 Entropy Detector (entropy.py)

**Cơ sở lý thuyết: Shannon Entropy (Claude Shannon, 1948)**

Shannon entropy đo mức độ "ngẫu nhiên" trong phân phối IP nguồn:

```
H(X) = -Σ[ p(xi) × log₂(p(xi)) ]
```

Trong đó:
- `p(xi) = số_gói_từ_IP_i / tổng_số_gói`
- `H(X) = 0` khi tất cả gói từ 1 IP duy nhất (tấn công từ 1 nguồn)
- `H(X)` cao khi nhiều IP khác nhau (traffic bình thường hoặc IP spoofing)

**Rényi Entropy (Alfréd Rényi, 1961)**

Tổng quát hóa của Shannon, dùng bậc q=2 (Collision entropy):

```
H_q(X) = (1/(1-q)) × log₂( Σ[ p(xi)^q ] )
```

Rényi bậc 2 nhạy cảm hơn với phân phối lệch (một vài IP chiếm đa số traffic).

**Cách phát hiện:**

| Metric | Bình thường | SYN/UDP/ICMP Flood | IP Spoof |
|--------|------------|---------------------|----------|
| Entropy | ~1.3 (baseline) | ~0 (1 IP) | >8 (hàng nghìn IP) |

**Phân biệt flash crowd vs spoof flood:**

```python
is_flash_crowd = (
    entropy_src > 4.0 AND       # Nhiều IP khác nhau
    syn_pct < 0.3 AND           # Không chỉ có SYN (đa dạng traffic)
    dst_port_entropy > 2.0      # Nhiều port khác nhau
)
```

Spoof flood có entropy CAO nhưng syn_pct CAO (>0.5) và dst_port_entropy THẤP (chỉ 1-2 port).

**Ngưỡng phát hiện: k-sigma rule (3-sigma)**

```python
anomaly = abs(giá_trị - baseline_mean) > 3 × baseline_std
```

Dựa trên phân phối chuẩn: 99.7% giá trị nằm trong [μ - 3σ, μ + 3σ].
Bất kỳ giá trị nào vượt ngoài là bất thường.

---

### 2.2 Stats Detector (stats.py)

**Vai trò:** Bổ trợ cho Entropy Detector. Trong khi Entropy phát hiện dựa trên **phân bố IP nguồn** (ai gửi?), Stats Detector phát hiện dựa trên **lưu lượng mạng** (gửi bao nhiêu?).

**Tại sao cần cả hai?**
- Entropy phát hiện tốt khi tấn công từ 1 IP (entropy giảm) hoặc nhiều IP giả (entropy tăng)
- Nhưng entropy KHÔNG phát hiện được nếu attacker giữ entropy bình thường mà chỉ tăng PPS
- Stats Detector bắt được trường hợp này: PPS/BPS tăng đột biến so với baseline

**Gồm 3 thuật toán thống kê, mỗi cái bắt một loại bất thường khác nhau:**

#### Z-Score (Phát hiện đột biến tức thì)

```
Z = (X - μ) / σ
```
- `|Z| > 3` → bất thường (vượt 3 độ lệch chuẩn)
- **Ưu điểm:** Phát hiện ngay lập tức khi PPS nhảy từ 10 lên 5000
- **Nhược điểm:** Không phát hiện được tăng chậm (từ 10 → 50 → 200 → 5000)

#### EWMA (Exponentially Weighted Moving Average - Phát hiện xu hướng)

```
EWMA_t = α × X_t + (1 - α) × EWMA_{t-1}
```
- `α = 0.3` (trọng số cho giá trị mới)
- Phát hiện khi `|X - EWMA| > 3 × σ`
- **Ưu điểm:** Theo dõi xu hướng, ít bị ảnh hưởng bởi spike đơn lẻ
- **Ví dụ:** PPS tăng dần 10 → 50 → 200 → EWMA nhận ra đang có xu hướng tăng

#### CUSUM (Cumulative Sum - E.S. Page, 1954 - Phát hiện tích lũy)

```
S_t = max(0, S_{t-1} + (X_t - μ - k))
Alert khi S_t > h
```
- `k = 0.5 × σ` (slack, tránh false positive)
- `h = 5 × σ` (ngưỡng alert)
- **Ưu điểm:** Phát hiện shift nhỏ nhưng liên tục (tích lũy theo thời gian)
- **Ví dụ:** PPS tăng nhẹ 10 → 15 → 20 → 25, mỗi lần tăng nhỏ nhưng CUSUM tích lũy và cuối cùng vượt ngưỡng

**Metrics được theo dõi:** pps (packets/sec), bps (bits/sec), new_flows_per_sec

**Trong detector.py, Stats Detector được gọi như sau:**
```python
stat_res = stat_det.check(features)
if stat_res.get("anomaly"):
    n_rules += 1           # Tăng số engine phát hiện bất thường
    evidence.extend(...)   # Thêm bằng chứng
```

Khi cả Entropy VÀ Stats đều phát hiện bất thường → độ tin cậy cao → chắc chắn là tấn công.

---

### 2.3 Signature Matcher (signature_matcher.py)

**Cơ sở lý thuyết: Rule-based Detection (kiểu Snort/Suricata)**

Mỗi loại tấn công có "dấu vân tay" đặc trưng được định nghĩa trong `attack_signatures.csv`:

| Tấn công | Rule | Giải thích |
|----------|------|------------|
| SYN Flood | `tcp_pct>0.5 AND entropy<1.5 AND pps>3000` | TCP chiếm đa số, 1 nguồn, PPS cực cao |
| UDP Flood | `udp_pct>0.5 AND entropy<1.5 AND pps>500` | UDP chiếm đa số, PPS cao |
| ICMP Flood | `icmp_pct>0.5 AND pps>500` | ICMP chiếm đa số, PPS cao |
| HTTP Flood | `tcp>0.8 AND entropy<1.5 AND 300<pps<3000` | TCP, PPS trung bình |
| DNS Ampl | `udp>0.5 AND entropy>3 AND pps>100` | UDP port 53, nhiều IP giả |
| IP Spoof | `entropy>3.5 AND pps>500` | Entropy rất cao (hàng nghìn IP giả) |
| Slowloris | `tcp>0.5 AND 30<pps<300 AND entropy<1.5` | TCP, PPS THẤP (tấn công chậm) |

**Độ ưu tiên:** Khi nhiều signature match, chọn rule có nhiều điều kiện nhất (cụ thể nhất):
```python
hits.sort(key=lambda h: h["_specificity"], reverse=True)
```

---

### 2.4 Kết hợp 3 tầng (detector.py)

```
Mỗi chu kỳ (~1 giây):
  1. Lấy flow stats từ Ryu REST API
  2. Tính features (pps, bps, entropy, tcp_pct, ...)
  3. Chạy 3 engine:
     - ent_det.check(features)  → anomaly True/False
     - stat_det.check(features) → anomaly True/False
     - sig_matcher.match(features) → danh sách signature match
  4. n_rules = số engine phát hiện bất thường
  5. Nếu n_rules >= 1 → gửi alert
```

**Guard chống false positive:**
- `MIN_PKTS_FOR_ALERT = 50`: Chỉ alert khi có đủ gói (tránh pingall bị nhầm)
- `WARMUP_CYCLES = 5`: Bỏ qua 5 chu kỳ đầu khi khởi động
- PPS guard: Nếu CHỈ signature match (không có stat/entropy) VÀ pps < 200 → bỏ qua

---

## 3. Spoof Detection (l3_router_test.py)

**Tại sao cần tách riêng?**

IP Spoof dùng `--rand-source` → mỗi gói có IP khác nhau → detector dựa trên flow stats KHÔNG thấy được vì switch gộp chung vào 1 flow rule. Phải detect trực tiếp từ `packet_in` event.

**Thuật toán:**

```
Mỗi 2 giây (SPOOF_WINDOW):
  Đếm packet_in count, unique_ips, MAC counter, protocol, port
  
  Nếu KHÔNG thỏa điều kiện → reset, tiếp tục
  
  Điều kiện SPOOF:
    - packet_in > 100 gói trong 2s
    - unique_ips > 20 IP duy nhất
    - unique_ips / total > 30% (tỷ lệ IP mới cao)
    
  Nếu thỏa → SPOOF DETECTED:
    - Xác định protocol + port (phân loại attack)
    - Block MAC address của attacker (vì IP giả, MAC không đổi)
    - Hard_timeout = 20s (tự động gỡ sau 20 giây)
```

**Phân loại dựa trên protocol:**
```python
if proto == UDP and port == 53 → s05_dns_ampl
elif proto == UDP             → s02_udp_flood (spoofed)
elif proto == ICMP            → s03_icmp_flood (spoofed)
else (TCP)                    → s06_ip_spoof
```

**Tại sao block MAC thay vì IP?**
Khi attacker dùng `--rand-source`, IP nguồn thay đổi liên tục → block IP vô nghĩa. Nhưng MAC address của attacker KHÔNG ĐỔI (do network interface của máy tấn công chỉ có 1 MAC).

---

## 4. Graduated Response (Mitigation)

**Cơ sở lý thuyết: Defense-in-Depth (RFC 4732 - DDoS Taxonomy)**

Hệ thống áp dụng 3 cấp phản hồi tăng dần, tránh over-reaction:

```
Cấp 1: LOG (INFO)
  → Ghi nhận cảnh báo, không can thiệp
  → Cho phép quan sát trước khi hành động

Cấp 2: RATE-LIMIT (WARN)
  → Giới hạn attacker xuống 1000 pps
  → Dùng OpenFlow Meter Table
  → Không chặn hoàn toàn, vẫn cho phép traffic hợp pháp

Cấp 3: BLOCK (CRITICAL)
  → Chặn hoàn toàn IP/MAC của attacker
  → Cài flow rule: priority=100, match=ip_src, actions=drop
  → Tự động gỡ chặn sau 20 giây (hard_timeout)
```

### 4.1 Block Module (mitigation.py)

```python
# Cài flow rule DROP trên switch
match = OFPMatch(eth_type=0x0800, ipv4_src=attacker_ip)
instructions = []  # Không có action = DROP
FlowMod(priority=100, match, instructions, hard_timeout=20s)
```

### 4.2 Rate-Limit Module (mitigation.py)

```python
# Tạo Meter với band DROP khi vượt 1000 pps
meter_band = OFPMeterBandDrop(rate=1000, burst=100)
MeterMod(command=ADD, flags=PKTPS, meter_id, bands=[band])

# Cài flow rule sử dụng meter
match = OFPMatch(eth_type=0x0800, ipv4_src=attacker_ip)
instructions = [InstructionMeter(meter_id), InstructionActions(OUTPUT:NORMAL)]
FlowMod(priority=80, match, instructions, hard_timeout=120s)
```

### 4.3 Blacklist Manager (mitigation.py)

```python
# Lưu {IP: thời_gian_hết_hạn}
entries = {"10.0.1.10": 1715000020}  # hết hạn sau 20s

# Tự động dọn dẹp mỗi 3 giây
while True:
    xóa các IP đã hết hạn
    sleep(3)
```

---

## 5. Logic các kịch bản tấn công

### s01: SYN Flood
```bash
hping3 -S -p 80 --flood VICTIM
```
- `-S`: SYN flag, `-p 80`: port 80, `--flood`: gửi nhanh nhất có thể
- **Mục đích:** Chiếm hết bảng kết nối (SYN queue) của server
- **Dấu hiệu:** entropy ~0, pps >3000, tcp_pct ~1.0, syn_pct ~1.0

### s02: UDP Flood
```bash
hping3 --udp -p 53 --flood VICTIM
```
- **Mục đích:** Làm nghẽn băng thông với gói UDP vô nghĩa
- **Dấu hiệu:** entropy ~0, pps >500, udp_pct >0.5

### s03: ICMP Flood (Ping of Death)
```bash
hping3 -1 --flood VICTIM
```
- `-1`: ICMP mode
- **Mục đích:** Làm nghẽn băng thông với ICMP Echo Request
- **Dấu hiệu:** entropy ~0, pps >500, icmp_pct >0.5

### s04: HTTP Flood
```bash
hping3 -S -p 80 -i u500 VICTIM
```
- `-i u500`: 1 gói mỗi 500 microsecond = ~2000 pps
- **Mục đích:** Làm quá tải web server với nhiều kết nối HTTP
- **Phân biệt với SYN Flood:** PPS thấp hơn (300-3000 vs >3000)

### s05: DNS Amplification
```bash
hping3 --udp -p 53 --rand-source -i u500 DNS_SERVER
```
- `--rand-source`: giả mạo IP nguồn (spoof victim IP)
- **Mục đích:** Gửi DNS query nhỏ (60B) → DNS trả lời lớn (3000B) → khuếch đại 50x
- **Tại sao hiệu quả:** Attacker gửi 1 Mbps → victim nhận 50 Mbps
- **Detection:** Controller packet_in detect (UDP + port 53 + nhiều IP nguồn giả)
- **Dấu hiệu:** entropy >8, UDP protocol, port 53

### s06: IP Spoof Flood
```bash
hping3 --rand-source -S -p 80 -i u500 VICTIM
```
- **Mục đích:** SYN flood với IP giả → victim không biết ai tấn công
- **Detection:** Packet_in monitor thấy nhiều IP lạ từ cùng 1 MAC
- **Dấu hiệu:** entropy >8, TCP protocol, 1 MAC nhiều IP

### s07: Slowloris
```bash
hping3 -S -p 80 -i u10000 VICTIM
```
- `-i u10000`: 1 gói mỗi 10ms = ~100 pps (CHẬM)
- **Mục đích:** Giữ nhiều kết nối HTTP mở cùng lúc, không bao giờ gửi xong request
- **Tại sao nguy hiểm:** PPS thấp nhưng chiếm hết connection pool của web server
- **Dấu hiệu:** entropy ~0, pps 30-300, tcp_pct >0.5

### s08: Flash Crowd (KHÔNG PHẢI TẤN CÔNG)
```bash
# 6 người dùng hợp pháp truy cập đồng thời
hping3 -a 10.0.4.10 -S -p 80   -i u50000 VICTIM &  # User 1: web
hping3 -a 10.0.4.11 -S -p 443  -i u50000 VICTIM &  # User 2: HTTPS
hping3 -a 10.0.4.12 -S -p 8080 -i u50000 VICTIM &  # User 3: API
hping3 -a 10.0.4.13 -S -p 80   -i u50000 VICTIM &  # User 4: web
hping3 -a 10.0.1.20 -S -p 443  -i u50000 VICTIM &  # User 5: HTTPS
hping3 -a 10.0.3.10 -S -p 3306 -i u50000 VICTIM &  # User 6: DB
```
- **Mục đích:** Mô phỏng traffic hợp pháp tăng đột biến (sale, event...)
- **Tại sao KHÔNG bị chặn:**
  - Tất cả IP nguồn đều nằm trong whitelist
  - PPS mỗi nguồn rất thấp (~20 pps)
  - Nhiều port khác nhau (entropy port cao)
  - syn_pct thấp (nhiều loại traffic)

---

## 6. Feature Extraction (feature_extraction.py)

Trích xuất features từ pcap file dùng sliding window:

| Feature | Công thức | Ý nghĩa |
|---------|-----------|---------|
| entropy_src_ip | `H(src_ip)` | Độ phân tán IP nguồn |
| entropy_dst_ip | `H(dst_ip)` | Độ phân tán IP đích |
| entropy_dst_port | `H(dst_port)` | Độ phân tán port đích |
| entropy_renyi_src | `H₂(src_ip)` | Rényi bậc 2 của IP nguồn |
| pps | `n_packets / window` | Packets per second |
| bps | `total_bytes × 8 / window` | Bits per second |
| syn_pct | `syn_count / total` | Tỷ lệ gói SYN |
| icmp_pct | `icmp_count / total` | Tỷ lệ gói ICMP |
| new_flows_per_sec | `new_5tuple / window` | Luồng mới/giây |
| avg_pkt_size | `total_bytes / n_packets` | Kích thước gói trung bình |

**Sliding window:** window=1s, slide=0.5s → overlap 50% để không bỏ sót

---

## 7. Dashboard (dashboard.py)

**4 trang:**
- `/` — Biểu đồ Entropy + PPS realtime, trạng thái hệ thống, IP/MAC bị chặn
- `/alerts` — Danh sách cảnh báo, chặn/gỡ chặn IP thủ công
- `/flows` — OpenFlow rules trên switch s2
- `/api/debug` — Raw data từ Ryu controller

**Cập nhật:** Mỗi 2 giây fetch `/api/stats` → lấy entropy, pps, attack_status, blocked_ips từ Ryu

---

## 8. Tham khảo

| Viện dẫn | Tác giả | Nội dung |
|----------|---------|----------|
| Shannon 1948 | C.E. Shannon | "A Mathematical Theory of Communication" — Shannon Entropy |
| Rényi 1961 | A. Rényi | "On Measures of Entropy and Information" — Rényi Entropy |
| Page 1954 | E.S. Page | "Continuous Inspection Schemes" — CUSUM algorithm |
| Kumar 2018 | A1 | SDN-based DDoS detection using entropy |
| Bhuyan 2015 | B4 | Network anomaly detection using entropy-based approach |
| RFC 4732 | IETF | "Internet Denial-of-Service Considerations" |
