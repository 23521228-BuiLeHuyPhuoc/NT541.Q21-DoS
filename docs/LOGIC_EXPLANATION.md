# LOGIC TONG QUAN - HE THONG SDN DDoS DETECTION & MITIGATION

## 1. Kien truc tong the

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
    Doc flow stats      /api/entropy        OpenFlow 1.3
    tu Ryu REST API          |                   |
         |                   |         +---------+----------+
         +-------------------+-------->|  OVS Switches      |
                                       |  s1, s2, s3, s4    |
                                       +--------------------+
```

---

## 2. Detection Engine (3 tang)

He thong phat hien dua tren 3 detection engine doc lap:

### 2.1 Entropy Detector (entropy.py)

**Co so ly thuyet: Shannon Entropy (Claude Shannon, 1948)**

Shannon entropy do muc do "ngau nhien" trong phan phoi IP nguon:

```
H(X) = -Sum[ p(xi) * log2(p(xi)) ]
```

Trong do:
- `p(xi) = so_goi_tu_IP_i / tong_so_goi`
- `H(X) = 0` khi tat ca goi tu 1 IP (tan cong tu 1 nguon)
- `H(X)` cao khi nhieu IP khac nhau (traffic binh thuong hoac IP spoofing)

**Renyi Entropy (Alfred Renyi, 1961)**

Tong quat hoa cua Shannon, dung bac q=2 (Collision entropy):

```
H_q(X) = (1/(1-q)) * log2( Sum[ p(xi)^q ] )
```

Renyi bac 2 nhay cam hon voi phan phoi lech (mot vai IP chiem da so traffic).

**Cach phat hien:**

| Metric | Binh thuong | SYN/UDP/ICMP Flood | IP Spoof |
|--------|------------|---------------------|----------|
| Entropy | ~1.3 (baseline) | ~0 (1 IP) | >8 (hang ngan IP) |

**Phan biet flash crowd vs spoof flood:**

```python
is_flash_crowd = (
    entropy_src > 4.0 AND       # Nhieu IP khac nhau
    syn_pct < 0.3 AND           # Khong chi co SYN (da dang traffic)
    dst_port_entropy > 2.0      # Nhieu port khac nhau
)
```

Spoof flood co entropy CAO nhung syn_pct CAO (>0.5) va dst_port_entropy THAP (chi 1-2 port).

**Nguong phat hien: k-sigma rule (3-sigma)**

```python
anomaly = abs(value - baseline_mean) > 3 * baseline_std
```

Dua tren phan phoi chuan: 99.7% gia tri nam trong [mu - 3*sigma, mu + 3*sigma].
Bat ky gia tri nao vuot ngoai la bat thuong.

---

### 2.2 Stats Detector (stats.py)

**Gom 3 thuat toan thong ke:**

#### Z-Score

```
Z = (X - mu) / sigma
```
- `|Z| > 3` → bat thuong (vuot 3 do lech chuan)
- Ap dung cho: pps, bps, new_flows_per_sec

#### EWMA (Exponentially Weighted Moving Average)

```
EWMA_t = alpha * X_t + (1 - alpha) * EWMA_{t-1}
```
- `alpha = 0.3` (trong so cho gia tri moi)
- Phat hien khi `|X - EWMA| > 3 * sigma`
- Uu diem: theo doi xu huong, it bi anh huong boi spike don le

#### CUSUM (Cumulative Sum - E.S. Page, 1954)

```
S_t = max(0, S_{t-1} + (X_t - mu - k))
Alert khi S_t > h
```
- `k = 0.5 * sigma` (slack, tranh false positive)
- `h = 5 * sigma` (nguong alert)
- Uu diem: phat hien shift nho nhung lien tuc (tich luy theo thoi gian)

**Metrics duoc theo doi:** pps (packets/sec), bps (bits/sec), new_flows_per_sec

---

### 2.3 Signature Matcher (signature_matcher.py)

**Co so ly thuyet: Rule-based Detection (Snort/Suricata style)**

Moi loai tan cong co "dau van tay" dac trung duoc dinh nghia trong `attack_signatures.csv`:

| Tan cong | Rule | Giai thich |
|----------|------|------------|
| SYN Flood | `tcp_pct>0.5 AND entropy<1.5 AND pps>3000` | TCP chiem da so, 1 nguon, PPS cuc cao |
| UDP Flood | `udp_pct>0.5 AND entropy<1.5 AND pps>500` | UDP chiem da so, PPS cao |
| ICMP Flood | `icmp_pct>0.5 AND pps>500` | ICMP chiem da so, PPS cao |
| HTTP Flood | `tcp>0.8 AND entropy<1.5 AND 300<pps<3000` | TCP, PPS trung binh (khong nhanh bang SYN flood) |
| DNS Ampl | `udp>0.5 AND entropy>3 AND pps>100` | UDP port 53, nhieu IP (spoofed) |
| IP Spoof | `entropy>3.5 AND pps>500` | Entropy rat cao (hang ngan IP gia) |
| Slowloris | `tcp>0.5 AND 30<pps<300 AND entropy<1.5` | TCP, PPS THAP (tan cong cham) |

**Do uu tien:** Khi nhieu signature match, chon rule co nhieu dieu kien nhat (cu the nhat):
```python
hits.sort(key=lambda h: h["_specificity"], reverse=True)
```

---

### 2.4 Ket hop 3 tang (detector.py)

```
Moi chu ky (~1 giay):
  1. Lay flow stats tu Ryu REST API
  2. Tinh features (pps, bps, entropy, tcp_pct, ...)
  3. Chay 3 engine:
     - ent_det.check(features)  → anomaly True/False
     - stat_det.check(features) → anomaly True/False
     - sig_matcher.match(features) → danh sach signature match
  4. n_rules = so engine phat hien bat thuong
  5. Neu n_rules >= 1 → gui alert
```

**Guard chong false positive:**
- `MIN_PKTS_FOR_ALERT = 50`: Chi alert khi co du goi (tranh pingall bi nham)
- `WARMUP_CYCLES = 5`: Bo qua 5 chu ky dau khi khoi dong
- PPS guard: Neu CHI signature match (khong co stat/entropy) VA pps < 200 → bo qua

---

## 3. Spoof Detection (l3_router_test.py)

**Tai sao can tach rieng?**

IP Spoof dung `--rand-source` → moi goi co IP khac nhau → detector dua tren flow stats KHONG thay duoc vi switch gop chung vao 1 flow rule. Phai detect truc tiep tu `packet_in` event.

**Thuat toan:**

```
Moi 2 giay (SPOOF_WINDOW):
  Dem packet_in count, unique_ips, MAC counter
  
  Neu KHONG thoa dieu kien → reset, tiep tuc
  
  Dieu kien SPOOF:
    - packet_in > 100 goi trong 2s
    - unique_ips > 20 IP duy nhat
    - unique_ips / total > 30% (ty le IP moi cao)
    
  Neu thoa → SPOOF DETECTED:
    - Xac dinh protocol + port (phan loai attack)
    - Block MAC address cua attacker (vi IP gia, MAC khong doi)
    - Hard_timeout = 20s (tu dong go sau 20 giay)
```

**Phan loai dua tren protocol:**
```python
if proto == UDP and port == 53 → s05_dns_ampl
elif proto == UDP             → s02_udp_flood (spoofed)
elif proto == ICMP            → s03_icmp_flood (spoofed)
else (TCP)                    → s06_ip_spoof
```

**Tai sao block MAC thay vi IP?**
Khi attacker dung `--rand-source`, IP nguon thay doi lien tuc → block IP vo nghia. Nhung MAC address cua attacker KHONG DOI (do network interface cua may tan cong chi co 1 MAC).

---

## 4. Graduated Response (Mitigation)

**Co so ly thuyet: Defense-in-Depth (RFC 4732 - DDoS Taxonomy)**

He thong ap dung 3 cap phan hoi tang dan, tranh over-reaction:

```
Cap 1: LOG (INFO)
  → Ghi nhan canh bao, khong can thiep
  → Cho phep quan sat truoc khi hanh dong

Cap 2: RATE-LIMIT (WARN)  
  → Gioi han attacker xuong 1000 pps
  → Dung OpenFlow Meter Table
  → Khong chan hoan toan, van cho phep traffic hop phap

Cap 3: BLOCK (CRITICAL)
  → Chan hoan toan IP/MAC cua attacker
  → Cai flow rule: priority=100, match=ip_src, actions=drop
  → Tu dong go chan sau 20 giay (hard_timeout)
```

### 4.1 Block Module (mitigation.py)

```python
# Cai flow rule DROP tren switch
match = OFPMatch(eth_type=0x0800, ipv4_src=attacker_ip)
instructions = []  # Khong co action = DROP
FlowMod(priority=100, match, instructions, hard_timeout=20s)
```

### 4.2 Rate-Limit Module (mitigation.py)

```python
# Tao Meter voi band DROP khi vuot 1000 pps
meter_band = OFPMeterBandDrop(rate=1000, burst=100)
MeterMod(command=ADD, flags=PKTPS, meter_id, bands=[band])

# Cai flow rule su dung meter
match = OFPMatch(eth_type=0x0800, ipv4_src=attacker_ip)
instructions = [InstructionMeter(meter_id), InstructionActions(OUTPUT:NORMAL)]
FlowMod(priority=80, match, instructions, hard_timeout=120s)
```

### 4.3 Blacklist Manager (mitigation.py)

```python
# Luu {IP: thoi_gian_het_han}
entries = {"10.0.1.10": 1715000020}  # het han sau 20s

# Tu dong don dep moi 3 giay
while True:
    xoa cac IP da het han
    sleep(3)
```

---

## 5. Logic cac kich ban tan cong

### s01: SYN Flood
```bash
hping3 -S -p 80 --flood VICTIM
```
- `-S`: SYN flag, `-p 80`: port 80, `--flood`: gui nhanh nhat co the
- **Muc dich:** Chiem het bang ket noi (SYN queue) cua server
- **Dau hieu:** entropy ~0, pps >3000, tcp_pct ~1.0, syn_pct ~1.0

### s02: UDP Flood
```bash
hping3 --udp -p 53 --flood VICTIM
```
- **Muc dich:** Lam nghen bang thong voi goi UDP vo nghia
- **Dau hieu:** entropy ~0, pps >500, udp_pct >0.5

### s03: ICMP Flood (Ping of Death)
```bash
hping3 -1 --flood VICTIM
```
- `-1`: ICMP mode
- **Muc dich:** Lam nghen bang thong voi ICMP Echo Request
- **Dau hieu:** entropy ~0, pps >500, icmp_pct >0.5

### s04: HTTP Flood
```bash
hping3 -S -p 80 -i u500 VICTIM
```
- `-i u500`: 1 goi moi 500 microsecond = ~2000 pps
- **Muc dich:** Lam qua tai web server voi nhieu ket noi HTTP
- **Phan biet voi SYN Flood:** PPS thap hon (300-3000 vs >3000)

### s05: DNS Amplification
```bash
hping3 --udp -p 53 --rand-source -i u500 DNS_SERVER
```
- `--rand-source`: gia mao IP nguon (spoof victim IP)
- **Muc dich:** Gui DNS query nho (60B) → DNS tra loi lon (3000B) → khuech dai 50x
- **Tai sao hieu qua:** Attacker gui 1 Mbps → victim nhan 50 Mbps
- **Detection:** Controller packet_in detect (UDP + port 53 + nhieu IP nguon gia)
- **Dau hieu:** entropy >8, udp protocol, port 53

### s06: IP Spoof Flood
```bash
hping3 --rand-source -S -p 80 -i u500 VICTIM
```
- **Muc dich:** SYN flood voi IP gia → victim khong biet ai tan cong
- **Detection:** Packet_in monitor thay nhieu IP la tu cung 1 MAC
- **Dau hieu:** entropy >8, tcp protocol, 1 MAC nhieu IP

### s07: Slowloris
```bash
hping3 -S -p 80 -i u10000 VICTIM
```
- `-i u10000`: 1 goi moi 10ms = ~100 pps (CHAM)
- **Muc dich:** Giu nhieu ket noi HTTP mo cung luc, khong bao gio gui xong request
- **Tai sao nguy hiem:** PPS thap nhung chiem het connection pool cua web server
- **Dau hieu:** entropy ~0, pps 30-300, tcp_pct >0.5

### s08: Flash Crowd (KHONG PHAI TAN CONG)
```bash
# 6 nguoi dung hop phap truy cap dong thoi
hping3 -a 10.0.4.10 -S -p 80   -i u50000 VICTIM &  # User 1: web
hping3 -a 10.0.4.11 -S -p 443  -i u50000 VICTIM &  # User 2: HTTPS
hping3 -a 10.0.4.12 -S -p 8080 -i u50000 VICTIM &  # User 3: API
hping3 -a 10.0.4.13 -S -p 80   -i u50000 VICTIM &  # User 4: web
hping3 -a 10.0.1.20 -S -p 443  -i u50000 VICTIM &  # User 5: HTTPS
hping3 -a 10.0.3.10 -S -p 3306 -i u50000 VICTIM &  # User 6: DB
```
- **Muc dich:** Mo phong traffic hop phap tang dot bien (sale, event...)
- **Tai sao KHONG bi chan:**
  - Tat ca IP nguon deu nam trong whitelist
  - PPS moi nguon rat thap (~20 pps)
  - Nhieu port khac nhau (entropy port cao)
  - syn_pct thap (nhieu loai traffic)

---

## 6. Feature Extraction (feature_extraction.py)

Trich xuat features tu pcap file dung sliding window:

| Feature | Cong thuc | Y nghia |
|---------|-----------|---------|
| entropy_src_ip | `H(src_ip)` | Do phan tan IP nguon |
| entropy_dst_ip | `H(dst_ip)` | Do phan tan IP dich |
| entropy_dst_port | `H(dst_port)` | Do phan tan port dich |
| entropy_renyi_src | `H_2(src_ip)` | Renyi bac 2 cua IP nguon |
| pps | `n_packets / window` | Packets per second |
| bps | `total_bytes * 8 / window` | Bits per second |
| syn_pct | `syn_count / total` | Ty le goi SYN |
| icmp_pct | `icmp_count / total` | Ty le goi ICMP |
| new_flows_per_sec | `new_5tuple / window` | Luong moi/giay |
| avg_pkt_size | `total_bytes / n_packets` | Kich thuoc goi trung binh |

**Sliding window:** window=1s, slide=0.5s → overlap 50% de khong bo sot

---

## 7. Dashboard (dashboard.py)

**4 trang:**
- `/` — Bieu do Entropy + PPS realtime, trang thai he thong, IP/MAC bi chan
- `/alerts` — Danh sach canh bao, chan/go chan IP thu cong
- `/flows` — OpenFlow rules tren switch s2
- `/api/debug` — Raw data tu Ryu controller

**Cap nhat:** Moi 2 giay fetch `/api/stats` → lay entropy, pps, attack_status, blocked_ips tu Ryu

---

## 8. Tham khao

| Vien dan | Tac gia | Noi dung |
|----------|---------|----------|
| Shannon 1948 | C.E. Shannon | "A Mathematical Theory of Communication" — Shannon Entropy |
| Renyi 1961 | A. Renyi | "On Measures of Entropy and Information" — Renyi Entropy |
| Page 1954 | E.S. Page | "Continuous Inspection Schemes" — CUSUM algorithm |
| Kumar 2018 | A1 | SDN-based DDoS detection using entropy |
| Bhuyan 2015 | B4 | Network anomaly detection using entropy-based approach |
| RFC 4732 | IETF | "Internet Denial-of-Service Considerations" |
