# GIẢI THÍCH LOGIC - HỆ THỐNG SDN DDoS DETECTION & MITIGATION

## 1. Kiến trúc tổng thể

```
+------------------+                   +--------------------+
|  Detector        |    /api/alert     | Ryu Controller     |
|  detector.py     +------------------>| l3_router_test.py  |
|                  |                   | l3_router_extended |
|  - entropy.py    |                   +--------+-----------+
|  - stats.py      |                            |
|  - signature_    |                        OpenFlow 1.3
|    matcher.py    |                            |
+--------+---------+                   +--------+-----------+
         |                             |  OVS Switches      |
    Đọc flow stats từ Ryu REST API     |  s1, s2, s3, s4    |
                                       +--------------------+
         +------------------+
         |   Dashboard      |  (Flask :8080)
         |   /api/stats     +---> Đọc từ Ryu /api/entropy
         +------------------+
```

---

## 2. Tầng 1: Entropy Detector (`entropy.py`)

### 2.1 Shannon Entropy — Công thức

```
H(X) = -Σ[ p(xi) × log₂(p(xi)) ]
```

**Trong code (`entropy.py`, dòng 5-7):**
```python
def shannon(items):
    c = Counter(items); n = sum(c.values())
    return -sum((v/n)*math.log2(v/n) for v in c.values()) if n else 0
```

- `items` = danh sách IP nguồn trong 1 window (ví dụ: `['10.0.1.10', '10.0.1.10', '10.0.2.10']`)
- `Counter(items)` = đếm số lần xuất hiện mỗi IP: `{'10.0.1.10': 2, '10.0.2.10': 1}`
- `v/n` = `p(xi)` = xác suất IP đó xuất hiện (2/3 và 1/3)
- Kết quả: `H = -(2/3 × log₂(2/3) + 1/3 × log₂(1/3))` ≈ 0.918

**Được gọi ở đâu?**
- `feature_extraction.py` dòng 185: `shannon(src_ips)` → tính entropy IP nguồn cho mỗi window khi trích xuất features từ pcap
- `l3_router_test.py` dòng 389: tính entropy thực tế từ IP trong spoof detection window

**Dùng để làm gì?**
- Entropy = 0 → tất cả gói từ 1 IP → nghi ngờ tấn công flood (SYN/UDP/ICMP)
- Entropy cao (>8) → hàng nghìn IP khác nhau → nghi ngờ IP spoofing
- Entropy ~1.3 → bình thường (vài người dùng)

### 2.2 Rényi Entropy — Công thức

```
H_q(X) = (1/(1-q)) × log₂( Σ[ p(xi)^q ] )     (q = 2)
```

**Trong code (`entropy.py`, dòng 9-13):**
```python
def renyi(items, q=2):
    c = Counter(items); n = sum(c.values())
    s = sum((v/n)**q for v in c.values())
    return (1/(1-q)) * math.log2(s) if s > 0 else 0
```

**Dùng để làm gì?**
Rényi bậc 2 nhạy cảm hơn Shannon khi có IP chiếm đa số traffic. Ví dụ: nếu 1 IP gửi 90% traffic và 10 IP khác gửi 10%, Shannon vẫn cho giá trị khá cao nhưng Rényi giảm mạnh hơn → phát hiện sớm hơn.

**Được gọi ở đâu?**
- `feature_extraction.py` dòng 188: `renyi(src_ips)` → tính Rényi entropy cho mỗi window
- `entropy.py` dòng 48: kiểm tra `entropy_renyi_src` có vượt ngưỡng 3σ không

### 2.3 Ngưỡng phát hiện: 3-sigma rule

```
bất_thường = |giá_trị - μ_baseline| > 3 × σ_baseline
```

**Trong code (`entropy.py`, dòng 52-55):**
```python
mu, sig = self.mu.get(mu_key, 0), self.sigma.get(mu_key, 1)
if abs(v - mu) > self.k * sig:       # self.k = 3
    alerts.append({"source": "entropy", "feature": key, ...})
```

- `mu` và `sigma` được đọc từ `datasets/baseline_stats.json` (entropy bình thường: μ=1.298, σ=0.290)
- Ví dụ: entropy = 0 → |0 - 1.298| = 1.298 > 3 × 0.290 = 0.870 → **BẤT THƯỜNG**
- Ví dụ: entropy = 1.1 → |1.1 - 1.298| = 0.198 < 0.870 → **bình thường**

### 2.4 Phân biệt flash crowd vs spoof flood

**Trong code (`entropy.py`, dòng 33-40):**
```python
is_flash_crowd = (
    entropy_src > 4.0 and          # Nhiều IP khác nhau
    syn_pct < 0.3 and              # Không chỉ có SYN
    dst_port_entropy > 2.0         # Nhiều port khác nhau
)
if is_flash_crowd:
    return {"anomaly": False}      # KHÔNG phải tấn công
```

**Tại sao logic này đúng?**
| | Flash Crowd | Spoof Flood |
|---|---|---|
| Entropy IP | Cao (nhiều user thật) | Cao (nhiều IP giả) |
| syn_pct | Thấp (<0.3, đa dạng traffic) | Cao (>0.5, chỉ SYN) |
| Entropy port | Cao (80, 443, 8080, 3306...) | Thấp (chỉ port 80) |

---

## 3. Tầng 2: Stats Detector (`stats.py`)

**Vai trò:** Entropy phát hiện dựa trên **phân bố IP** (ai gửi?). Stats phát hiện dựa trên **lưu lượng** (gửi bao nhiêu?). Hai tầng bổ sung cho nhau.

### 3.1 Z-Score — Phát hiện đột biến tức thì

```
Z = (X - μ) / σ        bất thường khi |Z| > 3
```

**Trong code (`stats.py`, dòng 17-20):**
```python
def zscore(self, key, x):
    mu, sig = self.mu[key], max(self.sigma[key], 1e-6)
    z = (x - mu) / sig
    return {"alert": abs(z) > 3, "score": z}
```

- `key` = "pps", `x` = PPS hiện tại (ví dụ: 5000)
- `mu` = PPS baseline trung bình (11.4), `sig` = độ lệch chuẩn (6.4)
- `z = (5000 - 11.4) / 6.4 = 779` → **|779| > 3 → BẤT THƯỜNG**
- Khi PPS = 15: `z = (15 - 11.4) / 6.4 = 0.56` → |0.56| < 3 → bình thường

### 3.2 EWMA — Phát hiện xu hướng tăng dần

```
EWMA_t = α × X_t + (1 - α) × EWMA_{t-1}      (α = 0.3)
```

**Trong code (`stats.py`, dòng 22-26):**
```python
def ewma_check(self, key, x):
    self.ewma[key] = self.alpha * x + (1-self.alpha) * self.ewma[key]
    dev = abs(x - self.ewma[key])
    return {"alert": dev > 3*self.sigma[key]}
```

**Ví dụ thực tế:** PPS tăng dần: 10 → 50 → 200 → 800
- Bước 1: EWMA = 0.3×10 + 0.7×11.4 = 10.98 → dev = |10-10.98| = 0.98 → OK
- Bước 2: EWMA = 0.3×50 + 0.7×10.98 = 22.69 → dev = |50-22.69| = 27.31 → OK
- Bước 3: EWMA = 0.3×200 + 0.7×22.69 = 75.88 → dev = |200-75.88| = 124.12 → **BẤT THƯỜNG** (>3×6.4=19.2)

### 3.3 CUSUM — Phát hiện tích lũy (E.S. Page, 1954)

```
S_t = max(0, S_{t-1} + X_t - μ - k)      Alert khi S_t > h
```

**Trong code (`stats.py`, dòng 28-36):**
```python
def cusum_check(self, key, x):
    mu, sig = self.mu[key], max(self.sigma[key], 1e-6)
    k = self.k_factor * sig        # k = 0.5 × 6.4 = 3.2 (slack)
    h = self.h_factor * sig        # h = 5 × 6.4 = 32 (ngưỡng)
    self.cusum[key] = max(0, self.cusum[key] + (x - mu - k))
    alert = self.cusum[key] > h
```

**Ví dụ thực tế:** PPS tăng nhẹ liên tục: 20, 25, 30, 20, 25
- S₁ = max(0, 0 + 20 - 11.4 - 3.2) = 5.4
- S₂ = max(0, 5.4 + 25 - 11.4 - 3.2) = 15.8
- S₃ = max(0, 15.8 + 30 - 11.4 - 3.2) = 31.2
- S₄ = max(0, 31.2 + 20 - 11.4 - 3.2) = 36.6 → **> 32 → ALERT!**

Mỗi lần tăng nhỏ nhưng CUSUM tích lũy và cuối cùng vượt ngưỡng.

### 3.4 Kết hợp trong detector.py

**Trong code (`detector.py`, dòng 200-209):**
```python
ent_res = ent_det.check(features)        # Tầng 1: Entropy
stat_res = stat_det.check(features)       # Tầng 2: Stats
sig_hits = sig_matcher.match(features)    # Tầng 3: Signature

n_rules = 0
if ent_res.get("anomaly"): n_rules += 1  # Entropy bất thường → +1
if stat_res.get("anomaly"): n_rules += 1  # Stats bất thường → +1
if sig_hits: n_rules += len(sig_hits)      # Signature match → +N
```

- `n_rules = 0` → bình thường
- `n_rules = 1` → cấp 1 (LOG)
- `n_rules = 2` → cấp 2 (RATE-LIMIT)
- `n_rules >= 3` → cấp 3 (BLOCK)

---

## 4. Tầng 3: Signature Matcher (`signature_matcher.py`)

**Trong code (`signature_matcher.py`, dòng 49-62):**
```python
def match(self, features):
    for r in self.rules:
        rule_text = r.get('rule', '')           # "tcp_pct>0.5 AND pps>3000"
        if safe_eval(rule_text, features):       # Đánh giá rule với features hiện tại
            hits.append({"attack": r['name']})   # Match → thêm vào kết quả
    hits.sort(key=lambda h: h["_specificity"], reverse=True)
```

`safe_eval` parse rule thành AST Python và đánh giá an toàn:
- Input: `"tcp_pct>0.5 AND pps>3000"`, features = `{"tcp_pct": 0.95, "pps": 5000}`
- Kết quả: `0.95 > 0.5 AND 5000 > 3000` → `True` → match s01_syn_flood

---

## 5. Spoof Detection (`l3_router_test.py`)

**Tại sao cần tách riêng?** IP Spoof dùng `--rand-source` → mỗi gói có IP khác → switch cài 1 flow rule cho TẤT CẢ → detector đọc flow stats chỉ thấy 1 entry → KHÔNG phát hiện được. Phải detect trực tiếp từ `packet_in`.

**Trong code (`l3_router_test.py`, dòng 287-310):**
```python
# Mỗi packet_in từ IP không nằm trong whitelist:
self._pktin_count += 1
self._pktin_unique_ips.add(p_ip.src)
self._pktin_mac_counter[p_eth.src] += 1
self._pktin_proto_counter[p_ip.proto] += 1

# Mỗi 2 giây kiểm tra:
if now - self._pktin_window_start >= 2:
    self._check_spoof_flood(dp, victim_ip)
```

**Điều kiện phát hiện (`l3_router_test.py`, dòng 370-380):**
```python
if (self._pktin_count < 100 or             # < 100 gói → bình thường
    len(unique_ips) < 20 or                 # < 20 IP → bình thường
    len(unique_ips)/self._pktin_count < 0.3):  # Tỷ lệ IP mới < 30%
    return  # KHÔNG phải spoof
```

**Block MAC thay vì IP (`l3_router_test.py`, dòng 446-450):**
```python
match = parser.OFPMatch(eth_src=top_mac)     # Match theo MAC attacker
mod = parser.OFPFlowMod(datapath=dp, priority=100,
                        match=match, instructions=[],  # Không action = DROP
                        hard_timeout=20)                # Tự gỡ sau 20s
dp.send_msg(mod)
```

---

## 6. Graduated Response (`l3_router_extended.py`)

**Trong code (`l3_router_extended.py`, dòng 93-116):**
```python
if action == 'Logged':        # Cấp 1: Ghi nhận
    self.attack_status = 1

elif action == 'Rate-Limited': # Cấp 2: Giới hạn tốc độ
    self.ratelimit.apply(dp, src, pps=1000)

else:                          # Cấp 3: Chặn hoàn toàn
    self.block.apply(dp, src, timeout=20)
    self.blocked_ips.add(src)
```

**Block Module (`mitigation.py`, dòng 9-16):**
```python
# Cài flow rule: match IP nguồn, không có action → DROP
match = OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
instructions = []  # Rỗng = DROP tất cả gói từ IP này
FlowMod(priority=100, match=match, instructions=[], hard_timeout=20)
```

**Rate-Limit Module (`mitigation.py`, dòng 24-42):**
```python
# Bước 1: Tạo Meter giới hạn 1000 pps
band = OFPMeterBandDrop(rate=1000, burst=100)  # Vượt 1000 pps → DROP
MeterMod(command=ADD, flags=PKTPS, meter_id=mid, bands=[band])

# Bước 2: Cài flow rule sử dụng meter
instructions = [InstructionMeter(meter_id),     # Áp dụng meter
                InstructionActions(OUTPUT:NORMAL)] # Cho phép traffic dưới ngưỡng
FlowMod(priority=80, match=match, instructions=inst, hard_timeout=120)
```

---

## 7. Logic các kịch bản tấn công

### s01: SYN Flood — `hping3 -S -p 80 --flood VICTIM`
- `--flood`: gửi nhanh nhất có thể (>3000 pps)
- **Detection:** Entropy ~0 (1 IP) + PPS >3000 + tcp_pct ~1.0 → match signature s01

### s02: UDP Flood — `hping3 --udp -p 53 --flood VICTIM`
- **Detection:** Entropy ~0 + PPS >500 + udp_pct >0.5 → match signature s02

### s03: ICMP Flood — `hping3 -1 --flood VICTIM`
- **Detection:** PPS >500 + icmp_pct >0.5 → match signature s03

### s04: HTTP Flood — `hping3 -S -p 80 -i u500 VICTIM`
- `-i u500`: 2000 pps (chậm hơn SYN flood)
- **Detection:** tcp_pct >0.8 + 100 < PPS < 3000 → match s04 (không phải s01)

### s05: DNS Amplification — `hping3 --udp -p 53 --rand-source -i u500 DNS`
- `--rand-source`: giả mạo IP nguồn → entropy rất cao
- **Detection:** Controller packet_in thấy UDP + port 53 + nhiều IP giả → s05_dns_ampl
- **Block:** MAC (vì IP giả)

### s06: IP Spoof — `hping3 --rand-source -S -p 80 -i u500 VICTIM`
- **Detection:** Controller packet_in thấy TCP + port 80 + nhiều IP giả → s06_ip_spoof
- **Block:** MAC

### s07: Slowloris — `hping3 -S -p 80 -i u10000 VICTIM`
- `-i u10000`: chỉ 100 pps (tấn công chậm)
- **Detection:** tcp_pct >0.5 + 30 < PPS < 300 + entropy <1.5 → match s07

### s08: Flash Crowd — 1 user hợp pháp, nhiều kết nối
- **KHÔNG bị chặn** vì: IP thật không spoofing, PPS thấp, nhiều port khác nhau, entropy port cao, entropy IP thấp.

---

## 8. Bảng tóm tắt

| Kịch bản | Entropy | PPS | Phát hiện bởi | Chặn |
|----------|---------|-----|---------------|------|
| s01 SYN Flood | ~0 | >3000 | Entropy + Stats + Signature | IP |
| s02 UDP Flood | ~0 | >500 | Entropy + Stats + Signature | IP |
| s03 ICMP Flood | ~0 | >500 | Stats + Signature | IP |
| s04 HTTP Flood | ~0 | 100-3000 | Entropy + Stats + Signature | IP |
| s05 DNS Ampl | ~9 | >500 | Packet_in (UDP:53 + spoof) | MAC |
| s06 IP Spoof | ~9 | >500 | Packet_in (TCP + spoof) | MAC |
| s07 Slowloris | ~0 | 30-300 | Stats + Signature | IP |
| s08 Flash Crowd | ~0 | ~120 | **Không phát hiện** | **Không** |

---

## 9. Tham khảo

| Viện dẫn | Tác giả | Nội dung |
|----------|---------|----------|
| Shannon 1948 | C.E. Shannon | "A Mathematical Theory of Communication" — Shannon Entropy |
| Rényi 1961 | A. Rényi | "On Measures of Entropy and Information" — Rényi Entropy |
| Page 1954 | E.S. Page | "Continuous Inspection Schemes" — Thuật toán CUSUM |
| Kumar 2018 | A1 | SDN-based DDoS detection using entropy |
| Bhuyan 2015 | B4 | Network anomaly detection using entropy-based approach |
| RFC 4732 | IETF | "Internet Denial-of-Service Considerations" |
