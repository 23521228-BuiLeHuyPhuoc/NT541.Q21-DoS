# 🚀 QUICKSTART: Cách Chạy Hệ thống Phát hiện DoS (4 tuần)

**Tóm tắt:** 5 bước chính, từ chuẩn bị → Demo live

---

## 📁 CẤUTRÚC FILE (sau 4 tuần)

```
NT541.Q21-DDoS/
├── docs/
│   ├── LITERATURE_SURVEY.md          (TV1 Tuần 1)
│   ├── THEORY_BACKGROUND.md         (TV1 Tuần 1)
│   ├── ATTACK_SIGNATURES.md          (TV1 Tuần 2)
│   ├── EVALUATION_PROTOCOL.md        (TV1 Tuần 2)
│   ├── PHAN_CONG_CHI_TIET_FINAL.md   (Task assignment)
│   ├── PRESENTATION_STRUCTURE.md     (18-slide guide)
│   └── README.md                     (Project overview)
│
├── code/
│   ├── topology_nhom4.py             (có sẵn)
│   ├── l3_router.py                  (có sẵn)
│   ├── l3_router_extended.py         (TV4 viết)
│   ├── detection_entropy.py          (TV3 viết)
│   ├── detection_stats.py            (TV3 viết)
│   ├── attack_signature_matching.py  (TV3 viết)
│   ├── alert_system.py               (TV3 viết)
│   ├── mitigation_rate_limit.py      (TV4 viết)
│   ├── mitigation_dqos.py            (TV4 viết)
│   ├── mitigation_blacklist.py       (TV4 viết)
│   ├── feature_extraction.py         (TV2 viết)
│   ├── integration_test.py           (TV5 viết)
│   ├── visualization.py              (TV5 viết)
│   ├── capture_live.sh               (TV2 viết)
│   ├── demo.sh                       (TV5 viết)
│   └── requirements.txt              (dependencies)
│
├── data/
│   ├── flows_baseline.pcap           (TV2 Tuần 2)
│   ├── baseline_stats.json           (TV2 Tuần 2)
│   ├── dos_*.pcap (10 files)         (TV2 Tuần 2)
│   ├── feature_*.csv (11 files)      (TV2 Tuần 3)
│   └── attacks_metadata.json
│
├── results/
│   ├── test_results.json             (TV5 Tuần 3)
│   ├── alerts.json                   (TV3 Tuần 3)
│   ├── mitigation_actions.json       (TV4 Tuần 3)
│   ├── benchmark_results.json        (TV4 Tuần 3)
│   └── plots/
│       ├── entropy_timeline.png
│       ├── attack_stats_comparison.png
│       ├── detection_accuracy_roc.png
│       ├── latency_histogram.png
│       ├── mitigation_effectiveness.png
│       ├── traffic_pattern.png
│       ├── bandwidth_allocation.png
│       └── threshold_optimization.png
│
├── PRESENTATION.pptx                 (TV5 Tuần 4)
├── QA_SCRIPT.md                      (TV1 Tuần 4)
└── .gitignore
```

---

## 🏃‍♂️ WORKFLOW CHẠY (4 tuần)

### TUẦN 1: Chuẩn bị (Ngày 1-5)

**Step 1.1: Setup môi trường**
```bash
# Clone repo
git clone https://github.com/[user]/NT541.Q21-DDoS.git
cd NT541.Q21-DDoS

# Install Python dependencies
pip install -r requirements.txt
# ryu, mininet, scapy, pandas, matplotlib, numpy

# Verify Mininet installation
mininet --version
```

**Step 1.2: Kiểm chứng Lab (TV2)**
```bash
# Terminal 1: Start Mininet
sudo python3 code/topology_nhom4.py

# Terminal 2: Trong Mininet shell
mininet> h1 ping h2        # Test connectivity
mininet> h3 ping h4
mininet> h5 ping h6

# Terminal 3: Start Ryu controller
ryu-manager code/l3_router.py

# Terminal 2 (continue): Verify routing
mininet> h1 ping 10.0.2.1   # Should work
```

**Output mong đợi:** Lab chạy, tất cả host ping được nhau, Ryu log output

---

### TUẦN 2: Phát triển SONG SONG (Ngày 1-10)

#### **Dòng A: TV2 - Tạo dữ liệu**

**Step 2A.1: Thu thập Baseline (Ngày 1-2)**
```bash
# Terminal 1: Mininet running

# Terminal 2: Tcpdump capture
mkdir -p data/
sudo tcpdump -i s2-eth0 -w data/flows_baseline.pcap 'tcp or udp' &
sleep 1

# Terminal 3: Trong Mininet - tạo normal traffic (5 phút)
mininet> h_pc1 ab -n 1000 -c 10 http://h_web1   # HTTP traffic
mininet> h_pc1 dig @h_dns1 example.com           # DNS traffic
mininet> h_pc1 iperf -c h_app1 -t 300            # TCP background

# Sau 5 phút
sudo pkill tcpdump

# Extract stats
python3 code/feature_extraction.py data/flows_baseline.pcap data/baseline_stats.json
```

**Output:** `data/flows_baseline.pcap` (~50MB), `data/baseline_stats.json`

---

**Step 2A.2: Tạo 10 DoS Attacks (Ngày 2-5)**
```bash
# For each of 10 attacks:
for i in {1..10}; do
    sudo tcpdump -i s2-eth0 -w data/dos_attack_$i.pcap 'tcp or udp' &
    sleep 1
    
    # Trong Mininet - trigger attack (mỗi attack khác nhau)
    case $i in
        1) mininet> h_att1 hping3 -S --flood 10.0.2.1 ;;      # SYN flood
        2) mininet> h_att1 hping3 --udp --flood 10.0.2.1 ;;   # UDP flood
        3) mininet> h_att1 hping3 -R --flood 10.0.2.1 ;;      # RST flood
        4) mininet> h_att1 ab -n 50000 http://h_web1 ;;       # HTTP GET
        5) mininet> h_att1 ab -p post_data -n 5000 http://h_web1 ;; # HTTP POST
        6) mininet> h_att1 dig @h_dns1 example.com x 10000 ;; # DNS ampl
        7) mininet> h_att1 hping3 --spoof 10.0.3.1 10.0.2.1 ;; # IP spoof
        8) mininet> h_att1 hping3 -S 10.0.2.1 --rate 1 -c 600 ;; # Low-rate
        9) mininet> h_att1 h_ext1 hping3 -S --flood 10.0.2.1 ;; # Distributed
        10) mininet> nmap -p 1-65535 10.0.2.1 ; hping3 -S --flood 10.0.2.1 ;; # Port scan
    esac
    
    sleep 30  # Attack duration
    sudo pkill tcpdump
    sleep 2
done

# Result: data/dos_attack_1.pcap ... dos_attack_10.pcap
```

**Output:** 10 pcap files (~500MB tổng)

---

**Step 2A.3: Extract Features (Ngày 4-5)**
```bash
# Parse tất cả 11 pcap (1 baseline + 10 attacks)
python3 << 'EOF'
import os
import sys
sys.path.insert(0, 'code')
from feature_extraction import extract_features

pcap_files = ['data/flows_baseline.pcap'] + [f'data/dos_attack_{i}.pcap' for i in range(1, 11)]

for pcap in pcap_files:
    csv_out = pcap.replace('.pcap', '_features.csv')
    extract_features(pcap, csv_out)
    print(f"✓ {csv_out}")
EOF

# Result: data/*_features.csv (11 files)
# Mỗi file: timestamp, entropy_src, entropy_dst, pps, bps, syn%, rst%, ...
```

**Output:** 11 CSV files với 15+ metrics mỗi file

---

#### **Dòng B: TV3 - Xây Detection**

**Step 2B.1: Build Entropy Module (Ngày 1-4)**
```bash
# Tạo file: code/detection_entropy.py
cat > code/detection_entropy.py << 'EOF'
import math
from collections import defaultdict

class EntropyDetector:
    def __init__(self):
        self.baseline_h_src = 4.5  # Normal: 4-5 bits
        self.baseline_h_dst = 3.2
        
    def calculate_entropy(self, values):
        """Shannon entropy: H(X) = -Σ p(x) log2(p(x))"""
        if not values:
            return 0
        freq = defaultdict(int)
        for v in values:
            freq[v] += 1
        total = len(values)
        entropy = 0
        for count in freq.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy
    
    def detect_anomaly(self, src_ips, entropy_threshold=1.5):
        """Alert nếu entropy_src < 1.5 (SYN flood pattern)"""
        h_src = self.calculate_entropy(src_ips)
        if h_src < entropy_threshold:
            return {"alert": True, "attack": "SYN_FLOOD", "entropy": h_src}
        return {"alert": False, "entropy": h_src}

if __name__ == "__main__":
    detector = EntropyDetector()
    # Test data
    normal_src = ['10.0.1.1', '10.0.1.2', '10.0.1.3', '10.0.1.1', '10.0.1.2']
    syn_flood_src = ['10.0.1.10'] * 100  # Cùng nguồn
    
    print("Normal:", detector.detect_anomaly(normal_src))
    print("SYN Flood:", detector.detect_anomaly(syn_flood_src))
EOF

python3 code/detection_entropy.py
```

**Output:** Module hoạt động, test cases pass

---

**Step 2B.2: Build Stats Module (Ngày 2-4)**
```bash
cat > code/detection_stats.py << 'EOF'
class StatisticalDetector:
    def __init__(self):
        self.baseline_pps = 1000  # packets/sec
        self.baseline_std = 100
        
    def z_score_anomaly(self, current_pps, threshold=3):
        """Z-score > 3 → anomaly"""
        z = (current_pps - self.baseline_pps) / self.baseline_std
        return z > threshold
    
    def spike_detection(self, current_pps, spike_factor=5):
        """Alert nếu pps > 5x baseline"""
        return current_pps > self.baseline_pps * spike_factor
    
    def detect(self, current_pps):
        if self.z_score_anomaly(current_pps):
            return {"alert": True, "reason": "Z-score anomaly", "z": (current_pps - self.baseline_pps) / self.baseline_std}
        if self.spike_detection(current_pps):
            return {"alert": True, "reason": "Traffic spike", "factor": current_pps / self.baseline_pps}
        return {"alert": False}

if __name__ == "__main__":
    detector = StatisticalDetector()
    print("Normal:", detector.detect(1050))
    print("Spike:", detector.detect(6000))
EOF

python3 code/detection_stats.py
```

**Output:** Module hoạt động, test cases pass

---

#### **Dòng C: TV4 - Xây Mitigation**

**Step 2C.1: Ryu Blocking (Ngày 1-4)**
```bash
cat > code/l3_router_extended.py << 'EOF'
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4

class BlockingRyu(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(BlockingRyu, self).__init__(*args, **kwargs)
        self.blacklist = set()
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Install default rule: send to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 0, match, actions)
    
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)
    
    def block_source_ip(self, datapath, src_ip):
        """Install DROP rule for src_ip"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(ipv4_src=src_ip)
        actions = []  # Empty = DROP
        self.add_flow(datapath, 100, match, actions)
        self.logger.info(f"Blocked {src_ip}")
EOF
```

**Output:** Ryu app dengan blocking capability

---

### TUẦN 3: Integration & Testing (Ngày 1-15)

#### **Step 3.1: Signature Matching (TV3)**
```bash
cat > code/attack_signature_matching.py << 'EOF'
class SignatureMatcher:
    def match_attack(self, entropy_src, syn_pct, pps, baseline_pps):
        """Match traffic to attack type"""
        
        # SYN Flood
        if entropy_src < 1.5 and syn_pct > 50:
            return {"type": "SYN_FLOOD", "confidence": "HIGH"}
        
        # UDP Flood
        if pps > baseline_pps * 5 and entropy_src > 3:  # High pps, diverse src
            return {"type": "UDP_FLOOD", "confidence": "HIGH"}
        
        # IP Spoof
        if entropy_src > 6.5:
            return {"type": "IP_SPOOF", "confidence": "HIGH"}
        
        # Low-rate DoS
        if entropy_src < 2 and pps < baseline_pps * 1.5:
            return {"type": "LOW_RATE", "confidence": "MEDIUM"}
        
        return {"type": "UNKNOWN", "confidence": "LOW"}
EOF
```

---

#### **Step 3.2: Integration Test (TV5)**
```bash
# Start full pipeline
# Terminal 1: Mininet + Ryu
sudo python3 code/topology_nhom4.py &
sleep 2
ryu-manager code/l3_router_extended.py &
sleep 2

# Terminal 2: Detection + Mitigation listener
python3 << 'EOF'
import sys
sys.path.insert(0, 'code')
from detection_entropy import EntropyDetector
from attack_signature_matching import SignatureMatcher
from mitigation_blacklist import BlacklistManager

detector = EntropyDetector()
matcher = SignatureMatcher()
mitigation = BlacklistManager()

# Read alerts from alerts.json
import json
import time
while True:
    try:
        with open('results/alerts.json', 'r') as f:
            alerts = json.load(f)
            for alert in alerts:
                print(f"Alert: {alert}")
                # Mitigate
                mitigation.add_to_blacklist(alert['src_ip'])
    except:
        pass
    time.sleep(1)
EOF

# Terminal 3: In Mininet - trigger attack
mininet> h_att1 hping3 -S --flood 10.0.2.1
```

**Expected flow:**
1. Attack starts
2. Detection: entropy < 1.5
3. Alert: `{"attack": "SYN_FLOOD", "src_ip": "10.0.1.10"}`
4. Mitigation: Block installed
5. Traffic drops

**Output:** test_results.json (pass/fail)

---

#### **Step 3.3: Visualization (TV5)**
```bash
python3 code/visualization.py

# Outputs: results/plots/
# - entropy_timeline.png
# - detection_accuracy_roc.png
# - latency_histogram.png
# - mitigation_effectiveness.png
# ...
```

---

### TUẦN 4: Demo & Presentation (Ngày 1-5)

#### **Step 4.1: Live Demo Rehearsal**
```bash
# Setup (ngày 1-2)
# Terminal 1: Mininet
sudo python3 code/topology_nhom4.py

# Terminal 2: Ryu controller
ryu-manager code/l3_router_extended.py

# Terminal 3: Live capture
bash code/capture_live.sh

# Terminal 4: Run demo script
bash code/demo.sh

# Expected: 4 panes on projector
# - Mininet topology
# - Attack traffic (tcpdump)
# - Ryu alerts
# - Metrics
```

---

#### **Step 4.2: Presentation Slides**
```bash
# Generate from PRESENTATION_STRUCTURE.md
# Create PRESENTATION.pptx with 18 slides
# Include visualizations from results/plots/
```

---

## 🔧 REQUIREMENTS.txt

```
mininet==2.3.0
ryu==4.34
scapy==2.4.5
pandas==1.5.0
matplotlib==3.7.0
numpy==1.24.0
```

---

## 📊 SANITY CHECK: Test mỗi phần riêng

### TV1 - Papers & Theory
```bash
# Verify: LITERATURE_SURVEY.md tồn tại, >5000 từ
wc -w docs/LITERATURE_SURVEY.md  # Should be > 5000

# Verify: THEORY_BACKGROUND.md có công thức
grep "H(X)" docs/THEORY_BACKGROUND.md  # Should find formulas
```

### TV2 - Data Collection
```bash
# Verify: 11 pcap files + 11 CSV files
ls -lh data/*.pcap      # 11 files, ~500MB
ls -lh data/*_features.csv  # 11 files

# Verify: CSV có metrics
head data/flows_baseline_features.csv  # Should see: entropy, pps, syn%, etc.
```

### TV3 - Detection
```bash
# Test detection modules
python3 code/detection_entropy.py
python3 code/detection_stats.py
python3 code/attack_signature_matching.py

# Verify: alerts.json được tạo
ls -l results/alerts.json  # Should exist, >1MB
```

### TV4 - Mitigation
```bash
# Test Ryu app
ryu-manager code/l3_router_extended.py --verbose

# Verify: mitigation_actions.json được tạo
ls -l results/mitigation_actions.json
```

### TV5 - Integration & Visualization
```bash
# Test integration
python3 code/integration_test.py

# Verify: test_results.json, 8 plots
ls -l results/test_results.json
ls -l results/plots/*.png  # 8 files

# Verify: All metrics meet criteria
grep "TPR" results/test_results.json  # Should be >= 90%
grep "FPR" results/test_results.json  # Should be <= 5%
```

---

## 🎯 TIMELINE QUICK REF

| Tuần | Ngày | Đầu vào | Công việc | Đầu ra |
|---|---|---|---|---|
| **T1** | 1-5 | Survey 20-25 papers | Setup lab, theory | Lab chạy + Docs |
| **T2** | 6-15 | Theory từ TV1 | 3 dòng song song: Data (10 DoS), Detection (entropy+stats), Mitigation (Ryu) | 10 pcap + Detection modules + Ryu app |
| **T3** | 16-25 | Outputs từ T2 | Integration + Visualization + Testing | test_results.json + 8 plots + alerts |
| **T4** | 26-28 | Results từ T3 | Live demo + Presentation | Demo chạy + Slides + Docs finalized |

---

## ✅ FINAL CHECKLIST

- [ ] Tất cả code files được viết
- [ ] All 11 pcap files tạo xong
- [ ] Detection + Mitigation modules test OK
- [ ] Integration test: TPR ≥90%, FPR ≤5%
- [ ] 8 visualizations generated
- [ ] 18-slide presentation done
- [ ] Live demo tested 2+ times
- [ ] Q&A script reviewed
- [ ] GitHub push v1.0-final
