# TASK ASSIGNMENT V3 FINAL - DoS Detection using SDN with Scientific Basis

**V3 Features:**

- ✅ **Code Inheritance**: topology_nhom4.py + l3_router.py (extended)
- ✅ **Scientific Foundation**: 20-25 IEEE/ACM/Springer papers
- ✅ **Specific Methods**: Entropy + Statistical methods (no redundancy)
- ✅ **Advanced Mitigation**: DQoS, traffic shaping, multi-level filtering
- ✅ **Parallelization**: 3 independent streams (Data, Detection, Mitigation)
- ✅ **Timeline**: 3-4 weeks, 5 team members

---

## 📚 PART I: THEORY AND SCIENTIFIC FOUNDATION

### 1. BACKGROUND ON DoS ATTACKS

**Paper References:**

- A1: Kaur et al. (2012) - Entropy-based anomaly detection
- B1-B3: Layer 4/7 DDoS surveys (2018-2020)
- C1: SDN DDoS defense mechanisms

**Content Member 1 must prepare:**

```
THEORY_BACKGROUND.md
├── 1. DDoS Classification
│   ├── Layer 4 (Transport): SYN, UDP, ACK, FIN, RST floods
│   ├── Layer 7 (Application): HTTP, DNS, SMTP floods
│   ├── Spoofing attacks: IP spoofing + source entropy analysis
│   └── Low-rate attacks: Hard to detect (entropy + timing analysis)
│
├── 2. Why Entropy?
│   ├── Shannon entropy: H(X) = -Σ p(x) log₂(p(x))
│   ├── Normal traffic: diverse sources → entropy ≈ 4-5 bits
│   ├── Flood attack: same source → entropy ≈ 0-1 bits
│   ├── Spoofed attack: random sources → entropy ≈ 6-8 bits
│   └── Paper: "Entropy-based Anomaly Detection" (A1)
│
├── 3. Statistical Methods for Detection
│   ├── Rate anomaly: (current_rate - baseline_rate) / baseline_std > 3σ
│   ├── Flag ratios: SYN%, RST%, ACK% deviations
│   ├── Flow count spike: new_flows > baseline * 5
│   └── Paper: "Flow-based Botnet Detection" (A2)
│
└── 4. SDN-based Mitigation
    ├── Reactive vs Proactive defense
    ├── OpenFlow FlowMod: install rate-limit rules
    ├── DQoS: priority queues
    ├── Traffic shaping: token bucket, leaky bucket
    └── Paper: "SDN DDoS Detection" (A3)
```

---

### 2. ARCHITECTURE OVERVIEW (Code Inheritance)

```
CURRENT STATE (already have):
  topology_nhom4.py → 5 switches, 8 hosts, 4 zones
  l3_router.py      → Ryu L3 router + flow stats + port stats
  l3_router_test.py → Demo with basic entropy checking

TO DEVELOP (V3 goal):

  ┌─────────────────────────────────────────────────────────────┐
  │          MEMBER 1: Theory Lead                             │
  │  • Review 20-25 papers (IEEE/ACM)                          │
  │  • Write THEORY_BACKGROUND.md (3000+ words)                │
  │  • Link papers to detection/mitigation methods             │
  │  • Define attack signatures from literature                │
  └─────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
  ┌───────▼────────┐  ┌──────▼─────────┐  ┌─────▼───────────┐
  │   MEMBER 2     │  │  MEMBER 3      │  │  MEMBER 4       │
  │   DATA LAYER   │  │  DETECTION     │  │  MITIGATION     │
  │                │  │  LAYER         │  │  LAYER          │
  │ • Generate     │  │                │  │                 │
  │   10 DoS types │  │ • Extract 15+  │  │ • Ryu l3_router │
  │ • Feature extr │  │   entropy stats│  │   (extend)      │
  │ • Real-time    │  │ • Signature    │  │ • Add DQoS      │
  │   capture      │  │   matching     │  │ • Traffic shape │
  │ • Pcap files   │  │ • Alert system │  │ • Priority flow │
  └────────────────┘  └────────────────┘  └─────────────────┘
          │                   │                   │
          └───────────────────┼───────────────────┘
                              │
  ┌─────────────────────────────────────────────────────────────┐
  │  MEMBER 5: Testing & Integration                            │
  │  • Combine 2+3+4 together                                   │
  │  • Test end-to-end: attack → detect → mitigate → measure   │
  │  • Visualization: 8+ plots                                  │
  │  • Live demo: 15-20 min presentation                        │
  └─────────────────────────────────────────────────────────────┘
```

---

## 📋 PART II: DETAILED TASK ASSIGNMENT

### 👤 MEMBER 1: Ngô Thị Mai Anh (Theory + Research Lead)

| ID      | Task                                    | Week | Details                                                                                                                                                                                                                                                                                                                                 | Deadline   | Deliverables                                      | Papers                            |
| ------- | --------------------------------------- | ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ------------------------------------------------- | --------------------------------- |
| **1.1** | **Literature Survey (20-25 papers)**    | 1    | • GROUP A (4 papers): Entropy-based detection<br>• GROUP B (5 papers): Flow-based + statistical methods<br>• GROUP C (5 papers): SDN architecture + OpenFlow<br>• GROUP D (3 papers): DDoS mitigation strategies<br>• GROUP E (4 papers): Real-time detection systems<br>• Organize: Title, Authors, Year, DOI, Key insights, Relevance | End Week 1 | `LITERATURE_SURVEY.md` (5000+ words, IEEE format) | A1-A4, B1-B5, C1-C5, D1-D3, E1-E4 |
| **1.2** | **Theoretical Framework**               | 1    | • Shannon entropy formula + explanation<br>• Statistical anomaly detection:<br> - Z-score: (x - mean)/std<br> - Moving average baseline<br> - Deviation thresholds<br>• DDoS attack taxonomy (L4/L7, spoofing, low-rate)<br>• Why each method works for each attack<br>• Create decision tree                                           | End Week 1 | `THEORY_BACKGROUND.md` (3000+ words, diagrams)    | A1-A3, B1-B3                      |
| **1.3** | **Attack Signatures from Literature**   | 1-2  | • Map each paper's findings to detection rules:<br> - SYN flood → SYN% > 60%, entropy < 2<br> - UDP flood → pps > 5x baseline<br> - DNS ampl → DNS_resp/DNS_req > 10x<br> - IP spoof → entropy > 6 bits<br> - Low-rate → timing + entropy<br>• Create table: Attack → Paper → Rule → Thresholds                                         | Week 2     | `ATTACK_SIGNATURES.md` (1500+ words, CSV)         | Cross-reference all groups        |
| **1.4** | **Evaluation Protocol**                 | 1-2  | • Define metrics with paper backing:<br> - TPR/FPR per attack<br> - Detection latency < 3 sec<br> - Mitigation effectiveness<br>• Test dataset: 70% train, 30% test<br>• Acceptance: TPR ≥90%, FPR ≤5%                                                                                                                                  | End Week 2 | `EVALUATION_PROTOCOL.md` (1000+ words)            | B2, B3, E1                        |
| **1.5** | **Code Review & Integration Oversight** | 2-4  | • Weekly checklist:<br> - Week 2: Review M2 features, M3 detection, M4 mitigation<br> - Week 3: Verify accuracy vs papers<br> - Week 4: Final paper linking<br>• Ensure all code has citations                                                                                                                                          | Week 4     | Weekly logs, code with citations                  |                                   |

---

### 👤 MEMBER 2: Đỗ Hoàng Phúc (Data Generation + Feature Extraction)

**Reuses**: topology_nhom4.py (no changes)

| ID      | Task                                                  | Week | Details                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Deadline   | Deliverables                                 | Theory Basis             |
| ------- | ----------------------------------------------------- | ---- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | -------------------------------------------- | ------------------------ |
| **2.1** | **Lab Verification**                                  | 1    | • Start topology_nhom4.py<br>• Verify: all 5 switches online, 8 hosts connected<br>• Test connectivity: each host ping others<br>• Setup monitoring: tcpdump on s2                                                                                                                                                                                                                                                                                                                                                                                                                                                     | End Week 1 | Lab running, tcpdump ready                   | -                        |
| **2.2** | **Baseline Traffic Collection**                       | 1-2  | • Normal traffic: 5 minutes<br> - h_pc1 → h_web1: HTTP (Apache Bench)<br> - h_pc1 → h_dns1: DNS queries (dig)<br> - h_pc1 → h_app1: TCP connections<br>• Capture: flows.pcap<br>• Extract: baseline_stats.json                                                                                                                                                                                                                                                                                                                                                                                                         | End Week 2 | `flows_baseline.pcap`, `baseline_stats.json` | B1: Flow-based detection |
| **2.3** | **Generate 10 DoS Attack Scenarios (DIFFERENTIATED)** | 2    | **Layer 4 Floods (3):**<br>1. SYN Flood: hping3 -S --flood, entropy <1 bit<br>2. UDP Flood: 5k+ pps, different entropy signature<br>3. ACK+RST Flood: >30% RST packets (vs <5% baseline)<br><br>**Layer 7 Floods (3):**<br>4. HTTP GET: 500+ req/sec, established conns<br>5. HTTP POST: Large bodies, tests traffic shaping<br>6. DNS Amplification: DNS_resp >> DNS_req (10x)<br><br>**Spoofing + Low-Rate (4):**<br>7. IP Spoof: Random src IPs, entropy >6 bits<br>8. Low-Rate: 1 req/sec for 10 min (stealthy)<br>9. Distributed: Multi-source (h_att1+h_ext1)<br>10. Port Scan+Flood: Reconnaissance then attack | End Week 2 | `dos_*.pcap` (10 files, labeled)             | A1, B2, C1, E1           |
| **2.4** | **Feature Extraction Pipeline**                       | 2-3  | • Parse each pcap (baseline + 10 DoS)<br>• Extract per 1-second window:<br> - src/dst IP entropy (A1 formula)<br> - pps, bps, SYN%/RST%/ACK%<br> - unique src/dst IPs, new flows/sec<br> - packet size std<br>• Output CSV with all metrics                                                                                                                                                                                                                                                                                                                                                                            | End Week 3 | `feature_extraction.py` (200 lines), 11 CSVs | B1: Feature engineering  |
| **2.5** | **Real-time Traffic Capture Setup**                   | 3    | • Script for live capture on s2<br>• Rolling pcap files (1 per minute)<br>• Ready for M4 real-time demo                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Week 3     | `capture_live.sh`, demo_setup.sh             | -                        |

---

### 👤 MEMBER 3: Bùi Lê Huy Phước (Detection Engine)

**Extends**: l3_router.py (add detection module)

| ID      | Task                             | Week | Details                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Deadline        | Deliverables                               | Theory Basis                      |
| ------- | -------------------------------- | ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- | ------------------------------------------ | --------------------------------- | ------------------------------------------------- | ---------- | -------------------------------- | ------------------------------- |
| **3.1** | **Entropy Detection Module**     | 2    | • Build on l3_router.py stats<br>• For each 1-sec window, compute:<br> - H_src = Shannon entropy of src IPs<br> - H_dst = Shannon entropy of dst ports<br> - H_ttl = TTL entropy<br> - H_pkt_size = packet size entropy<br>• Compare to baseline thresholds:<br> - SYN flood: H_src < 1 bit → alert<br> - IP spoof: H_src > 6 bits → alert<br>• Alert if abnormal for 2+ consecutive sec                                                                                                                                                                                                                                        | End Week 2      | `detection_entropy.py` (150 lines)         | A1: Kaur et al. entropy detection |
| **3.2** | **Statistical Detection Module** | 2    | • Compute per 1-sec window:<br> - rate_current, rate_baseline, rate_std<br> - z_score = (rate_current - baseline) / std<br>• Alert rules:<br> - Z > 3: High traffic anomaly<br> - Spike: rate > 5x baseline<br> - New flows spike: new_conns > 3x baseline<br> - Flag ratio abnormal:                                                                                                                                                                                                                                                                                                                                           | SYN% - baseline | > 20%<br> - RST% abnormal:                 | RST% - baseline                   | > 15%<br>• Alert if any rule triggers for 3+ secs | End Week 2 | `detection_stats.py` (150 lines) | B2: Flow-based, B3: Statistical |
| **3.3** | **Attack Signature Matching**    | 2-3  | • Implement decision rules from M1's ATTACK_SIGNATURES.md:<br><br>**SYN Flood:**<br> IF (entropy_src < 1.5 AND syn_pct > 50%) → SYN_FLOOD<br><br>**UDP Flood:**<br> IF (pps > 5x AND pkt_size_std < 10) → UDP_FLOOD<br><br>**HTTP Flood:**<br> IF (http_req_rate > 100/s AND entropy_src normal) → HTTP_FLOOD<br><br>**DNS Amplification:**<br> IF (dns_resp >> dns_req AND entropy_dst_port high) → DNS_AMPL<br><br>**IP Spoofing:**<br> IF (entropy_src > 6.5 AND pps high) → IP_SPOOF<br><br>**Low-rate DoS:**<br> IF (pps normal BUT entropy_src < 2 bits) → LOW_RATE<br><br>• Each with confidence score (HIGH/MEDIUM/LOW) | Week 3          | `attack_signature_matching.py` (200 lines) | All papers                        |
| **3.4** | **Real-time Alert System**       | 3    | • Listen to M2's live pcap/stats<br>• Generate alerts (JSON):<br> `<br>  {<br>    timestamp, attack_type, confidence,<br>    src_ip, dst_ip, dst_port,<br>    metrics: {entropy, syn_pct, pps},<br>    mitigation_action<br>  }<br>  `<br>• Log all alerts: alerts.json<br>• Send to M4 (mitigation)                                                                                                                                                                                                                                                                                                                            | Week 3          | `alert_system.py` (100 lines), alerts.json | -                                 |

---

### 👤 MEMBER 4: Phạm Ngọc Trúc Quỳnh (SDN Mitigation Layer)

**Extends**: l3_router.py (add mitigation app)

| ID      | Task                                            | Week | Details                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Deadline   | Deliverables                           | Theory Basis              |
| ------- | ----------------------------------------------- | ---- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | -------------------------------------- | ------------------------- |
| **4.1** | **Extend Ryu l3_router.py with Basic Blocking** | 1-2  | • Start from l3_router.py<br>• Add method: `block_source_ip(src_ip)`<br>• Install DROP rule on all switches:<br> - match: ipv4_src=src_ip<br> - action: DROP<br> - priority: 100<br>• Test: SYN flood detected → rule → traffic dropped<br>• Measure latency: alert to drop (target: <100ms)                                                                                                                                                                                       | End Week 2 | Extend l3_router.py with blocking      | C1: OpenFlow defense      |
| **4.2** | **Rate Limiting using Token Bucket**            | 2    | • Implement per-source-IP rate limiting<br>• Token bucket:<br> - Rate: R tokens/sec<br> - Bucket: B tokens<br> - If tokens >= pkt_size → forward; else DROP<br>• OpenFlow METER tables (v1.3):<br> - Create meter: max_rate=1000pps per src<br> - Install rule: match src_ip, meter<br>• Config per attack:<br> - SYN flood: 100 pps<br> - UDP flood: 200 pps<br> - HTTP flood: 50 req/sec                                                                                         | End Week 2 | `mitigation_rate_limit.py` (150 lines) | D1: Token bucket          |
| **4.3** | **DQoS + Traffic Shaping**                      | 2-3  | • Implement Quality of Service<br>• Classes:<br> - Priority 1 (high): DNS, Critical → no throttle<br> - Priority 2 (mid): Normal → light throttle<br> - Priority 3 (low): Attack → aggressive<br>• OpenFlow DSCP tagging:<br> - Priority 3 traffic: DSCP=8<br> - Queue rules: per DSCP value<br> - Bandwidth: P1=50%, P2=30%, P3=20%<br>• Multi-level filtering:<br> - L1: First pkt → Priority 3<br> - L2: If whitelisted → Priority 1<br> - L3: If legit protocol → Priority 1-2 | Week 3     | `mitigation_dqos.py` (200 lines)       | D2: DQoS, D3: Multi-level |
| **4.4** | **Blacklist/Whitelist Management**              | 3    | • Dynamic blacklist from M3's alerts<br>• Subscribe to alert system:<br> `python<br>  def receive_alert(alert_msg):<br>      if alert_msg.confidence == "HIGH":<br>          add_to_blacklist(alert_msg.src_ip)<br>          install_drop_rule(alert_msg.src_ip)<br>  `<br>• Whitelist: pre-defined trusted IPs<br>• Auto-recovery: remove after 5 min<br>• Log: mitigation_actions.json                                                                                           | Week 3     | `mitigation_blacklist.py` (100 lines)  | C1: Reactive defense      |
| **4.5** | **Performance Benchmarking**                    | 3    | • Measure Ryu latencies:<br> - Rule install: time(alert) → time(installed)<br> - Target: <100ms<br> - Throughput: >1Gbps with rules<br>• Load test: 1000 rules, measure CPU/mem<br>• Plot: rules vs latency, rules vs CPU                                                                                                                                                                                                                                                          | Week 3     | `benchmark_mitigation.py` (100 lines)  | C3: SDN scalability       |

---

### 👤 MEMBER 5: Phạm Nguyễn Tấn Sang (Testing + Integration + Demo)

| ID      | Task                                  | Week | Details                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Deadline   | Deliverables                                         | Theory Basis |
| ------- | ------------------------------------- | ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ---------------------------------------------------- | ------------ |
| **5.1** | **End-to-End Integration Testing**    | 3    | For each 10 DoS + baseline:<br>1. Start topology<br>2. Run Ryu + detection (M3) + mitigation (M4)<br>3. Generate attack (M2 replay/live)<br>4. Measure: detection latency, mitigation latency, effectiveness<br>5. Verify: metrics match paper baselines<br><br>**Test per attack:**<br>- Test_001: SYN flood latency ≤ 3s (E1)<br>- Test_002: UDP detection TPR ≥ 90% (B2)<br>- Test_003: HTTP FPR ≤ 5% (B3)<br>- Test_004-010: Other DoS types<br>- Test_011: Baseline FPR = 0<br><br>**Results JSON:** test_results.json with status/latency/metrics<br>**Failures:** Root cause analysis, bug reports                                                                                                                             | End Week 3 | `integration_test.py` (300 lines), test_results.json | All papers   |
| **5.2** | **Visualization & Analysis**          | 3    | **Plot 1: Detection Timeline per Attack**<br> - X: Time (sec), Y: Metrics<br> - Show: baseline (green), attack (red), alert (dot)<br><br>**Plot 2: Entropy Signature per Attack Type**<br> - 10 subplots showing entropy over time<br><br>**Plot 3: Detection Accuracy (Bar)**<br> - X: Attack types, Y: TPR/FPR<br><br>**Plot 4: Detection Latency (Box plot)**<br> - Distribution across attack types<br><br>**Plot 5: Mitigation Effectiveness**<br> - Before/after traffic volume<br><br>**Plot 6: Ryu Latency (Histogram)**<br> - Rule install latency distribution<br><br>**Plot 7: Traffic Patterns (Stacked Area)**<br> - Normal vs SYN vs HTTP<br><br>**Plot 8: FPR vs Threshold Trade-off**<br> - Find Youden optimal point | Week 3     | `visualization.py` (300 lines), 8 PNG plots          | E2: Analysis |
| **5.3** | **Live Demo (15-20 min)**             | 3-4  | **Flow:**<br>[0-1m] Lab topology diagram<br>[1-2m] Start Mininet + Ryu<br>[2-3m] Show baseline traffic<br>[3-7m] SYN flood attack demo<br> - Show: attacker sends packets<br> - Show: Ryu detects entropy anomaly<br> - Show: Mitigation rule installed<br> - Show: Attack dropped<br>[7-12m] HTTP flood attack demo<br> - Different detection (rate-based)<br> - Different mitigation (rate limit)<br>[12-15m] Show plots + metrics<br>[15-20m] Q&A<br><br>**Fallback:** Pre-recorded demo video                                                                                                                                                                                                                                     | Week 4     | `demo.sh`, live or demo.mp4                          | -            |
| **5.4** | **Final Presentation (12-15 slides)** | 4    | Slide 1: Title + Team<br>Slides 2-3: Problem + DDoS threat<br>Slides 4-5: Related work (5 key papers)<br>Slides 6-7: Architecture (Mininet + Ryu + layers)<br>Slides 8-9: Theory (entropy, statistics)<br>Slides 10-12: Results (3 attack examples)<br>Slide 13: Demo walkthrough<br>Slide 14: Conclusions & limitations<br>Slide 15: Future work<br><br>**Q&A Script:** 15+ questions + answers<br>- "How is entropy threshold chosen?" → from A1 + baseline<br>- "Why not ML?" → simpler, paper-proven, real-time<br>- "What's the FPR?" → <5% vs B3 benchmark                                                                                                                                                                      | Week 4     | `PRESENTATION.pptx` (15 slides), `QA_SCRIPT.md`      | -            |
| **5.5** | **Final Documentation & GitHub**      | 4    | • `README.md`: Quick start, structure<br>• `INSTALL.md`: Dependencies, setup<br>• `QUICKSTART.md`: Run in 5 minutes<br>• `RESULTS.md`: Summary vs papers<br>• `TROUBLESHOOTING.md`: Issues + fixes<br><br>**GitHub structure:**<br>`<br>docs/  → markdown files + papers<br>code/  → Python scripts<br>data/  → pcap, CSV, stats<br>results/ → plots, benchmarks<br>`<br><br>• Code: docstrings with citations, type hints, clean<br>• Tag: v1.0-final                                                                                                                                                                                                                                                                                | Week 4     | Clean GitHub, all docs organized                     | -            |

---

## 📊 PARALLELIZATION MATRIX

| Week  | M1 (Theory)             | M2 (Data)                               | M3 (Detection)                     | M4 (Mitigation)                      | M5 (Testing)                       |
| ----- | ----------------------- | --------------------------------------- | ---------------------------------- | ------------------------------------ | ---------------------------------- |
| **1** | Lit survey 20-25 papers | Lab setup                               | Study detection papers             | Study Ryu + OpenFlow                 | Setup test framework               |
| **2** | Theory + attack sigs    | Generate 10 DoS + features **PARALLEL** | Build entropy + stats **PARALLEL** | Build rate limit + DQoS **PARALLEL** | Ready to integrate                 |
| **3** | Code review             | Fine-tune + live capture                | Signatures + alerts                | Benchmarking + rules                 | Integration + visualization + demo |
| **4** | Final report            | Done                                    | Done                               | Done                                 | Live presentation + docs           |

**Key Parallel Opportunities:**

- **Week 2:** M2, M3, M4 work completely independently (only M1's theory as input)
- **Week 3:** Integration (M3→M4 via alerts, M2→M5 via features)
- **Week 4:** All converge for demo + docs

---

## ✅ SUCCESS CRITERIA

| Criteria               | Target                     | Owner          | Paper Ref |
| ---------------------- | -------------------------- | -------------- | --------- |
| **Detection Accuracy** | TPR ≥90%, FPR ≤5%          | M3, M5         | B2, B3    |
| **Detection Speed**    | Alert ≤3 sec               | M3, M5         | E1        |
| **Mitigation Speed**   | Rule install <100ms        | M4, M5         | C1        |
| **Attack Coverage**    | All 10 types detected      | M3, M5         | M1 sigs   |
| **Baseline Stability** | FPR=0 on normal            | M3, M5         | B1        |
| **Code Quality**       | 100+ lines/module, cited   | All            | -         |
| **Live Demo**          | 15-20 min working          | M5, M2, M3, M4 | -         |
| **Scientific Basis**   | All linked to 20-25 papers | M1, All        | -         |

---

## 📁 EXPECTED OUTPUT STRUCTURE

```
NT541.Q21-DDoS/
├── docs/
│   ├── LITERATURE_SURVEY.md
│   ├── THEORY_BACKGROUND.md
│   ├── ATTACK_SIGNATURES.md
│   ├── EVALUATION_PROTOCOL.md
│   ├── README.md
│   ├── INSTALL.md
│   ├── QUICKSTART.md
│   ├── RESULTS.md
│   └── TROUBLESHOOTING.md
├── code/
│   ├── topology_nhom4.py (existing)
│   ├── l3_router.py (existing)
│   ├── l3_router_extended.py (M4)
│   ├── detection_entropy.py (M3)
│   ├── detection_stats.py (M3)
│   ├── attack_signature_matching.py (M3)
│   ├── alert_system.py (M3)
│   ├── mitigation_rate_limit.py (M4)
│   ├── mitigation_dqos.py (M4)
│   ├── mitigation_blacklist.py (M4)
│   ├── benchmark_mitigation.py (M4)
│   ├── feature_extraction.py (M2)
│   ├── integration_test.py (M5)
│   ├── visualization.py (M5)
│   ├── demo.sh (M5)
│   └── capture_live.sh (M2)
├── data/
│   ├── flows_baseline.pcap (M2)
│   ├── baseline_stats.json (M2)
│   ├── dos_*.pcap (M2, 10 files)
│   ├── features_*.csv (M2, 11 files)
│   └── attacks_metadata.json
├── results/
│   ├── test_results.json
│   ├── alerts.json
│   ├── mitigation_actions.json
│   ├── benchmark_results.json
│   └── plots/ (8 PNG files)
├── PRESENTATION.pptx
├── QA_SCRIPT.md
├── .gitignore
└── requirements.txt
```

---

## 📝 WEEKLY CHECKPOINT MEETINGS

### Week 1 - Kickoff

- [ ] M1: Papers organized, theory documented
- [ ] M2: Lab running, baseline captured
- [ ] M3: Entropy formula coded, tested
- [ ] M4: Ryu basic blocking working
- [ ] M5: Test framework ready

### Week 2 - Implementation Sprint

- [ ] M2: All 10 DoS + features extracted
- [ ] M3: Detect all 10 types on M2 data
- [ ] M4: Rate limit + DQoS implemented
- [ ] M1: Attack signatures + paper linking
- [ ] M5: Ready for integration

### Week 3 - Integration & Demo Prep

- [ ] M5: End-to-end tests passing
- [ ] M5: Visualization complete, demo script working
- [ ] All: Code reviewed, citations added
- [ ] All: GitHub cleaned up

### Week 4 - Final Submission

- [ ] Live demo rehearsed
- [ ] Presentation ready
- [ ] All docs complete
- [ ] GitHub tagged v1.0-final

---

## 🎯 KEY DIFFERENCES FROM V2

| Aspect           | V2           | V3                                                         |
| ---------------- | ------------ | ---------------------------------------------------------- |
| Code foundation  | From scratch | **Inherits + extends** topology + l3_router                |
| Papers           | ~15 vague    | **20-25 specific IEEE/ACM**, cited per method              |
| Attack scenarios | 10 generic   | **10 unique**, well-differentiated                         |
| Detection        | Entropy only | **Entropy + Statistical** (literature-based)               |
| Mitigation       | Basic drop   | **DQoS + Shaping + Multi-level**                           |
| Theory           | Weak         | **THEORY_BACKGROUND.md** + **ATTACK_SIGNATURES.md** linked |
| Parallelization  | Loose        | **Tight matrix**: M2/M3/M4 fully parallel Week 2           |

---

## 📚 REFERENCE PAPERS BY GROUP

- **GROUP A (4)**: Entropy-based detection (A1-A4)
- **GROUP B (5)**: Flow-based + statistical (B1-B5)
- **GROUP C (5)**: SDN architecture + OpenFlow (C1-C5)
- **GROUP D (3)**: DDoS mitigation (D1-D3)
- **GROUP E (4)**: Real-time systems (E1-E4)

_Details in M1's LITERATURE_SURVEY.md_
