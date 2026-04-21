# PHÂN CÔNG V2 - ĐỀ TÀI DoS DETECTION USING SDN

**Thay đổi so với V1:**

- ❌ Bỏ ML/DL hoàn toàn → ✅ Entropy + Statistical methods
- 📊 50% SDN (Ryu mitigation) + 50% Detection
- 🎯 10+ loại DoS attack scenarios (không chỉ 5)
- 🔄 Song song hóa: 3 thành viên main (2,3,4) làm độc lập
- ⏱️ Timeline: 3-4 tuần (compact)

**Kế hoạch tuần:**

- **Tuần 1:** Lab setup + Paper survey + Planning
- **Tuần 2:** Data collection (10+ DoS) + Detection (entropy/stats) + Mitigation (SDN rules) [PARALLEL]
- **Tuần 3:** Integration testing + Visualization + Live demo
- **Tuần 4:** Final demo + Documentation (optional)

---

## 📋 PHÂN CÔNG TOÀN DỰ ÁN

### 👤 THÀNH VIÊN 1: Ngô Thị Mai Anh (Project Manager + Research)

| STT     | Task                           | Tuần | Chi tiết                                                                                                                                                                                                                                                                                                                                                                 | Deadline   | Sản phẩm                                                       |
| ------- | ------------------------------ | ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------- | -------------------------------------------------------------- |
| **1.1** | **Survey SDN + DoS Papers**    | 1    | • Tìm 10+ papers uy tín (IEEE, ACM):<br> - 3 papers: SDN security, DDoS mitigation, Ryu controller<br> - 5 papers: DoS detection (entropy-based, statistical methods)<br> - 2+ papers: Real-time detection case studies<br>• Tóm tắt: phương pháp detection, metrics, tools<br>• Note: Ưu/nhược điểm mỗi paper                                                           | Hết tuần 1 | `RESEARCH_PAPERS.md` (1500+ từ, 10+ papers cited, IEEE format) |
| **1.2** | **Define Metrics & Protocol**  | 1    | • Detection metrics: True Positive Rate (TPR), False Positive Rate (FPR), Detection Time (ms)<br>• Attack metrics: Attack volume (Mbps), packet rate (pps), duration<br>• System metrics: CPU (%), Memory (MB), Latency (ms)<br>• Dataset format: timestamp, src, dst, sport, dport, proto, bytes, flags, etc.<br>• Acceptance: TPR ≥90%, FPR ≤5%, Detection time ≤500ms | Hết tuần 1 | `EVALUATION_PROTOCOL.md` (800+ từ, công thức)                  |
| **1.3** | **Weekly Reviews & Oversight** | 2-4  | • **Tuần 2:** Review data collection (10+ DoS scenarios), detection code, mitigation rules<br>• **Tuần 3:** Integration & test results<br>• **Tuần 4:** Final demo & documentation                                                                                                                                                                                       | Tuần 4     | Checklist approval per week                                    |
| **1.4** | **Viết báo cáo cuối**          | 3-4  | • Executive summary (1 trang)<br>• Related work (2 trang)<br>• Methodology (3 trang): kiến trúc, 10 DoS types, detection methods, SDN mitigation<br>• Results (2 trang): metrics table, detection performance per attack type<br>• Demo analysis (1 trang)<br>• Conclusion (0.5 trang)                                                                                   | Tuần 4     | `FINAL_REPORT.md` (12-15 trang PDF)                            |

---

### 👤 THÀNH VIÊN 2: Đỗ Hoàng Phúc (Lab Engineer + Data Collection)

**Focus:** Cài lab, generate 10+ DoS attack scenarios (thực hành nhiều!)

| STT     | Task                                | Tuần | Chi tiết                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Deadline   | Sản phẩm                                                       |
| ------- | ----------------------------------- | ---- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | -------------------------------------------------------------- |
| **2.1** | **Lab Setup (Mininet + Ryu)**       | 1    | • Mininet topology: 1 switch, 3-5 hosts (server, client, 2-3 attackers)<br>• Ryu SDN controller (port 6653)<br>• Network config: 10.0.0.0/24 subnet, static IPs<br>• Test: connectivity ping, Ryu logs, OpenFlow protocol<br>• Create scripts: startup, cleanup, monitoring                                                                                                                                                                                                                                                                                                                                                                                                                           | Hết tuần 1 | `setup_lab.py`, `LAB_GUIDE.md`, topology ready                 |
| **2.2** | **Baseline Traffic Collection**     | 1-2  | • Normal traffic: iperf (TCP), curl (HTTP), DNS queries<br>• Duration: 10 mins, ~50MB pcap<br>• Logs: timestamp, pps, packet size distribution                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Hết tuần 2 | `data/normal.pcap`, `logs/normal.log`                          |
| **2.3** | **DoS Attack Scenarios (10+)**      | 2    | Generate 10+ attack types (each 2 mins, ~50MB pcap):<br><br>**Layer 4 Floods (5):**<br>1. SYN Flood: hping3 -S --flood<br>2. UDP Flood: coap-client or custom script<br>3. ACK Flood: hping3 -A --flood<br>4. FIN Flood: hping3 -F --flood<br>5. RST Flood: hping3 -R --flood<br><br>**Layer 7 Floods (3):**<br>6. HTTP GET Flood: Apache Bench (ab) or custom<br>7. HTTP POST Flood: curl loop<br>8. DNS Amplification: simulated via DNS queries<br><br>**Spoofed/Distributed (2+):**<br>9. IP Spoofing: random src IP flood<br>10. Low-rate DoS: 1 req/sec for 5 mins (hard to detect)<br>11. Mix (optional): SYN + UDP combined<br><br>Each: labeled pcap, attack metadata (start/end, pps, type) | Hết tuần 2 | `data/dos_*.pcap` (10+ files), `logs/dos_*.log`                |
| **2.4** | **Feature Extraction**              | 2-3  | • Parse pcap → flows (5-tuple: src, dst, sport, dport, proto)<br>• Extract per flow: byte count, packet count, flow duration, flags (SYN, ACK, FIN, RST)<br>• Aggregate per second: total packets/bytes, flow count, entropy<br>• Output: flows.csv (1 row per flow), timeseries.csv (1 row per second)<br>• Format: timestamp, attack_type, feature1, feature2, ...                                                                                                                                                                                                                                                                                                                                  | Hết tuần 3 | `feature_extraction.py` (150 lines), flows.csv, timeseries.csv |
| **2.5** | **Live Traffic Capture (for demo)** | 3    | • Real-time tcpdump on switch interface<br>• Capture live attacks, save to rolling pcap files<br>• Script for demo: run attack → capture → analyze                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Tuần 3     | `capture_live.sh`, sample live pcaps                           |

---

### 👤 THÀNH VIÊN 3: Bùi Lê Huy Phước (SDN Mitigation Engineer)

**Focus:** Ryu controller, flow rules, rate limiting, traffic engineering

| STT     | Task                           | Tuần | Chi tiết                                                                                                                                                                                                                                                                                                                                                                                                                                     | Deadline   | Sản phẩm                                                 |
| ------- | ------------------------------ | ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | -------------------------------------------------------- |
| **3.1** | **Ryu Controller Setup**       | 1    | • Deploy Ryu on controller host (port 6633 for Mininet switch)<br>• Test: verify switch connects, receive packet_in messages<br>• Logs: show OFP handshake, feature_request/reply                                                                                                                                                                                                                                                            | Hết tuần 1 | Ryu running, controller logs                             |
| **3.2** | **Base Flow Rules**            | 1-2  | • Add default drop rules (OFPT_FLOW_MOD)<br>• Allow normal traffic: server↔client flows<br>• Install rules for DNS, HTTP, ICMP<br>• Test: normal traffic still works via Ryu                                                                                                                                                                                                                                                                 | Hết tuần 2 | `base_flows.py` (Ryu app)                                |
| **3.3** | **Detection-based Mitigation** | 2    | • Integration with detection (from Thành viên 4):<br> - Receive detection alerts (attack detected)<br> - Install rate-limiting rules: max 1000 pps per src IP<br> - Blacklist source IP (drop rule)<br> - Whitelist legitimate IPs (priority=higher)<br>• Methods:<br> - Token bucket: limit pps per flow<br> - Traffic policing: DSCP tagging<br> - Path rerouting: redirect attack traffic<br>• Test with live attacks (from Thành viên 2) | Hết tuần 3 | `mitigation_app.py` (Ryu app, 200+ lines), rules scripts |
| **3.4** | **Performance Benchmark**      | 3    | • Test Ryu rule installation latency: < 100ms<br>• Measure switch throughput with rules: >1 Gbps<br>• CPU/Memory usage of controller<br>• Create latency vs rule complexity plot                                                                                                                                                                                                                                                             | Tuần 3     | `benchmark_results.json`, performance.png                |

**Implementation note:** Ryu app structure:

```python
class DOSMitigationApp(app_manager.RyuApp):
    def __init__(self):
        # Handle packet_in → detect attack → install rule

    def receive_detection_alert(self, src_ip, attack_type):
        # Call this from detection module to install rules
        self.install_rate_limit_rule(src_ip, max_pps=1000)
```

---

### 👤 THÀNH VIÊN 4: Phạm Ngọc Trúc Quỳnh (Detection Engineer)

**Focus:** Entropy-based + statistical detection (NO ML, keep it simple!)

| STT     | Task                           | Tuần | Chi tiết                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Deadline   | Sản phẩm                                                 |
| ------- | ------------------------------ | ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | -------------------------------------------------------- |
| **4.1** | **Entropy-based Detection**    | 2    | • Per-second statistics:<br> - Src IP entropy (measure diversity of sources)<br> - Dst port entropy (diversity of target ports)<br> - TTL entropy (unusual values = spoofed?)<br> - Packet size entropy (unusual distribution)<br>• Thresholds (learned from baseline):<br> - Normal Src entropy: 3-5 bits<br> - Attack Src entropy: >6 bits (many sources) or <1 bit (single source)<br> - Normal packet size std: 50-100 bytes<br> - Attack packet size std: <10 bytes (all same size = flood)<br>• Alert if entropy > threshold for 3+ consecutive seconds | Hết tuần 2 | `entropy_detection.py` (150+ lines), thresholds.json     |
| **4.2** | **Statistical Methods**        | 2    | • Simple stats (no ML!):<br> - Packet/byte rate anomaly: deviation from baseline<br> - Baseline = mean rate over last 5 mins<br> - Alert if: current rate > baseline \* 5 (5x spike)<br> - Flag ratio: % of packets with SYN/RST flags<br> - Normal HTTP: SYN ~5%, RST <1%<br> - SYN flood: SYN >50%<br> - RST flood: RST >30%<br> - Connection rate: new flows per second<br> - Normal: <100 new flows/sec<br> - Attack: >500 new flows/sec<br>• Alert if any metric anomalous                                                                               | Hết tuần 2 | `stats_detection.py` (150+ lines)                        |
| **4.3** | **Per-Attack Detection Rules** | 2    | Create specific rules for each DoS type:<br><br>1. **SYN Flood:** SYN% >50% + high entropy on ports → ALERT<br>2. **UDP Flood:** UDP packets > baseline\*10 → ALERT<br>3. **HTTP Flood:** HTTP requests >100/sec → ALERT<br>4. **DNS Amplification:** DNS responses >> requests → ALERT<br>5. **IP Spoof:** Src entropy > threshold → ALERT<br>6. **Low-rate DoS:** subtle (1 req/sec) → use entropy drop or flag patterns<br>7-11. Others... <br><br>Test each rule against corresponding attack scenario                                                    | Hết tuần 3 | `attack_signatures.py` (200+ lines), detection_rules.csv |
| **4.4** | **Alert System**               | 2-3  | • Real-time monitoring: process pcap or live traffic<br>• Alert format: {timestamp, attack_type, confidence, src_ip, dst_ip}<br>• Send alert to Thành viên 3 (mitigation) for rule installation<br>• Log all alerts: alerts.json                                                                                                                                                                                                                                                                                                                              | Tuần 3     | `alert_system.py` (100+ lines), alerts.json              |

---

### 👤 THÀNH VIÊN 5: Phạm Nguyễn Tấn Sang (Testing + Visualization + Presentation)

**Focus:** Integrate everything, test end-to-end, create visualizations & demo

| STT     | Task                    | Tuần | Chi tiết                                                                                                                                                                                                                                                                                                                                                                                                                                     | Deadline | Sản phẩm                                              |
| ------- | ----------------------- | ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | ----------------------------------------------------- |
| **5.1** | **Integration Testing** | 3    | • Test detection + mitigation end-to-end:<br> - Start lab (Mininet + Ryu)<br> - Run normal traffic → should NOT alert<br> - Trigger SYN flood → detect within 3 secs → Ryu installs rule<br> - Verify attack traffic gets rate-limited<br> - Check detection accuracy for each 10 attack types<br>• Calculate per-attack metrics: detection time, TPR, FPR<br>• Document failures & issues                                                   | Tuần 3   | `test_integration.py` (200+ lines), test_results.json |
| **5.2** | **Visualization**       | 3    | • **Plot 1:** Detection timeline (traffic volume vs time, alert markers)<br>• **Plot 2:** Entropy over time (baseline + alert threshold + actual)<br>• **Plot 3:** Detection accuracy per attack type (bar chart: TPR/FPR)<br>• **Plot 4:** Detection latency per attack type (box plot)<br>• **Plot 5:** Ryu rule installation latency (histogram)<br>• **Plot 6:** Network traffic before/after mitigation (line chart)                    | Tuần 3   | `visualization.py` (200+ lines), 6 plots PNG          |
| **5.3** | **Live Demo Script**    | 3    | • Automated demo:<br> 1. Show lab topology (diagram)<br> 2. Start normal traffic (show traffic flow)<br> 3. Trigger DoS attack (live pcap display)<br> 4. Show detection alert (terminal output)<br> 5. Show Ryu rule installation (OpenFlow logs)<br> 6. Show traffic rate-limiting effect<br>• Timing: 10-15 minutes total<br>• Fallback: recorded demo (if live fails)                                                                    | Tuần 3   | `demo.sh` (automation script), demo.mp4 (backup)      |
| **5.4** | **Presentation**        | 3-4  | • **12-15 slides:**<br> 1. Title + Team<br> 2. Problem: DDoS threats, why SDN helps<br> 3. Related work: 3-4 papers summary<br> 4. Architecture: Mininet topology + Ryu + detection<br> 5-7. Detection methods: entropy, stats, rules (3 slides)<br> 8-10. Results: accuracy, latency, mitigation effectiveness (3 slides)<br> 11. Live demo walkthrough<br> 12. Conclusions & future work<br>• Q&A script: 10-15 common questions + answers | Tuần 4   | `PRESENTATION.pptx` (12-15 slides), `QA_SCRIPT.md`    |
| **5.5** | **Final Documentation** | 4    | • `README.md`: Quick start guide, folder structure<br>• `INSTALL.md`: Step-by-step setup<br>• `USAGE.md`: How to run labs, reproduce results<br>• `RESULTS.md`: Summary of findings<br>• GitHub: Clean repo structure, requirements.txt, scripts                                                                                                                                                                                             | Tuần 4   | All docs ready for submission                         |

---

## 📊 PARALLELIZATION PLAN

**Tuần 1 (Setup & Planning):** Sequential

- Thành viên 1: Survey papers + metrics (parallel start)
- Thành viên 2: Lab setup (wait for 1 to finish metrics)
- Thành viên 3: Ryu setup (parallel with 2, independent)
- Thành viên 4: Literature on detection methods (parallel start)
- Thành viên 5: Prepare test framework (parallel)

**Tuần 2 (Implementation):** PARALLEL!

- **Thành viên 2:** Generate 10+ DoS attacks (independent) ✅
- **Thành viên 3:** Build Ryu mitigation rules (independent of 2,4 until integration) ✅
- **Thành viên 4:** Build detection system (independent, consumes 2's data) ✅
- **Thành viên 1:** Review & coordinate ✅
- **Thành viên 5:** Prepare test suite (ready for integration) ✅

**Tuần 3 (Integration & Testing):** Sequential convergence

- All outputs come together
- Thành viên 5: Test end-to-end, visualize
- Thành viên 3: Fine-tune mitigation rules based on 4's alerts
- Thành viên 2: Generate live demo traffic
- Thành viên 1: Prepare final report

**Tuần 4 (Demo & Documentation):**

- Thành viên 5: Live demo + presentation
- All: Documentation + final touches

---

## ✅ SUCCESS CRITERIA (Mục tiêu đạt được)

| Tiêu chí               | Yêu cầu                                  | Owner      |
| ---------------------- | ---------------------------------------- | ---------- |
| **Detection Accuracy** | TPR ≥90%, FPR ≤5% per attack type        | T4, T5     |
| **Detection Speed**    | Alert within 3-5 seconds of attack start | T4, T5     |
| **Mitigation Latency** | Ryu rule install <100ms                  | T3, T5     |
| **Attack Coverage**    | All 10+ DoS types detected               | T2, T4, T5 |
| **Live Demo**          | 15-min end-to-end demo working           | T5, T2     |
| **Documentation**      | 10+ paper citations, clear methodology   | T1, T5     |
| **Code Quality**       | Clean, commented, reproducible           | All        |

---

## 📁 FOLDER STRUCTURE (Expected Output)

```
NT541.Q21-DDoS/
├── docs/
│   ├── RESEARCH_PAPERS.md          (T1)
│   ├── EVALUATION_PROTOCOL.md      (T1)
│   ├── LAB_GUIDE.md                (T2)
│   ├── FINAL_REPORT.md             (T1)
│   ├── PRESENTATION.pptx           (T5)
│   ├── README.md                   (T5)
│   ├── INSTALL.md                  (T5)
│   └── USAGE.md                    (T5)
├── data/
│   ├── normal.pcap                 (T2)
│   ├── dos_*.pcap                  (T2 - 10+ files)
│   ├── flows.csv                   (T2)
│   └── timeseries.csv              (T2)
├── detection/
│   ├── entropy_detection.py        (T4)
│   ├── stats_detection.py          (T4)
│   ├── attack_signatures.py        (T4)
│   ├── alert_system.py             (T4)
│   ├── thresholds.json             (T4)
│   └── alerts.json                 (T4 - runtime)
├── mitigation/
│   ├── base_flows.py               (T3)
│   ├── mitigation_app.py           (T3)
│   └── benchmark_results.json      (T3)
├── lab/
│   ├── setup_lab.py                (T2)
│   ├── capture_live.sh             (T2)
│   └── cleanup.sh                  (T2)
├── testing/
│   ├── test_integration.py         (T5)
│   ├── test_results.json           (T5)
│   └── test_*.py                   (T5 - unit tests)
├── visualization/
│   ├── visualization.py            (T5)
│   └── plots/                      (T5 - 6 PNG files)
└── demo/
    ├── demo.sh                     (T5)
    └── demo.mp4                    (T5 - optional)
```

---

## 📝 WEEKLY CHECKLIST

### Tuần 1 - Setup & Planning

- [ ] Thành viên 1: Survey 10+ papers, metrics defined
- [ ] Thành viên 2: Lab running, baseline traffic captured
- [ ] Thành viên 3: Ryu controller online
- [ ] Thành viên 4: Detection methods designed
- [ ] Thành viên 5: Test suite skeleton ready

**Checkpoint meeting:** All systems go? Data formats aligned? Dependencies clear?

### Tuần 2 - Implementation (Parallel)

- [ ] Thành viên 2: All 10+ DoS attacks generated & labeled
- [ ] Thành viên 3: Mitigation rules coded & tested on normal traffic
- [ ] Thành viên 4: Detection working on replay attacks (from 2's data)
- [ ] Thành viên 1: Code review, paper tracing
- [ ] Thành viên 5: Test framework ready for integration

**Checkpoint meeting:** Each component works independently? Ready for integration?

### Tuần 3 - Integration & Testing

- [ ] Thành viên 5: End-to-end test: detection → mitigation → effectiveness
- [ ] All: Metrics collected per attack type
- [ ] Thành viên 5: Visualizations created
- [ ] Thành viên 5: Live demo working
- [ ] Thành viên 1: Draft final report

**Checkpoint meeting:** Demo works? All metrics acceptable? What's broken?

### Tuần 4 - Final Demo & Documentation

- [ ] Live presentation demo
- [ ] Final report finished
- [ ] All docs complete
- [ ] GitHub clean & tagged

---

**Notes:**

- Entropy/stats detection = simple, no ML required ✅
- 10+ DoS types = lots of hands-on practice ✅
- 3 tuần = aggressive but doable with parallel work ✅
- SDN = 50% focus (mitigation + performance analysis) ✅
