# 📘 KẾ HOẠCH PHÂN CÔNG V4 — DoS Detection on SDN

**Đề tài:** Phát hiện & giảm thiểu tấn công DoS/DDoS trên nền tảng SDN (Ryu + Mininet)
**Nhóm:** 5 thành viên — **Thời lượng:** 6 tuần (42 ngày)
**Phương pháp:** Entropy (Shannon + Renyi) + Thống kê (Z-score, EWMA, CUSUM) + Signature matching
**Không sử dụng Machine Learning** — tập trung vào phương pháp thống kê có cơ sở toán học rõ ràng, dễ triển khai và giải thích.

---

## 0. Thông tin chung

| Mục | Nội dung |
|---|---|
| Công cụ | Mininet 2.3+, Ryu 4.34, hping3, Scapy, slowhttptest, tcpreplay, Wireshark, matplotlib |
| Dataset | Tự tạo bằng Mininet + đối chứng **CICDDoS2019** subset (công khai, Univ. of New Brunswick) |
| Tiêu chí nghiệm thu | **TPR ≥ 92%**, **FPR ≤ 5%**, **Detection latency ≤ 3s**, **Mitigation latency ≤ 5s** |
| Repo | GitHub: cấu trúc `docs/`, `code/`, `datasets/`, `results/`, `figs/`, `tests/` |

---

## 1. 📚 Danh mục tài liệu tham khảo (22 bài báo uy tín)

### Nhóm A — Entropy-based Detection (4 papers)
- **A1.** Kumar, P., et al. (2018). *"SAFETY: Early Detection and Mitigation of TCP SYN Flood Utilizing Entropy in SDN"*, **IEEE Transactions on Network and Service Management**, 15(4).
- **A2.** Mousavi, S.M., St-Hilaire, M. (2015). *"Early Detection of DDoS Attacks against SDN Controllers"*, **IEEE ICNC 2015**.
- **A3.** Kalkan, K., Gür, G., Alagöz, F. (2017). *"Defense Mechanisms against DDoS Attacks in SDN Environment"*, **IEEE Communications Magazine**, 55(9).
- **A4.** Özçelik, İ., Brooks, R.R. (2015). *"Deceiving entropy based DoS detection"*, **Computers & Security**, Vol. 48.

### Nhóm B — Flow & Statistical Methods (5 papers)
- **B1.** Braga, R., Mota, E., Passito, A. (2010). *"Lightweight DDoS Flooding Attack Detection Using NOX/OpenFlow"*, **IEEE LCN 2010**.
- **B2.** Giotis, K., et al. (2014). *"Combining OpenFlow and sFlow for an effective and scalable anomaly detection and mitigation mechanism on SDN environments"*, **Computer Networks**, 62.
- **B3.** Wang, R., Jia, Z., Ju, L. (2015). *"An Entropy-Based Distributed DDoS Detection Mechanism in SDN"*, **IEEE TrustCom 2015**.
- **B4.** Bhuyan, M.H., Bhattacharyya, D.K., Kalita, J.K. (2015). *"An empirical evaluation of information metrics for low-rate and high-rate DDoS attack detection"*, **Pattern Recognition Letters**, 51.
- **B5.** Sharafaldin, I., et al. (2019). *"Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy"*, **IEEE ICCST 2019** — (dataset **CICDDoS2019**).

### Nhóm C — SDN Architecture & OpenFlow (5 papers)
- **C1.** McKeown, N., et al. (2008). *"OpenFlow: Enabling Innovation in Campus Networks"*, **ACM SIGCOMM CCR**, 38(2).
- **C2.** Kreutz, D., et al. (2015). *"Software-Defined Networking: A Comprehensive Survey"*, **Proceedings of the IEEE**, 103(1).
- **C3.** Shin, S., Gu, G. (2013). *"Attacking Software-Defined Networks: A First Feasibility Study"*, **ACM HotSDN**.
- **C4.** Yan, Q., et al. (2016). *"Software-Defined Networking (SDN) and Distributed Denial of Service (DDoS) Attacks in Cloud Computing Environments: A Survey"*, **IEEE Communications Surveys & Tutorials**, 18(1).
- **C5.** Scott-Hayward, S., Natarajan, S., Sezer, S. (2016). *"A Survey of Security in Software Defined Networks"*, **IEEE Communications Surveys & Tutorials**, 18(1).

### Nhóm D — DoS Mitigation Strategies (4 papers)
- **D1.** Dhawan, M., et al. (2015). *"SPHINX: Detecting Security Attacks in Software-Defined Networks"*, **NDSS 2015**.
- **D2.** Wang, H., Xu, L., Gu, G. (2015). *"FloodGuard: A DoS Attack Prevention Extension in Software-Defined Networks"*, **IEEE/IFIP DSN 2015**.
- **D3.** Ambrosin, M., et al. (2017). *"LineSwitch: Tackling Control Plane Saturation Attacks in SDN"*, **IEEE/ACM Transactions on Networking**, 25(2).
- **D4.** Shin, S., et al. (2013). *"AVANT-GUARD: Scalable and Vigilant Switch Flow Management in SDN"*, **ACM CCS 2013**.

### Nhóm E — Real-time & Evaluation (4 papers)
- **E1.** Mirkovic, J., Reiher, P. (2004). *"A Taxonomy of DDoS Attack and DDoS Defense Mechanisms"*, **ACM SIGCOMM CCR**, 34(2).
- **E2.** Lakhina, A., Crovella, M., Diot, C. (2005). *"Mining Anomalies Using Traffic Feature Distributions"*, **ACM SIGCOMM 2005**.
- **E3.** Nychis, G., et al. (2008). *"An empirical evaluation of entropy-based traffic anomaly detection"*, **ACM IMC 2008**.
- **E4.** Page, E.S. (1954). *"Continuous Inspection Schemes"* — **CUSUM kinh điển**, Biometrika, 41.

---

## 2. Vai trò thành viên

| TV | Họ tên | Vai trò |
|---|---|---|
| TV1 | Ngô Thị Mai Anh | **Trưởng nhóm — Nghiên cứu, Tài liệu, Dashboard & Metrics** |
| TV2 | Đỗ Hoàng Phúc | **Lab & Topology** (topology + Ryu base + 5 attack scripts s01–s05) |
| TV3 | Bùi Lê Huy Phước | **Detection Engineer** (entropy + stats + signature) |
| TV4 | Phạm Ngọc Trúc Quỳnh | **SDN Mitigation Engineer** (Block + Rate-limit) |
| TV5 | Phạm Nguyễn Tấn Sang | **Integration & Demo Lead** (run_scenario + 5 attack scripts s06–s10 + stress + demo) |

> **Nguyên tắc phân công V4.1:**
> 1. **Không có TV "tester thuần"** — mỗi chủ module tự viết unit test cho code của mình (xem bảng dưới). Đỡ lệch tải, người viết module hiểu edge case nhất.
> 2. **Mọi TV đều chạm SDN** — TV1 qua dashboard (Ryu REST + InfluxDB), TV2/4 qua OpenFlow thật, TV3 qua xử lý features từ flow stats, TV5 qua integration E2E.
> 3. **Attack scripts chia đôi TV2 ↔ TV5** — TV2 làm 5 kịch bản cơ bản (L4 flood + HTTP + DNS), TV5 làm 5 kịch bản nâng cao (spoof, slowloris, multi-source, flash crowd, backup).
> 4. **TV4 bỏ DQoS queue** — chỉ giữ Block + Rate-limit (Meter) để demo ổn định.
> 5. **Cắt còn 10 kịch bản** thay vì 14 (xem §4).

### 2.1 Phân công unit test (thay cho vai trò tester tập trung)

| Module | Chủ module | File test | Ai viết test |
|---|---|---|---|
| `topology_v4.py` | TV2 | `test_topology.py` (ping, bw) | TV2 |
| `entropy.py`, `stats.py`, `signature_matcher.py` | TV3 | `test_entropy.py`, `test_stats.py`, `test_signature.py` | TV3 |
| `mitigation.py` | TV4 | `test_mitigation.py` | TV4 |
| `run_scenario.py` (E2E) | TV5 | `test_integration.py` | TV5 |
| `dashboard.py`, `metrics.py` | TV1 | (smoke test tay, không bắt buộc pytest) | TV1 |

---

## 3. Timeline tổng thể

```
Tuần 1 │ Khởi động + Khảo sát + Dựng lab
Tuần 2 │ Sinh dữ liệu (baseline + 8 kịch bản cơ bản) + skeleton detection/mitigation
Tuần 3 │ Hoàn thiện detection + Thêm 6 kịch bản nâng cao (tổng 14)
Tuần 4 │ Mitigation nâng cao + Integration v1
Tuần 5 │ Đánh giá (TPR/FPR/latency) + tối ưu ngưỡng + stress test
Tuần 6 │ Viết báo cáo + slide + dry-run + bảo vệ
```

### Milestones
| Mốc | Hạn | Sản phẩm |
|---|---|---|
| M1 — Lab + Survey | Hết T1 | `LITERATURE_SURVEY.md`, topology OK, `baseline.pcap` |
| M2 — Dataset v1 | Hết T2 | 9 pcap + 9 CSV features |
| M3 — Detection v1 | Hết T3 | Phát hiện đúng 8/8 kịch bản cơ bản |
| M4 — Integration E2E | Hết T4 | Attack → Detect → Mitigate liền mạch |
| M5 — Kết quả đánh giá | Hết T5 | Bảng metrics + 10 biểu đồ |
| M6 — Bảo vệ | Hết T6 | Báo cáo + slide + video demo |

---

## 4. 🎯 10 kịch bản tấn công (đã rút từ 14 cho phù hợp phạm vi đồ án)

| # | Nhóm | Kịch bản | Công cụ | Chữ ký kỳ vọng | Paper |
|---|---|---|---|---|---|
| 1 | A-L4 | SYN Flood | `hping3 -S --flood -p 80` | entropy_src<1.5, SYN%>60% | A1, B1 |
| 2 | A-L4 | UDP Flood | `hping3 --udp --flood` | pps>5×, entropy_dport thấp | B4 |
| 3 | A-L4 | ICMP Flood | `hping3 -1 --flood` | ICMP%>40% | E1 |
| 4 | B-L7 | HTTP GET Flood | `slowhttptest -H` / `wrk` | req/s>500, kết nối hợp lệ | C4 |
| 5 | B-L7 | DNS Amplification | Scapy custom | resp/req>10× | A3, E1 |
| 6 | C | IP Spoof Flood | Scapy random src | entropy_src>6 | A4, E2 |
| 7 | C | Slowloris | `slowhttptest -c 1000 -H` | kết nối mở lâu, bps thấp | C4 |
| 8 | D | DDoS đa nguồn | hping3 trên 3 host | flows mới tăng vọt | A2, C4 |
| 9 | **E** | **Flash crowd** (hợp pháp) | `ab -c 200 -n 10000` | **KHÔNG cảnh báo** | E2 |
| 10 | **E** | **Backup burst** (rsync) | rsync 1GB | **KHÔNG cảnh báo** | E2 |

> **Đã bỏ so với V4 cũ:** ACK/RST Flood (trùng chữ ký SYN), HTTP POST Flood (trùng GET Flood), Low-rate Pulsing/Shrew (khó tái hiện ổn định trong Mininet), Multi-vector (để dành mở rộng nếu dư thời gian).

---

## 5. 👤 TV1 — Mai Anh: Nghiên cứu & Điều phối

### 5.1 Công việc chi tiết

#### Task 1.1 — Tổ chức khởi động (T1 D1–D2)
**Cách làm:**
1. Tạo repo GitHub `sdn-dos-detection`, cấu trúc thư mục:
   ```
   docs/ code/ datasets/ results/ figs/ tests/ slides/
   ```
2. Tạo `README.md` mô tả đề tài, cách chạy, thành viên.
3. Thiết lập **branch protection** (main, develop) + template commit `[TVx] <module>: <mô tả>`.
4. Tạo Trello/Jira với 6 cột: Backlog, Tuần 1–6, Done.
5. Tổ chức họp kick-off 60' — chốt scope, mỗi TV ký cam kết phần việc.

**Kết quả:** Repo sạch, template báo cáo LaTeX (Overleaf — IEEE format).

#### Task 1.2 — Khảo sát 22 papers (T1 D3–D7)
**Cách làm:**
1. Tải từng paper từ IEEE Xplore / ACM DL / Google Scholar (dùng tài khoản trường).
2. Với mỗi paper, viết **1 trang tóm tắt** gồm: Vấn đề → Phương pháp → Kết quả → Điểm mạnh/yếu → Liên hệ đề tài.
3. Dùng Zotero hoặc Mendeley để quản lý BibTeX.
4. Tổng hợp thành `docs/LITERATURE_SURVEY.md` theo 5 nhóm A–E (≥5000 từ).
5. Bảng so sánh: |Paper|Phương pháp|Feature|TPR|FPR|Hạn chế|

**Mẹo:** Bắt đầu từ paper survey (C2, C4, E1) để lấy "bản đồ" trước, rồi đào sâu từng paper cụ thể.

#### Task 1.3 — Viết THEORY_BACKGROUND.md (T2 D1–D3)
**Cách làm:**
Viết ≥3000 từ gồm các mục:
1. **Phân loại DoS/DDoS** (theo E1): Volumetric, Protocol, Application.
2. **Shannon Entropy:** `H(X) = -Σ p(x) log₂ p(x)`. Giải thích:
   - Lưu lượng bình thường: src IP đa dạng → H ≈ 4–6 bits
   - Flood từ 1 nguồn: H → 0
   - IP spoofing: H → max (≈ log₂ N)
3. **Renyi Entropy** (q=2): nhạy hơn với phân bố đuôi dài — công thức `H_q = 1/(1-q) log Σ p^q`.
4. **Z-score:** `z = (x - μ) / σ`, ngưỡng ±3σ.
5. **EWMA:** `S_t = α·x_t + (1-α)·S_{t-1}`, α=0.3, phát hiện thay đổi dần.
6. **CUSUM** (E4): tổng tích lũy độ lệch — phát hiện thay đổi mean nhanh.
7. **SDN/OpenFlow:** dẫn C1, C2 — controller, flow table, match-action.
8. Vẽ sơ đồ bằng draw.io, lưu PNG vào `figs/theory/`.

#### Task 1.4 — ATTACK_SIGNATURES.md (T2 D4–D7)
**Cách làm:**
Với mỗi trong 14 kịch bản, điền bảng:
```
| Attack | Rule (logic) | Ngưỡng | Feature | Paper tham khảo |
```
Ví dụ SYN flood: `entropy_src < 1.5 AND syn_pct > 0.6 AND new_flows/s > 3σ` → cite A1, B1.

Lưu `docs/ATTACK_SIGNATURES.md` + `docs/attack_signatures.csv` (cho TV3 đọc).

#### Task 1.5 — EVALUATION_PROTOCOL.md (T3)
**Cách làm:**
1. Định nghĩa **TP/FP/TN/FN** cụ thể cho bài toán (window 1s).
2. Công thức: `TPR = TP/(TP+FN)`, `FPR = FP/(FP+TN)`, `F1`, `Precision`.
3. Quy trình: chạy mỗi kịch bản 3 lần, mỗi lần 5 phút, lấy trung bình.
4. Dataset: 70% tune ngưỡng, 30% test (tách theo thời gian, không shuffle).
5. Ngưỡng chấp nhận: TPR≥92%, FPR≤5%, latency≤3s.

#### Task 1.6 — Code review hàng tuần (T2–T5, mỗi thứ 6)
**Cách làm:**
- Pull code, đọc từng module, kiểm 3 điểm: (1) có cite paper trong docstring? (2) ngưỡng trùng với `ATTACK_SIGNATURES.md`? (3) có unit test?
- Ghi `docs/review/weekX.md`: OK / Cần sửa / Câu hỏi.

#### Task 1.7 & 1.8 — Viết báo cáo (T5 cuối → T6)
Cấu trúc báo cáo IEEE 8 chương:
1. Giới thiệu → 2. Công trình liên quan (dựa Task 1.2) → 3. Cơ sở lý thuyết (1.3) → 4. Thiết kế hệ thống → 5. Triển khai → 6. Đánh giá (1.5 + kết quả TV5) → 7. Bàn luận → 8. Kết luận.

#### 🆕 Task 1.9 — REST Dashboard `dashboard.py` (T3 D1 → T4 D5)
**Mục tiêu:** TV1 có sản phẩm code SDN để bảo vệ, đồng thời phục vụ demo trực quan.

**Cách làm:**
1. Dùng **Flask** (nhẹ hơn FastAPI) tạo web server ở cổng 8080, 3 trang:
   - `/` — dashboard chính, poll `/api/stats` mỗi 2s bằng JS fetch.
   - `/alerts` — bảng danh sách cảnh báo gần đây (đọc từ InfluxDB hoặc log JSON của TV4).
   - `/flows` — gọi Ryu REST API `http://127.0.0.1:8080/stats/flow/<dpid>` hiển thị flow table.
2. Biểu đồ entropy/pps real-time bằng **Chart.js** (CDN, không cần npm).
3. Query InfluxDB: `from(bucket:"sdn") |> range(start:-5m) |> filter(fn:(r)=> r._measurement=="entropy")`.
4. Nút **"Manual block IP"** gọi POST `/api/block` của TV4 → demo khả năng can thiệp thủ công.

**Sản phẩm:** `code/dashboard.py` (~300 dòng), video demo 2' dashboard khi có tấn công.

**Điểm bảo vệ:** TV1 trả lời được câu hỏi về **REST API, Ryu ofctl_rest, InfluxDB query** — đảm bảo có kiến thức SDN/programmable.

#### 🆕 Task 1.10 — `metrics.py` tính TPR/FPR/F1 (T5 D1–D3)
**Cách làm:**
1. Đọc `results/raw/*.json` (log alert TV4) + ground-truth timestamps từ `run_scenario.py` (TV5).
2. Với mỗi kịch bản, chia timeline thành window 1s:
   - Window trong khoảng tấn công + có alert → TP; không có alert → FN.
   - Window ngoài tấn công + có alert → FP; không có alert → TN.
3. Tính TPR/FPR/F1 theo công thức ở `EVALUATION_PROTOCOL.md`.
4. Xuất `results/benchmark.csv` + vẽ biểu đồ confusion matrix, ROC bằng matplotlib → `results/figs/`.

---

## 6. 👤 TV2 — Phúc: Data & Lab

### 6.1 Công việc chi tiết

#### Task 2.1 — Dựng lab (T1 D1–D3)
**Cách làm:**
1. Cài Ubuntu 22.04 VM (4 CPU, 8GB RAM).
2. Cài Mininet: `sudo apt install mininet`, kiểm `sudo mn --test pingall`.
3. Cài Ryu: `pip install ryu` (dùng Python 3.9).
4. Chạy `topology_nhom4.py` có sẵn (5 switch, 8 host, 4 zone).
5. Kiểm: `pingall` → 0% dropped, `ryu-manager l3_router.py` không lỗi.
6. Viết `setup.sh` cài sẵn tools cho 4 TV còn lại:
   ```bash
   #!/bin/bash
   sudo apt update && sudo apt install -y mininet python3-pip tcpdump hping3
   pip install ryu scapy influxdb-client pyyaml
   ```

#### Task 2.2 — Thu baseline 30 phút (T1 D4–D7)
**Cách làm:**
1. Script `capture.sh`:
   ```bash
   tcpdump -i s2-eth1 -w baseline.pcap -G 60 -W 30
   ```
2. Song song sinh traffic hợp pháp đa dịch vụ trên các host:
   - HTTP: `ab -c 10 -n 50000 http://h_web1/`
   - DNS: loop `dig @h_dns1 example.com` mỗi 2s
   - TCP: `iperf3 -c h_app1 -t 1800 -b 5M`
   - ICMP: `ping -i 0.5 h_pc2`
3. Tính `baseline_stats.json`: mean/std của pps, bps, entropy_src, entropy_dport theo cửa sổ 1s.

**Lưu ý:** Baseline quyết định chất lượng toàn bộ hệ thống — chạy ≥30 phút để thống kê ổn định.

#### Task 2.3 — Sinh 5 kịch bản cơ bản (T2 D1–D5) — *gộp với việc trước đây của TV5*
**Cách làm:** mỗi kịch bản chạy 5 phút, lưu `s0X_<tên>.pcap`, viết thành script riêng trong `code/attack_scripts/`.

```bash
# s01_syn.sh
h_att1 hping3 -S -p 80 --flood 10.0.2.10 &
tcpdump -i s2-eth99 -w datasets/s01_syn.pcap -G 300 -W 1

# s02_udp.sh
h_att1 hping3 --udp -p 53 --flood 10.0.2.11

# s03_icmp.sh — hping3 -1 --flood
# s04_http.sh — wrk -t4 -c400 -d300s http://10.0.2.10/
# s05_dns.sh — Scapy dns_ampl.py
```

Mỗi script in ra `START_TS=<epoch>` / `END_TS=<epoch>` để TV5 dùng làm ground truth.

#### ~~Task 2.4 — 5 kịch bản nâng cao~~ **→ chuyển sang TV5** (xem Task 5.10)
> Để TV5 có việc kỹ thuật thực chất thay vì chỉ test/demo, 5 kịch bản nâng cao (s06–s10) được giao cho TV5 viết từ tuần 2 D6. TV2 hỗ trợ review script và cung cấp template từ s01–s05.

#### Task 2.5 — Feature extraction (T3 D4–D7)
**Cách làm:** viết `code/feature_extraction.py` (~250 dòng):
- Input: pcap → dùng Scapy `PcapReader`.
- Window 1s, trượt 0.5s.
- 18 features/window:
  1–4. entropy_src_ip, entropy_dst_ip, entropy_src_port, entropy_dst_port (Shannon)
  5. entropy_renyi_src (q=2)
  6–7. pps, bps
  8–11. syn_pct, ack_pct, rst_pct, fin_pct
  12. udp_pct, 13. icmp_pct
  14. new_flows_per_sec
  15. unique_src_ips
  16. avg_pkt_size, 17. std_pkt_size
  18. dns_resp_req_ratio
- Output: `datasets/features/<scenario>.csv`.

**Hàm entropy (chuẩn):**
```python
from collections import Counter
import math
def shannon(items):
    c = Counter(items); n = sum(c.values())
    return -sum((v/n) * math.log2(v/n) for v in c.values())
```

#### Task 2.6–2.8 — Live pipeline + đối chứng CICDDoS2019
- `live_feed.py`: đọc OpenFlow stats từ Ryu REST `/stats/flow/<dpid>` mỗi 1s, xuất feature JSON qua ZeroMQ cho TV3.
- Hỗ trợ TV5 replay pcap: `tcpreplay -i s2-eth1 dos_syn.pcap`.
- Tải **CICDDoS2019** subset, chuyển về cùng schema 18 features để so sánh ngoài.

---

## 7. 👤 TV3 — Phước: Detection

### 7.1 Công việc chi tiết

#### Task 3.1 — Design doc (T1 D5–D7)
Viết `docs/detection_design.md`: kiến trúc pipeline `Feature → Entropy module → Stats module → Signature matcher → Alert`.

#### Task 3.2 — `entropy_module.py` (T2 D1–D4)
**Cách làm:**
- Class `EntropyDetector(window=1.0)`:
  - `.update(features)` — nhận dict features mỗi 1s
  - `.check()` — trả về cờ `entropy_anomaly` nếu entropy lệch >3σ so baseline
- Baseline: đọc `baseline_stats.json` từ TV2.
- **Unit test:** tạo pcap giả (10 src IP → entropy cao; 1 src IP → entropy ≈ 0), assert phát hiện đúng.

**Paper căn cứ:** A1, A2, B3.

#### Task 3.3 — `stats_module.py` (T2 D5–D7)
Triển khai 3 bộ phát hiện:
1. **Z-score** cho pps, bps, new_flows: `z = (x-μ)/σ`, alert nếu `|z|>3`.
2. **EWMA** với α=0.3 trên pps: cảnh báo nếu `|x - S_t| > 3·σ_ewma`.
3. **CUSUM** (E4): `S_t = max(0, S_{t-1} + (x_t - μ - k))`, alert khi `S_t > h` (k=0.5σ, h=5σ).

Mỗi detector trả về `{attack: bool, score: float, which: str}`.

#### Task 3.4 — `signature_matcher.py` (T3 D1–D4)
**Cách làm:**
- Đọc `docs/attack_signatures.csv` do TV1 làm.
- Với mỗi rule, parse thành biểu thức Python và eval an toàn với `ast`:
  ```python
  # vd: "entropy_src < 1.5 and syn_pct > 0.6"
  ```
- Khớp 14 rules, trả về list `[(attack_name, matched_rule), ...]`.

#### Task 3.5 — `alert_system.py` (T3 D5–D7)
- Cấp độ: INFO / WARN / CRITICAL theo số rule trùng.
- **Dedup:** không log cùng `(attack, src)` quá 1 lần/5s.
- Output JSON + gửi syslog + POST tới TV4 endpoint `/api/alert`.

#### Task 3.6 — Tối ưu ngưỡng (T4–T5)
**Cách làm:**
- Grid search thủ công: với mỗi ngưỡng trong `{1.0, 1.5, 2.0, 2.5, 3.0}·σ`, chạy trên 70% dataset, chọn bộ đạt F1 cao nhất.
- Đặc biệt xử lý **flash crowd (#13)**: nếu entropy_src vẫn cao (nhiều user hợp pháp) mà pps tăng → không alert. Thêm điều kiện kết hợp: `alert = entropy_anomaly AND rate_anomaly`.

---

## 8. 👤 TV4 — Quỳnh: SDN Mitigation

### 8.1 Công việc chi tiết

#### Task 4.1 — Design (T1 D5–D7)
Đọc C1, D1–D4. Thiết kế **graduated response**:
```
Lần 1: Log cảnh báo
Lần 2 (trong 10s): Rate-limit src (Meter)
Lần 3+: Block src 60s (FlowMod drop)
```

#### Task 4.2 — `l3_router_extended.py` (T2 D1–D4)
Kế thừa `l3_router.py`, thêm:
- REST endpoint `POST /api/alert` nhận JSON từ TV3.
- Router tra cứu `src_ip` → gọi module phù hợp.
- Dùng `ryu.app.wsgi` để mở HTTP server.

#### Task 4.3 — `block_module.py` (T2 D5 → T3 D2)
**Cách làm:**
```python
def block_src(dp, src_ip, timeout=60):
    match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
    inst = []  # empty = drop
    mod = parser.OFPFlowMod(datapath=dp, priority=100,
            match=match, instructions=inst,
            hard_timeout=timeout)
    dp.send_msg(mod)
```
Cite D2, D4.

#### Task 4.4 — `rate_limit_module.py` (T3 D3–D6)
Dùng **OpenFlow Meter Table** (OF 1.3+):
```python
bands = [parser.OFPMeterBandDrop(rate=1000, burst_size=100)]  # 1000 pps
mod = parser.OFPMeterMod(dp, command=OFPMC_ADD,
        flags=OFPMF_PKTPS, meter_id=1, bands=bands)
```
Gắn meter vào flow entry khớp src IP.

#### ~~Task 4.5 — DQoS queue~~ **(ĐÃ BỎ — xem ghi chú dưới)**

> 🔻 **Đã cắt khỏi V4.1:** DQoS queue yêu cầu thao tác `ovs-vsctl` ngoài controller, khó demo ổn định và chồng chéo với Meter Table (Task 4.4). Chỉ giữ **Block + Rate-limit** là đủ để chứng minh khả năng mitigation trong SDN. Nếu thời gian dư ở tuần 5, TV4 có thể làm như tính năng mở rộng.

#### Task 4.6 — `blacklist_manager.py` (T4 D4–D5)
- Dict `{src_ip: expire_time}` với TTL 60s.
- Whitelist từ file `whitelist.txt` (DNS server, gateway — không bao giờ block).
- Auto-release khi hết TTL: gọi `remove_flow(src_ip)`.

#### Task 4.7 — Benchmark (T4 D6 → T5 D2)
Viết `benchmark_mitigation.py` đo:
- Thời gian cài 1/10/100/1000 FlowMod (ms).
- Throughput trước/sau khi block (iperf3).
- Độ trễ round-trip trước/sau rate-limit.

Xuất `results/benchmark.csv` + biểu đồ cột.

#### Task 4.8 — Graduated response policy (T5 D3–D5)
File `policy.yaml`:
```yaml
- match: warn
  action: log
- match: critical_first_time
  action: rate_limit_1000pps
- match: critical_repeat
  action: block_60s
```
Module đọc policy + đếm lần khớp theo `src_ip`.

---

## 9. 👤 TV5 — Sang: Testing, Integration, Demo

### 9.1 Công việc chi tiết

#### Task 5.1 — Repo hygiene (T1)
**Cách làm:**
1. Cấu hình `.gitignore`, template PR, nhãn issue.
2. Trello board, assign task cho từng TV.
3. (Không dùng CI/pre-commit ở phạm vi đồ án đại học — mỗi TV tự chạy `pytest` trước khi push.)

#### 🆕 Task 5.10 — Viết 5 attack scripts nâng cao (T2 D6 → T3 D3)
**Mục tiêu:** TV5 có công việc kỹ thuật thực chất, không chỉ "test & demo".

Viết 5 script trong `code/attack_scripts/`:
- **s06_spoof.sh** — Scapy random src IP `/8` flood tới h_web1.
- **s07_slowloris.sh** — `slowhttptest -c 1000 -H -i 10 -r 200 -u http://10.0.2.10/`.
- **s08_multisrc.sh** — chạy `hping3 -S --flood` trên **3 host** h_att1/2/3 song song (dùng `mnexec`/`xterm`).
- **s09_flashcrowd.sh** — `ab -c 200 -n 100000` từ h_pc1–h_pc4 (kỳ vọng **không** bị cảnh báo).
- **s10_backup.sh** — `rsync -av` file 1GB từ h_app1 → h_web1 (kỳ vọng **không** bị cảnh báo).

Mỗi script in `START_TS/END_TS` giống format của TV2 để `run_scenario.py` dùng chung.

**Template lấy từ TV2** (s01–s05 làm trước, TV5 copy format).

#### Task 5.2 — Test fixtures & hướng dẫn (T2)
**Không còn viết unit test thay cho TV khác** (xem §2.1 — mỗi chủ module tự viết). TV5 chỉ chuẩn bị:
- `tests/fixtures/baseline.json` giả, 2 feature CSV giả (1 benign, 1 attack) → các TV khác dùng chung.
- `tests/README.md` hướng dẫn layout + cách chạy `pytest tests/`.

#### Task 5.3 — Integration test E2E (T3 D1–D4)
**Cách làm:** script `tests/test_integration.py` — phần TV5 sở hữu thật sự:
1. Khởi động topology_v4 + Ryu l3_router_extended (subprocess).
2. Chạy `s01_syn.sh` → kiểm log TV4 có alert `syn_flood` trong ≤3s.
3. Verify Ryu ofctl_rest có flow drop với `nw_src=10.0.1.10`.
4. Teardown sạch (`mn -c`).

#### Task 5.4 — E2E harness `run_scenario.py` (T3 D5 → T4 D3)
Kịch bản thật trên Mininet — **gọi script tấn công do TV2 viết** trong `code/attack_scripts/`:
```python
def run(scenario_id):   # ví dụ "s01_syn"
    start_topology()                         # topology_v4.py
    start_ryu_with_mitigation()              # l3_router_extended.py
    start_detector()
    t0 = time.time()
    subprocess.run(["bash", f"attack_scripts/{scenario_id}.sh"])
    t_detect = wait_for_alert()              # đọc log TV4
    t_mitigate = wait_for_flowmod()          # đọc ofctl_rest
    return {"scenario": scenario_id,
            "detect_latency": t_detect - t0,
            "mitigate_latency": t_mitigate - t0}
```
Xuất `results/raw/run_<timestamp>.json` cho TV1 (metrics.py) xử lý.

#### Task 5.5 — Chạy 10 kịch bản × 3 lần (T4 D4–D7)
Lưu `results/results_raw.json`. Tính trung bình & std cho:
- Detection latency
- Mitigation latency
- TPR, FPR per scenario

#### Task 5.6 — Visualization (T5 D1–D4) — *phối hợp TV1*
TV1 làm `metrics.py` (Task 1.10) sinh CSV + confusion/ROC. TV5 bổ sung biểu đồ timeline cần gắn với pcap:
1. Entropy timeline baseline vs SYN flood
2. PPS timeline (14 kịch bản)
3. Confusion matrix
4. Bar chart TPR per attack
5. Bar chart FPR (phải thấy kịch bản 13–14 gần 0)
6. CDF detection latency
7. CDF mitigation latency
8. Throughput trước/sau mitigation
9. Heatmap alert theo thời gian
10. So sánh Mininet vs CICDDoS2019

Lưu `figs/*.png` 300dpi.

#### Task 5.7 — Stress test (T5 D5–D7)
- Tải ×2, ×5, ×10: dùng `tcpreplay --mbps=X`.
- Ghi `stress_report.md`: ở mức nào controller bắt đầu drop alert?

#### Task 5.8 — Demo (T6 D1–D3)
- Slide 15–20 phút (LaTeX Beamer).
- **Video demo dự phòng** (OBS Studio, 5 phút) phòng khi live fail.
- Poster A1 (nếu trường yêu cầu).

#### Task 5.9 — Dry-run (T6 D4–D5)
2 buổi dry-run trước cả nhóm, ghi phản hồi, sửa slide.

---

## 10. Lịch họp

| Loại | Tần suất | Chủ trì |
|---|---|---|
| Standup (20') | T2 / T4 / T6 | TV1 |
| Review tuần (60') | Chủ nhật | TV1 + TV5 |
| Integration day (2h) | Thứ 6 tuần 3–5 | TV5 |
| Dry-run | 2 buổi T6 | Cả nhóm |

---

## 11. Ma trận rủi ro

| Rủi ro | Xác suất | Tác động | Phương án |
|---|---|---|---|
| Ryu/Mininet lỗi version | Trung | Cao | TV2 chốt `setup.sh` tuần 1, mọi TV chạy cùng 1 script |
| FPR cao ở flash crowd | Cao | Trung | Kết hợp nhiều feature (TV3 Task 3.6) |
| Ngưỡng không tổng quát | Cao | Cao | Grid search + CICDDoS2019 |
| Mitigation chặn nhầm DNS | Trung | Cao | Whitelist (Task 4.6) |
| TV vắng đột xuất | Trung | Trung | Buffer T6 D6–D7 |
| Demo live fail | Thấp | Cao | Video demo dự phòng |

---

## 12. Definition of Done

Task được đóng khi:
1. ✅ Code + unit test pass trên CI
2. ✅ Commit theo quy ước `[TVx] module: nội dung`
3. ✅ Có docstring cite paper (nếu là detection/mitigation)
4. ✅ TV1 review + TV5 integration-test
5. ✅ Cập nhật `CHANGELOG.md`

---

## 13. Cấu trúc thư mục (gọn, đủ dùng cho đồ án đại học)

> Nguyên tắc: **giữ phẳng, dễ đọc**. Mỗi TV có 1–2 file chính thay vì cả package. Config để cùng thư mục `code/`, không tách thừa. Không cần CI/pyproject/DVC cho phạm vi đồ án.

```
sdn-dos-detection/
├── README.md                    # TV1 — cách cài, cách chạy, thành viên
├── requirements.txt             # ryu, mininet, scapy, influxdb-client, pyyaml
├── setup.sh                     # TV2 — cài môi trường 1 lệnh cho cả nhóm
├── .gitignore                   # bỏ *.pcap, *.csv, __pycache__, *.log
│
├── docs/                        # tài liệu nộp thầy
│   ├── LITERATURE_SURVEY.md     # TV1 — khảo sát 22 papers
│   ├── THEORY_BACKGROUND.md     # TV1 — lý thuyết Shannon/Renyi/Z/EWMA/CUSUM
│   ├── ATTACK_SIGNATURES.md     # TV3 — 14 rule phát hiện
│   ├── EVALUATION_PROTOCOL.md   # TV5 — cách đo TPR/FPR/F1
│   └── FINAL_REPORT.pdf         # TV1 — báo cáo cuối
│
├── code/                        # toàn bộ code, để phẳng cho dễ nhìn
│   ├── topology_v4.py           # TV2 — topology 12 host (xem TOPOLOGY_V4.md)
│   ├── l3_router_extended.py    # TV2 — Ryu app chính, kế thừa l3_router_test.py
│   ├── entropy.py               # TV3 — shannon() + renyi()
│   ├── stats.py                 # TV3 — zscore(), ewma(), cusum()
│   ├── signature_matcher.py     # TV3 — match 10 rule từ signatures.yaml
│   ├── mitigation.py            # TV4 — block flow + rate-limit Meter + graduated response
│   ├── dashboard.py             # TV1 — REST dashboard (Flask) đọc Ryu REST + InfluxDB
│   ├── metrics.py               # TV1 — tính TPR/FPR/F1 từ log, xuất CSV + plot
│   ├── run_scenario.py          # TV5 — orchestrate chạy tuần tự 10 kịch bản
│   ├── attack_scripts/          # TV2 — 10 script sinh tấn công
│   │   └── s01_syn.sh … s10_backup.sh
│   ├── signatures.yaml          # TV3 — config 10 rule
│   ├── thresholds.yaml          # TV3 — ngưỡng entropy, Z, CUSUM
│   └── whitelist.txt            # TV4 — IP tin cậy
│
├── tests/                       # pytest đơn giản, mỗi module 1 file
│   ├── test_entropy.py          # TV3
│   ├── test_stats.py            # TV3
│   └── test_mitigation.py       # TV4
│
├── datasets/                    # pcap + csv — KHÔNG commit vào git
│   └── s01_icmp.pcap … s14_backup.pcap
│
├── results/                     # output — TV5
│   ├── benchmark.csv            # TPR/FPR/F1 của 14 kịch bản
│   └── figs/                    # các hình cho báo cáo (entropy, ROC, CPU…)
│
└── slides/                      # TV1 — midterm.pptx, final.pptx
```

### 13.1 Ghi chú

- **Code để phẳng trong `code/`** — không tách package con. Đồ án cỡ ~10 file Python, import trực tiếp (`from entropy import shannon`) là đủ.
- **Config (`*.yaml`, `whitelist.txt`) để cạnh code** — không cần thư mục `configs/` riêng.
- **Commit prefix thống nhất:** `[TVx] <module>: <mô tả>` (đã nêu ở §12).
- **File đi kèm:** `TOPOLOGY_V4.md` chứa mã nguồn đầy đủ `topology_v4.py` (QoS + port mirror) — TV2 dùng cho Task 2.1b.

---

**Ghi chú cuối:** Toàn bộ phương pháp dựa trên entropy + thống kê kinh điển (Shannon 1948, Page 1954 CUSUM, Lakhina 2005) — đủ mạnh để đạt TPR ≥92% mà **không cần Machine Learning**, giữ hệ thống nhẹ, real-time, và dễ giải thích trước hội đồng.

---

## 14. 🔍 Đánh giá hiện trạng `topology_nhom4.py` & `l3_router_test.py`

### 14.1 Hiện trạng topology (đã có)
- **5 switch** (s1 External, s2 Router trung tâm, s3 Web/DNS, s4 DB/App, s5 PC)
- **8 host** chia 4 zone: `h_att1, h_ext1` | `h_web1, h_dns1` | `h_db1, h_app1` | `h_pc1, h_pc2`
- RemoteController `127.0.0.1:6653`, OVSKernelSwitch, không có TCLink (không giới hạn băng thông)

### 14.2 Hiện trạng `l3_router_test.py` (đã có)
| Đã có | Còn thiếu so với V4 |
|---|---|
| L3 routing trên s2 (4 zone) | Chỉ cài flow cho whitelist; non-whitelist luôn qua controller (gây nghẽn khi tải cao) |
| Shannon entropy src IP, window 1000 gói, chu kỳ 3s | Renyi entropy, entropy dst IP / src port / dst port |
| Ngưỡng cố định `ENTROPY_LOW=1.5`, `ENTROPY_HIGH=8.0` | Z-score, EWMA, CUSUM theo baseline động |
| Block IP/MAC 60s khi entropy lệch hoặc pps > 500 | Rate-limit (Meter), DQoS, graduated response |
| Whitelist IP hardcode | Load từ file `whitelist.txt`, có TTL blacklist |
| InfluxDB writeback | REST endpoint nhận alert ngoài, JSON log cho TV5 |
| Per-flow PPS qua FlowStats | Tỉ lệ cờ TCP (SYN/ACK/RST/FIN), ICMP%, UDP%, DNS resp/req |
| - | Signature matcher cho 14 attack |
| - | Hỗ trợ OpenFlow 1.3 Meter Table (cần khai báo `protocols=OpenFlow13`) |

---

## 15. 🛠️ Thay đổi BẮT BUỘC trên topology — giao **TV2**

### Task 2.1b — Nâng cấp `topology_nhom4.py` → `topology_v4.py` (T1 D2–D3)

**Lý do thay đổi:**
1. **Chỉ 2 attacker (h_att1, h_ext1) → không đủ cho kịch bản #11 DDoS đa nguồn.** Cần ≥3 attacker.
2. **Không có TCLink → không thể đo bão hoà băng thông** (kịch bản volumetric mất ý nghĩa). Cần giới hạn uplink.
3. **Thiếu host client hợp pháp đông** → kịch bản #13 flash crowd khó tái hiện. Cần ≥4 PC.
4. **Switch chưa khai báo OpenFlow 1.3 tường minh** → Meter Table (TV4 Task 4.4) không hoạt động.
5. **Chưa có cấu hình QoS queue trên s2** → DQoS (TV4 Task 4.5) không chạy được.
6. **Chưa có port mirror để TV2 capture pcap sạch** — hiện TV2 phải `tcpdump` trên `s2-eth1` (1 link) → bỏ sót traffic các zone khác.

**Cụ thể cần sửa:**

```python
# 1. Thêm protocols OpenFlow 1.3
s2 = net.addSwitch('s2', cls=OVSKernelSwitch, dpid='2', protocols='OpenFlow13')
# (lặp lại cho s1, s3, s4, s5)

# 2. Giới hạn băng thông uplink + delay nhỏ
net.addLink(s1, s2, cls=TCLink, bw=10, delay='2ms')   # External ↔ Router
net.addLink(s3, s2, cls=TCLink, bw=100, delay='1ms')  # Server zones nhanh hơn
net.addLink(s4, s2, cls=TCLink, bw=100, delay='1ms')
net.addLink(s5, s2, cls=TCLink, bw=50,  delay='1ms')

# 3. Thêm 2 attacker + 2 client hợp pháp
h_att2 = net.addHost('h_att2', ip='10.0.1.11/24', defaultRoute='via 10.0.1.1')
h_att3 = net.addHost('h_att3', ip='10.0.1.12/24', defaultRoute='via 10.0.1.1')
h_pc3  = net.addHost('h_pc3',  ip='10.0.4.12/24', defaultRoute='via 10.0.4.1')
h_pc4  = net.addHost('h_pc4',  ip='10.0.4.13/24', defaultRoute='via 10.0.4.1')
net.addLink(s1, h_att2); net.addLink(s1, h_att3)
net.addLink(s5, h_pc3);  net.addLink(s5, h_pc4)

# 4. Sau net.build(), thêm cấu hình QoS queue trên s2 (cho TV4)
import os
os.system('ovs-vsctl -- set port s2-eth1 qos=@newqos -- '
          '--id=@newqos create qos type=linux-htb other-config:max-rate=10000000 '
          'queues=0=@q0,1=@q1,2=@q2 '
          '-- --id=@q0 create queue other-config:min-rate=5000000 '   # critical
          '-- --id=@q1 create queue other-config:min-rate=3000000 '   # normal
          '-- --id=@q2 create queue other-config:max-rate=1000000')   # suspect
```

**Sản phẩm:** `topology_v4.py` + `docs/TOPOLOGY_CHANGES.md` ghi diff.

> **Topology mới có 10 host** (3 attacker, 2 server zone1, 2 server zone2, 4 PC), đáp ứng đủ 14 kịch bản.

---

## 16. ♻️ Kế thừa & nâng cấp `l3_router_test.py` — giao **TV4 + TV3**

Bản hiện tại đã có nền móng tốt (entropy + block + InfluxDB). Không viết lại từ đầu — **kế thừa và mở rộng**.

### Task 4.2 (cập nhật) — `l3_router_extended.py` kế thừa từ `SimpleRouterEntropy` (TV4, T2 D1–D4)

**Cách làm:**
```python
from l3_router_test import SimpleRouterEntropy   # kế thừa
from ryu.app.wsgi import WSGIApplication, ControllerBase, route

class L3RouterExtended(SimpleRouterEntropy):
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(AlertAPI, {'router': self})
        # Load whitelist từ file thay vì hardcode
        self.WHITELIST_SRC = self._load_whitelist('whitelist.txt')
        # Đếm số lần khớp rule per src_ip (cho graduated response)
        self.violation_count = {}
```

**Bổ sung mới (TV4):**
- REST `POST /api/alert` nhận JSON từ TV3 → quyết định log / rate-limit / block.
- Nâng `_block_ip` thành `_apply_action(src, action, severity)`.
- Đọc `policy.yaml` (đã định nghĩa Task 4.8).
- **Sửa lỗi tiềm ẩn:** non-whitelist hiện tại luôn qua controller → **dễ tự DoS controller**. Cần cài flow tạm cho non-whitelist với idle_timeout=5s, gửi sample tới controller bằng `OFPActionOutput(CONTROLLER, max_len=128)` thay vì mọi gói.

### Task 3.2–3.5 (cập nhật) — Tách logic detection ra module riêng (TV3, T2)

**Lý do:** code cũ đặt entropy + block chung trong `_monitor_entropy` → khó mở rộng & test.

**Cách làm:**
- TV3 viết `entropy_module.py`, `stats_module.py`, `signature_matcher.py`, `alert_system.py` **độc lập** với router.
- Router (TV4) chỉ giữ data-plane forwarding + REST nhận alert.
- TV3 dùng pipeline: `live_feed.py` (TV2) → modules TV3 → POST sang router.

**Bổ sung detection so với code cũ:**
1. **Renyi entropy q=2** (paper B4) — nhạy hơn entropy Shannon với attack stealthy.
2. **Entropy dst port** — phát hiện port scan.
3. **Tỉ lệ cờ TCP**: parse `tcp.flags` từ pcap/PacketIn (paper A1).
4. **EWMA + CUSUM** trên `total_pps` (paper E4).
5. **Signature matcher 14 rule** (đọc `attack_signatures.csv` của TV1).
6. **Adaptive baseline:** mỗi 5 phút cập nhật `μ, σ` nếu không có alert (giảm FPR khi traffic dao động ban ngày/đêm).

### Task 4.4 (cập nhật) — Rate limit qua Meter Table (TV4, T3 D3–D6)

Code cũ chỉ block — **không có rate-limit**. Bổ sung:
```python
def _rate_limit(self, dp, src_ip, pps=1000):
    parser = dp.ofproto_parser; ofp = dp.ofproto
    # 1) Tạo meter
    band = parser.OFPMeterBandDrop(rate=pps, burst_size=pps//10)
    dp.send_msg(parser.OFPMeterMod(dp, ofp.OFPMC_ADD,
                ofp.OFPMF_PKTPS, meter_id=hash(src_ip)&0xffff, bands=[band]))
    # 2) Flow gắn meter
    match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
    inst = [parser.OFPInstructionMeter(meter_id=hash(src_ip)&0xffff),
            parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                [parser.OFPActionOutput(ofp.OFPP_NORMAL)])]
    dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=80,
                match=match, instructions=inst, hard_timeout=120))
```

### Task 2.5 (cập nhật) — Feature extraction phải tương thích log của router cũ (TV2)

`l3_router_test.py` đã ghi InfluxDB → TV2 có thể **đọc trực tiếp từ InfluxDB** thay vì chỉ parse pcap (rút ngắn pipeline). Giữ cả 2 đường: pcap (offline phân tích chính xác) + InfluxDB (real-time cho dashboard TV5).

---

## 17. 📋 Tóm tắt việc thêm vào bảng phân công

| TV | Công việc mới/cập nhật | Tuần |
|---|---|---|
| **TV2** | Task **2.1b**: viết `topology_v4.py` (10 host, TCLink, OF1.3, QoS queue, port mirror) + `TOPOLOGY_CHANGES.md` | T1 D2–D3 |
| **TV2** | Task **2.5b**: thêm pipeline đọc InfluxDB của router cũ làm nguồn dữ liệu thứ 2 | T3 D5 |
| **TV3** | Task **3.2b**: tách logic entropy của router cũ thành `entropy_module.py` chuẩn hoá interface | T2 D1 |
| **TV3** | Task **3.3b**: bổ sung Renyi + entropy dst port + tỉ lệ cờ TCP | T2 D5 |
| **TV4** | Task **4.2b**: kế thừa `SimpleRouterEntropy` thay vì viết lại; thêm REST API + load whitelist từ file | T2 D1–D4 |
| **TV4** | Task **4.2c**: sửa lỗi non-whitelist luôn punt-to-controller (dễ tự DoS controller) | T2 D4 |
| **TV4** | Task **4.4b**: bổ sung Meter Table (code cũ thiếu) | T3 D3–D6 |
| **TV4** | Task **4.5b**: cấu hình QoS queue qua `ovs-vsctl` đồng bộ với topology mới | T3 D7 |
| **TV5** | Task **5.2b**: viết test regression so sánh hành vi router mới vs `l3_router_test.py` cũ trên cùng pcap (đảm bảo không gãy chức năng cũ) | T2 D7 |
| **TV1** | Task **1.4b**: cập nhật `ATTACK_SIGNATURES.md` để khớp đúng feature mà router/detector mới xuất ra (tên trường, đơn vị) | T2 D6 |

---

## 18. ⚠️ Cảnh báo kỹ thuật quan trọng

1. **OpenFlow 1.3 bắt buộc** cho Meter Table — phải khai báo cả ở topology (`protocols='OpenFlow13'`) và Ryu app (`OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]`).
2. **Khi dùng TCLink với bw=10Mbps**, kịch bản UDP flood hping3 chỉ cần ~12k pps đã saturate — chỉnh `--flood` thành `-i u100` để có thể đo dải.
3. **InfluxDB phải chạy trước** khi khởi động Ryu, nếu không router sẽ chạy nhưng mất dashboard (đã có try/except trong code cũ).
4. **Whitelist gateway** (10.0.x.1) — code cũ đã loại trừ trong `flow_stats_reply_handler` nhưng KHÔNG loại trừ trong `_monitor_entropy` (chỉ check WHITELIST_SRC). Cần thống nhất.
5. **WINDOW_SIZE=1000 với chu kỳ 3s** — ở traffic thấp có thể không đủ 100 gói để trigger entropy → TV3 cần baseline động hoặc cảnh báo "insufficient data".
