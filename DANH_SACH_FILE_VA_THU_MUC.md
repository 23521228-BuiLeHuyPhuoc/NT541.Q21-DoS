# 📋 Danh Sách Tệp và Thư Mục - Dự Án NT541.Q21-DDoS

**Ngày tạo:** May 9, 2026  
**Mô tả:** Tài liệu liệt kê toàn bộ cấu trúc thư mục, danh sách tệp, và mô tả nội dung của dự án phát hiện và giảm thiểu tấn công DDoS sử dụng OpenFlow/SDN.

---

## 📁 Cấu Trúc Thư Mục Chính

```
NT541.Q21-DDoS/
├── .git/                          # Git repository folder
├── .github/                       # GitHub configuration
├── code/                          # 📌 Mã nguồn chính của dự án
│   ├── __init__.py               # Package initialization (trống)
│   ├── __pycache__/              # Python cache
│   ├── alert_system.py           # Hệ thống cảnh báo
│   ├── dashboard.py              # Dashboard Flask/InfluxDB
│   ├── detector.py               # Orchestrator phát hiện DDoS
│   ├── entropy.py                # Shannon + Rényi entropy detector
│   ├── feature_extraction.py     # Trích xuất features từ PCAP
│   ├── l3_router_extended.py    # Ryu SDN Controller (L3 routing)
│   ├── l3_router_test.py        # Unit test cho l3_router
│   ├── mitigation.py             # Block, RateLimit, Blacklist modules
│   ├── policy.yaml               # Graduated response policy
│   ├── run_scenario.py           # Chạy kịch bản kiểm thử
│   ├── signature_matcher.py      # Signature-based attack detection
│   ├── whitelist.txt             # Danh sách IP tin cậy
│   ├── attack_scripts/           # 📌 Kịch bản tấn công DDoS
│   ├── pipeline/                 # 📌 Data pipeline (InfluxDB)
│   ├── scripts/                  # 📌 Utility scripts
│   ├── templates/                # 📌 HTML templates (Flask)
│   └── topology/                 # 📌 Mininet topology
├── datasets/                      # 📌 Dữ liệu và features
├── docs/                          # 📌 Tài liệu
├── figs/                          # 📌 Hình ảnh/Biểu đồ
├── report/                        # 📌 Báo cáo
├── results/                       # 📌 Kết quả thực nghiệm
├── slides/                        # 📌 Slide thuyết trình
└── tests/                         # 📌 Unit tests & Integration tests
```

---

## 📂 Chi Tiết Các Thư Mục

### 🔸 `code/` - Mã Nguồn Chính

#### **Tệp Python Chính:**

| Tệp                     | Mô Tả                       | Chức Năng Chính                                               |
| ----------------------- | --------------------------- | ------------------------------------------------------------- |
| `__init__.py`           | Package initialization      | Trống, để cấu hình package Python                             |
| `alert_system.py`       | Hệ thống cảnh báo           | Emit alerts, log JSON, dedup, post HTTP                       |
| `dashboard.py`          | Flask Dashboard             | Web UI, query InfluxDB, hiển thị chart entropy/pps            |
| `detector.py`           | Orchestrator DDoS Detection | Gọi Ryu REST, trích features, chạy 3-layer detector           |
| `entropy.py`            | Entropy-based Detector      | Shannon + Rényi entropy, adaptive baseline, anomaly detection |
| `feature_extraction.py` | PCAP Feature Extractor      | Đọc .pcap, tính Shannon/Rényi per window, output CSV          |
| `l3_router_extended.py` | Ryu SDN Controller          | L3 routing, OpenFlow rule management, traffic control         |
| `l3_router_test.py`     | Unit Test Router            | Kiểm thử logic L3 routing                                     |
| `mitigation.py`         | Mitigation Modules          | BlockModule, RateLimitModule, BlacklistManager                |
| `signature_matcher.py`  | Signature Detector          | CSV-based rules, safe_eval, attack signature matching         |
| `run_scenario.py`       | Test Scenario Runner        | Start Mininet topology, Ryu, Detector, run attacks            |

#### **Tệp Cấu Hình:**

| Tệp             | Nội Dung                                                                        |
| --------------- | ------------------------------------------------------------------------------- |
| `policy.yaml`   | Graduated response policy: Level 1 (log), Level 2 (rate_limit), Level 3 (block) |
| `whitelist.txt` | Danh sách 5 IP tin cậy: 10.0.1.1, 10.0.2.1, 10.0.3.1, 10.0.4.1, 10.0.2.11       |

---

### 🔸 `code/attack_scripts/` - Kịch Bản Tấn Công

| Tệp Script           | Loại Tấn Công     | Mô Tả                             |
| -------------------- | ----------------- | --------------------------------- |
| `s01_syn.sh`         | SYN Flood         | Gửi SYN packets, SYN+ACK response |
| `s02_udp.sh`         | UDP Flood         | Flood UDP packets đến target      |
| `s03_icmp.sh`        | ICMP Flood        | Flood ICMP echo requests          |
| `s04_http.sh`        | HTTP Flood        | GET requests HTTP lặp lại         |
| `s05_dns_ampl.sh`    | DNS Amplification | DNS query amplification attack    |
| `s06_ip_spoof.sh`    | IP Spoofing       | Giả mạo source IP                 |
| `s07_slowloris.sh`   | Slowloris         | Slow HTTP POST attack             |
| `s08_flash_crowd.sh` | Flash Crowd       | Legitimate-like traffic spikes    |

---

### 🔸 `code/pipeline/` - Data Pipeline

| Tệp                | Mô Tả                                                  |
| ------------------ | ------------------------------------------------------ |
| `influx_writer.py` | Kết nối InfluxDB, query entropy data, lưu CSV realtime |
| `.gitkeep`         | Git marker file (empty)                                |

---

### 🔸 `code/scripts/` - Utility Scripts

| Tệp                   | Mô Tả                                |
| --------------------- | ------------------------------------ |
| `compute_baseline.py` | Tính toán baseline từ dữ liệu benign |
| `influx_pull.py`      | Pull data từ InfluxDB, export CSV    |

---

### 🔸 `code/templates/` - HTML Templates (Flask)

| Tệp           | Mô Tả                        |
| ------------- | ---------------------------- |
| `index.html`  | Trang chính dashboard        |
| `alerts.html` | Trang hiển thị alerts        |
| `flows.html`  | Trang hiển thị network flows |
| `.gitkeep`    | Git marker file              |

---

### 🔸 `code/topology/` - Mininet Topology

| Tệp              | Mô Tả                                             |
| ---------------- | ------------------------------------------------- |
| `topology_v4.py` | Mininet topology v4 (L3 routing, hosts, switches) |

---

### 🔸 `datasets/` - Dữ Liệu Huấn Luyện & Test

#### **PCAP Files (Network Traffic):**

| Tệp             | Loại Dữ Liệu      | Mô Tả                                  |
| --------------- | ----------------- | -------------------------------------- |
| `baseline.pcap` | Benign traffic    | Dữ liệu traffic bình thường (baseline) |
| `s01_syn.pcap`  | SYN Flood attack  | Captured packets từ SYN flood attack   |
| `s02_udp.pcap`  | UDP Flood attack  | Captured packets từ UDP flood attack   |
| `s03_icmp.pcap` | ICMP Flood attack | Captured packets từ ICMP flood attack  |
| `s04_http.pcap` | HTTP Flood attack | Captured packets từ HTTP flood attack  |

#### **Thư Mục `features/` - Extracted CSV Features:**

| Tệp            | Mô Tả                                                                  |
| -------------- | ---------------------------------------------------------------------- |
| `baseline.csv` | Features trích từ baseline.pcap (Shannon entropy, Rényi, packet stats) |
| `s01_syn.csv`  | Features từ SYN flood PCAP                                             |
| `s02_udp.csv`  | Features từ UDP flood PCAP                                             |
| `s03_icmp.csv` | Features từ ICMP flood PCAP                                            |
| `s04_http.csv` | Features từ HTTP flood PCAP                                            |

---

### 🔸 `docs/` - Tài Liệu

| Tệp                     | Nội Dung                                                      |
| ----------------------- | ------------------------------------------------------------- |
| `attack_signatures.csv` | CSV attack signatures (rules, thresholds, feature conditions) |
| `.gitkeep`              | Git marker file                                               |

---

### 🔸 `tests/` - Kiểm Thử

#### **Tệp Test Python:**

| Tệp                         | Loại Test        | Mô Tả                                         |
| --------------------------- | ---------------- | --------------------------------------------- |
| `test_entropy.py`           | Unit Test        | Kiểm thử Shannon/Rényi entropy calculation    |
| `test_signature.py`         | Unit Test        | Kiểm thử signature matching logic             |
| `test_mitigation.py`        | Unit Test        | Kiểm thử block/rate-limit modules             |
| `test_blacklist.py`         | Unit Test        | Kiểm thử blacklist manager                    |
| `test_regression_router.py` | Unit Test        | Kiểm thử L3 router logic                      |
| `test_integration.py`       | Integration Test | E2E test: Mininet + Ryu + Detector (cần root) |
| `README.md`                 | Documentation    | Hướng dẫn chạy tests                          |

#### **Thư Mục `fixtures/` - Mock Data:**

| Tệp                   | Dùng Cho        | Mô Tả                                                |
| --------------------- | --------------- | ---------------------------------------------------- |
| `baseline.json`       | Baseline stats  | Baseline statistics (mean, std) cho entropy detector |
| `features_benign.csv` | Benign features | Mock benign traffic features                         |
| `features_attack.csv` | Attack features | Mock attack traffic features                         |

---

### 🔸 `results/` - Kết Quả Thực Nghiệm

```
results/
├── raw/
│   ├── alerts.json        # JSON log alerts thực tế từ detector
│   └── ...
└── ...
```

---

### 🔸 `figs/` - Hình Ảnh & Biểu Đồ

- Thư mục chứa hình ảnh, biểu đồ kết quả thực nghiệm

---

### 🔸 `report/` - Báo Cáo

- Thư mục chứa báo cáo chi tiết về dự án

---

### 🔸 `slides/` - Slide Thuyết Trình

- Thư mục chứa slide trình bày kết quả

---

## 📝 Nội Dung Chi Tiết Các Tệp Chính

### 1️⃣ `code/alert_system.py`

**Mục đích:** Quản lý hệ thống cảnh báo, log alerts và gửi HTTP POST đến TV4 endpoint.

**Các thành phần chính:**

- `AlertSystem` class: Quản lý alerts
- `severity()`: Xác định mức độ nghiêm trọng (INFO/WARN/CRITICAL)
- `emit()`: Phát hành alert với deduplication (5s window)
- Log path: `results/raw/alerts.json`
- Endpoint TV4: `http://127.0.0.1:8081/api/alert`

**Cấu trúc JSON Alert:**

```json
{
  "timestamp": 1715219200.0,
  "src_ip": "10.0.1.10",
  "attack": "SYN_Flood",
  "severity": "CRITICAL",
  "n_rules": 3,
  "evidence": [...]
}
```

---

### 2️⃣ `code/entropy.py`

**Mục đích:** Phát hiện DDoS dựa trên entropy của dữ liệu mạng.

**Thuật toán:**

- **Shannon Entropy:** $H(X) = -\sum p(x) \log_2 p(x)$
- **Rényi Entropy (q=2):** $H_q(X) = \frac{1}{1-q} \log_2 \sum (p(x))^q$

**Các thành phần:**

- `shannon()`: Tính Shannon entropy
- `renyi()`: Tính Rényi entropy
- `EntropyDetector` class:
  - Load baseline từ JSON
  - `check()`: Phát hiện anomaly dùng k-sigma rule
  - `update_baseline()`: Adaptive baseline (cập nhật mỗi 5 phút nếu không có alert)

**Baseline stats gồm:**

- `entropy_src_ip`: Entropy của source IP
- `entropy_dst_port`: Entropy của destination port
- `entropy_renyi_src`: Rényi entropy của source

---

### 3️⃣ `code/detector.py`

**Mục đích:** Orchestrator chính phát hiện DDoS, tích hợp 3 layer detector.

**Alur chính:**

1. Gọi Ryu REST API `/stats/flow/2` để lấy flow statistics
2. Trích xuất features (PPS, BPS, entropy, suspicious IPs)
3. Chạy 3 layer detector:
   - **EntropyDetector:** Entropy-based anomaly
   - **StatsDetector:** Statistics-based anomaly
   - **SignatureMatcher:** Signature-based detection
4. Merge alerts và emit đến alert system
5. Gọi mitigation nếu cần

**Feature được trích:**

- `pps`: Packets per second
- `bps`: Bits per second
- `entropy_src_ip`: Source IP entropy
- `entropy_dst_port`: Destination port entropy
- `syn_pct`: SYN packet percentage
- `icmp_pct`: ICMP packet percentage
- `suspect_src_ip`: Source IP khả nghi nhất

---

### 4️⃣ `code/feature_extraction.py`

**Mục đích:** Trích xuất network features từ PCAP files.

**Thuật toán:**

- Đọc PCAP file dùng Scapy
- Sliding window: kích thước `win`, bước trượt `slide`
- Tính entropy của source IP, destination port, protocol mỗi window
- Output CSV columns:
  - `timestamp`
  - `pps` (packets per second)
  - `bps` (bits per second)
  - `entropy_src_ip`
  - `entropy_dst_port`
  - `entropy_protocol`
  - `syn_count`, `icmp_count`, `udp_count`

---

### 5️⃣ `code/signature_matcher.py`

**Mục đích:** Phát hiện DDoS dựa trên attack signatures (rule-based).

**Hệ thống rule:**

- Đọc từ CSV: `docs/attack_signatures.csv`
- Cột chính: `name`, `rule` (Python boolean expression), `severity`
- **Safe evaluation:** Chỉ cho phép operators và variables hợp lệ
- `match()`: Đối chiếu features với tất cả rules, trả về matching rules

**Ví dụ rule:**

```
pps > 1000 and entropy_src_ip < 3.0
```

---

### 6️⃣ `code/mitigation.py`

**Mục đích:** Giảm thiểu DDoS attack qua OpenFlow rules.

**3 Modules:**

1. **BlockModule:**
   - Tạo OpenFlow rule DROP (drop all packets từ src_ip)
   - Hard timeout: 60s (default)

2. **RateLimitModule:**
   - Dùng Meter Table (OpenFlow 1.3)
   - Giới hạn PPS (packets per second) của src_ip
   - Timeout: 120s

3. **BlacklistManager:**
   - Quản lý blacklist entries (src_ip → expire_ts)
   - Auto-release entries hết hạn
   - Persistent storage (optional)

---

### 7️⃣ `code/dashboard.py`

**Mục đích:** Web dashboard Flask hiển thị metrics real-time.

**Routes chính:**

- `/`: Trang chính (index.html)
- `/api/stats`: Query InfluxDB, trả JSON entropy + pps
- `/alerts`: Hiển thị alert log từ `results/raw/alerts.json`
- `/flows`: Hiển thị network flows

**Database:** InfluxDB (`sdn` org, `sdn` bucket)

**Port:** Flask chạy trên port mặc định (5000)

---

### 8️⃣ `code/l3_router_extended.py`

**Mục đích:** Ryu SDN Controller cho L3 routing + traffic engineering.

**Chức năng:**

- Học MAC address table động
- Forward packets theo L3 routing rules
- Support OpenFlow 1.3
- Integrate mitigation modules

**REST API:** Chạy trên port 8080

---

### 9️⃣ `code/run_scenario.py`

**Mục đích:** Chạy scenario kiểm thử end-to-end.

**Alur:**

1. Khởi động Mininet topology
2. Khởi động Ryu Controller
3. Khởi động Detector
4. Chạy attack script
5. Chờ alerts xuất hiện
6. Cleanup

---

### 🔟 `code/policy.yaml`

**Nội dung:** Graduated response policy (3 levels).

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

**Giải thích:**

- **Level 1:** Log only (trigger ngay)
- **Level 2:** Rate limit 1000 pps, duration 120s (khi 2 detector trigger)
- **Level 3:** Block (hard drop), duration 60s (khi 3 detector trigger)

---

### 1️⃣1️⃣ `code/whitelist.txt`

**Danh sách IP tin cậy (không bao giờ block):**

```
10.0.1.1
10.0.2.1
10.0.3.1
10.0.4.1
10.0.2.11
```

---

### 1️⃣2️⃣ `tests/README.md`

**Hướng dẫn chạy tests:**

#### Unit Tests (không cần Mininet, không cần root):

```bash
pytest tests/test_entropy.py tests/test_stats.py tests/test_signature.py tests/test_mitigation.py -v
```

#### Integration Tests (cần root, cần Mininet):

```bash
sudo pytest tests/test_integration.py -v --timeout=120
```

---

### 1️⃣3️⃣ `tests/fixtures/baseline.json`

**Nội dung:** Baseline statistics cho entropy detector.

Cấu trúc:

```json
{
  "entropy_src_ip": {
    "mean": 3.5,
    "std": 0.8
  },
  "entropy_dst_port": {
    "mean": 4.2,
    "std": 1.1
  },
  "entropy_renyi_src": {
    "mean": 2.8,
    "std": 0.6
  }
}
```

---

## 📊 Flow Của Hệ Thống DDoS Detection

```
┌─────────────────────────────────────────┐
│   Mininet Topology (Host + Switch)     │
└──────────────────┬──────────────────────┘
                   │ Network Traffic (PCAP)
                   ▼
┌─────────────────────────────────────────┐
│   Ryu Controller (l3_router_extended)   │
│   - OpenFlow rule management           │
│   - L3 routing                          │
│   - REST API :8080/stats/flow/2        │
└──────────────────┬──────────────────────┘
                   │ Flows Statistics
                   ▼
┌─────────────────────────────────────────┐
│      Detector (detector.py)             │
│  ┌───────────────────────────────────┐  │
│  │ Extract Features (PPS, BPS, etc)  │  │
│  └───────────────────┬───────────────┘  │
│                      │                   │
│  ┌───────────────────▼───────────────┐  │
│  │ 3-Layer Detection:                │  │
│  │ 1. EntropyDetector                │  │
│  │ 2. StatsDetector                  │  │
│  │ 3. SignatureMatcher               │  │
│  └───────────────────┬───────────────┘  │
│                      │                   │
│  ┌───────────────────▼───────────────┐  │
│  │ Merge Alerts → Alert System       │  │
│  └───────────────────┬───────────────┘  │
└──────────────────┬──────────────────────┘
                   │ Alerts JSON
                   ▼
┌─────────────────────────────────────────┐
│   Alert System (alert_system.py)        │
│   - Dedup (5s window)                   │
│   - Log to JSON                         │
│   - POST to TV4 HTTP API                │
└─────────────────────────────────────────┘
                   │
        ┌──────────┴──────────┐
        ▼                     ▼
   ┌────────┐          ┌──────────────┐
   │  JSON  │          │  Mitigation  │
   │  Log   │          │  (Block/RL)  │
   └────────┘          └──────────────┘
        │                     │
        │                     ▼
        │              ┌─────────────────┐
        │              │ OpenFlow Rules  │
        │              │ (Ryu sends)     │
        │              └─────────────────┘
        ▼
┌─────────────────────────────────────────┐
│   Dashboard (dashboard.py)              │
│   - Query InfluxDB                      │
│   - Display Alerts & Flows              │
│   - Web UI (Flask)                      │
└─────────────────────────────────────────┘
```

---

## 🔧 Công Nghệ & Thư Viện Sử Dụng

| Thành Phần            | Công Nghệ/Thư Viện |
| --------------------- | ------------------ |
| **SDN Controller**    | Ryu                |
| **Network Emulation** | Mininet            |
| **PCAP Reading**      | Scapy              |
| **Time Series DB**    | InfluxDB           |
| **Web Framework**     | Flask              |
| **Testing**           | pytest             |
| **Language**          | Python 3           |
| **Protocol**          | OpenFlow 1.3       |

---

## 📦 Tóm Tắt Thống Kê

| Loại                       | Số Lượng                       |
| -------------------------- | ------------------------------ |
| **Python files (.py)**     | 13+                            |
| **Shell scripts (.sh)**    | 8                              |
| **HTML templates (.html)** | 3                              |
| **PCAP files (.pcap)**     | 5                              |
| **CSV files (.csv)**       | 5+                             |
| **Test files**             | 6+                             |
| **Configuration files**    | 2 (policy.yaml, whitelist.txt) |
| **Thư mục chính**          | 10+                            |

---

## 🚀 Quick Start Guide

### 1. **Cài đặt dependencies:**

```bash
pip install ryu mininet scapy influxdb-client flask pytest
```

### 2. **Khởi động InfluxDB:**

```bash
# Docker hoặc cài local
docker run -d -p 8086:8086 influxdb:2
```

### 3. **Chạy scenario kiểm thử:**

```bash
cd e:\baitap\khả lập trình\github\NT541.Q21-DDoS
sudo python3 code/run_scenario.py
```

### 4. **Chạy unit tests:**

```bash
pytest tests/test_entropy.py -v
```

### 5. **Xem dashboard:**

```bash
python3 code/dashboard.py
# Truy cập: http://localhost:5000
```

---

## 📖 Các File Tài Liệu Khác

- `tests/README.md`: Hướng dẫn chi tiết chạy tests
- `docs/attack_signatures.csv`: Attack signature definitions
- `code/policy.yaml`: Graduated response policy configuration

---

**Cuối cùng cập nhật:** May 9, 2026

**Tác giả:** DDoS Detection Project Team

**Dự án:** NT541.Q21 - DDoS Detection & Mitigation System (SDN-based)
