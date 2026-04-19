# Hướng Dẫn Cài Đặt Grafana + Prometheus cho DDoS Detection

## Kiến Trúc Hệ Thống

```
┌──────────────┐     scrape     ┌──────────────┐     query     ┌──────────────┐
│  Ryu SDN     │───────────────▶│  Prometheus  │◀──────────────│   Grafana    │
│  Controller  │  :9100/metrics │  Server      │               │  Dashboard   │
│              │                │  :9090       │               │  :3000       │
└──────────────┘                └──────────────┘               └──────────────┘
       │
       │ OpenFlow
       ▼
┌──────────────┐
│   Mininet    │
│  Topology    │
└──────────────┘
```

---

## Bước 1: Cài đặt prometheus_client cho Python (trên máy chạy Ryu)

```bash
pip install prometheus_client
```

Kiểm tra:
```bash
python -c "from prometheus_client import start_http_server; print('OK')"
```

---

## Bước 2: Cài đặt Prometheus Server

### Cách 1: Cài trực tiếp (Ubuntu/Debian)

```bash
# Download Prometheus
cd /tmp
wget https://github.com/prometheus/prometheus/releases/download/v2.51.0/prometheus-2.51.0.linux-amd64.tar.gz
tar xvfz prometheus-2.51.0.linux-amd64.tar.gz
cd prometheus-2.51.0.linux-amd64

# Copy file config tu project
cp /path/to/project/prometheus.yml ./prometheus.yml

# Chay Prometheus
./prometheus --config.file=prometheus.yml
```

Prometheus sẽ chạy tại: **http://localhost:9090**

### Cách 2: Dùng Docker

```bash
docker run -d \
  --name prometheus \
  --net=host \
  -v /path/to/project/prometheus.yml:/etc/prometheus/prometheus.yml \
  prom/prometheus
```

---

## Bước 3: Cài đặt Grafana

### Cách 1: Cài trực tiếp (Ubuntu/Debian)

```bash
sudo apt-get install -y software-properties-common
sudo add-apt-repository "deb https://packages.grafana.com/oss/deb stable main"
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
sudo apt-get update
sudo apt-get install grafana

# Khoi dong
sudo systemctl start grafana-server
sudo systemctl enable grafana-server
```

### Cách 2: Dùng Docker

```bash
docker run -d \
  --name grafana \
  --net=host \
  grafana/grafana
```

Grafana sẽ chạy tại: **http://localhost:3000**

**Đăng nhập lần đầu:** admin / admin

---

## Bước 4: Cấu hình Grafana

### 4.1. Thêm Prometheus Data Source

1. Mở Grafana: http://localhost:3000
2. Vào **Configuration → Data Sources → Add data source**
3. Chọn **Prometheus**
4. URL: `http://localhost:9090`
5. Nhấn **Save & Test** → phải thấy "Data source is working"

### 4.2. Import Dashboard

1. Vào **Dashboards → Import**
2. Nhấn **Upload JSON file**
3. Chọn file `grafana_dashboard.json` trong thư mục project
4. Chọn Prometheus data source vừa tạo
5. Nhấn **Import**

---

## Bước 5: Chạy toàn bộ hệ thống

### Terminal 1: Ryu Controller

```bash
ryu-manager l3_router_test.py
```

Nếu thành công sẽ thấy dòng:
```
[GRAFANA] Prometheus metrics: http://0.0.0.0:9100/metrics
```

### Terminal 2: Mininet Topology

```bash
sudo mn -c
sudo python topology_nhom4.py
```

### Terminal 3: Prometheus (nếu chưa chạy)

```bash
cd /path/to/prometheus
./prometheus --config.file=/path/to/project/prometheus.yml
```

### Kiểm tra

1. Mở http://localhost:9100/metrics → Xem metrics từ Ryu
2. Mở http://localhost:9090 → Prometheus, thử query `sdn_entropy_value`
3. Mở http://localhost:3000 → Grafana Dashboard

---

## Bước 6: Demo tấn công

### Demo 1: Botnet Attack (Low Entropy)

Trong Mininet CLI:
```bash
h_web1 pkill iperf
h_web1 iperf -s -p 80 &
h_ext1 iperf -c 10.0.2.10 -p 80 -t 300 &
h_att1 hping3 -S -p 80 --flood 10.0.2.10 &
h_att2 hping3 -S -p 80 --flood 10.0.2.10
```

**Quan sát Grafana:** Entropy sẽ giảm xuống < 1.5, Status chuyển đỏ "BOTNET!"

### Demo 2: Spoofed IP Attack (High Entropy)

```bash
h_web1 pkill iperf
h_web1 iperf -s -p 80 &
h_ext1 iperf -c 10.0.2.10 -p 80 -t 300 &
h_att1 hping3 -S -p 80 --flood --rand-source 10.0.2.10
```

**Quan sát Grafana:** Entropy sẽ tăng vọt > 5.5, Status chuyển cam "SPOOFED!"

---

## Danh sách Metrics trên Grafana

| Metric | Loại | Mô tả |
|--------|------|--------|
| `sdn_entropy_value` | Gauge | Giá trị Shannon Entropy hiện tại |
| `sdn_entropy_threshold_high` | Gauge | Ngưỡng entropy cao (Spoofed) |
| `sdn_entropy_threshold_low` | Gauge | Ngưỡng entropy thấp (Botnet) |
| `sdn_entropy_unique_ips` | Gauge | Số IP duy nhất trong window |
| `sdn_entropy_window_packets` | Gauge | Số gói tin trong window |
| `sdn_packet_in_pps` | Gauge | Packet-In / giây |
| `sdn_packet_in_total` | Counter | Tổng Packet-In |
| `sdn_attack_botnet_total` | Counter | Tổng lần phát hiện Botnet |
| `sdn_attack_spoof_total` | Counter | Tổng lần phát hiện Spoofed IP |
| `sdn_blocked_ips_current` | Gauge | Số IP đang bị block |
| `sdn_blocked_ips_total` | Counter | Tổng IP đã từng bị block |
| `sdn_system_status` | Gauge | 0=Normal, 1=Botnet, 2=Spoofed |
| `sdn_port_rx_pps{dpid,port}` | Gauge | RX packets/s theo port |
| `sdn_port_tx_pps{dpid,port}` | Gauge | TX packets/s theo port |
| `sdn_port_rx_bytes_total{dpid,port}` | Gauge | Tổng bytes nhận |
| `sdn_port_tx_bytes_total{dpid,port}` | Gauge | Tổng bytes gửi |
| `sdn_port_rx_errors_total{dpid,port}` | Gauge | Lỗi nhận (RX) |
| `sdn_port_tx_errors_total{dpid,port}` | Gauge | Lỗi gửi (TX) |
| `sdn_port_rx_dropped_total{dpid,port}` | Gauge | Gói bị drop (RX) |
| `sdn_port_tx_dropped_total{dpid,port}` | Gauge | Gói bị drop (TX) |
