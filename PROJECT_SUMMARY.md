# NT541.Q21-DDoS - PROJECT CODE SUMMARY

---

## 📋 FILE LISTING

```
code/entropy.py
code/feature_extraction.py
code/l3_router_test.py
code/attack_scripts/s01_syn.sh
code/attack_scripts/s02_udp.sh
code/attack_scripts/s03_icmp.sh
code/attack_scripts/s04_http.sh
code/pipeline/influx_writer.py
code/scripts/compute_baseline.py
code/topology/topology_nhom4.py
datasets/baseline.pcap
datasets/s01_syn.pcap
datasets/s02_udp.pcap
datasets/s03_icmp.pcap
datasets/s04_http.pcap
datasets/features/baseline.csv
datasets/features/s01_syn.csv
datasets/features/s02_udp.csv
datasets/features/s03_icmp.csv
datasets/features/s04_http.csv
docs/attack_signature.csv
tests/README.md
tests/fixtures/baseline.json
tests/fixtures/features_attack.csv
tests/fixtures/features_benign.csv
```

---

## 📄 FILE CONTENTS

### 1. code/entropy.py

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

---

### 2. code/feature_extraction.py

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

---

### 3. code/l3_router_test.py

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
    HAS_INFLUX = True
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

---

### 4. code/attack_scripts/s01_syn.sh

```bash
#!/bin/bash
# Kich ban tan cong SYN Flood
VICTIM=10.0.2.10
DURATION=60

echo "Bat dau SYN Flood vao $VICTIM trong $DURATION giay..."
timeout $DURATION hping3 -S -p 80 --flood $VICTIM
echo "Hoan tat tan cong SYN Flood!"
```

---

### 5. code/attack_scripts/s02_udp.sh

```bash
#!/bin/bash
# Kich ban tan cong UDP Flood (vao may DNS)
VICTIM=10.0.2.11
DURATION=60

echo "Bat dau UDP Flood vao $VICTIM trong $DURATION giay..."
timeout $DURATION hping3 --udp -p 53 -i u100 $VICTIM
echo "Hoan tat tan cong UDP Flood!"
```

---

### 6. code/attack_scripts/s03_icmp.sh

```bash
#!/bin/bash
# Kich ban tan cong ICMP (Ping) Flood
VICTIM=10.0.2.10
DURATION=60

echo "Bat dau ICMP Flood vao $VICTIM trong $DURATION giay..."
timeout $DURATION hping3 -1 --flood $VICTIM
echo "Hoan tat tan cong ICMP Flood!"
```

---

### 7. code/attack_scripts/s04_http.sh

```bash
#!/bin/bash
# Kich ban tan cong HTTP GET Flood
VICTIM=10.0.2.10
DURATION=60

echo "Bat dau HTTP Flood vao $VICTIM trong $DURATION giay..."
timeout $DURATION wrk -t4 -c400 -d300s http://$VICTIM/
echo "Hoan tat tan cong HTTP Flood!"
```

---

### 8. code/pipeline/influx_writer.py

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

---

### 9. code/scripts/compute_baseline.py

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

---

### 10. code/topology/topology_nhom4.py

```python
#!/usr/bin/env python3
"""
topology_nhom4.py — TV2 (Phúc) — Task 2.1 & 2.2
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

---

### 11. tests/README.md

````markdown
# Hướng dẫn chạy Kiểm thử (Testing)

Thư mục `tests/` chứa toàn bộ các kịch bản kiểm thử cho hệ thống phát hiện và giảm thiểu DDoS. Thư mục này bao gồm các bài test độc lập (Unit Test) và bài test tích hợp toàn hệ thống (Integration Test).

## 1. Cấu trúc thư mục (Layout)

- `fixtures/`: Chứa các dữ liệu giả lập (mock data) như `baseline.json`, `features_benign.csv`, `features_attack.csv` để phục vụ cho Unit Test.

- `test_*.py`: Các kịch bản kiểm thử cho từng module tương ứng (entropy, stats, signature, mitigation, integration).

## 2. Hướng dẫn chạy (How to run)

### 2.1. Unit Test (Không cần Mininet)

Unit Test được sử dụng để kiểm tra logic toán học và xử lý của từng module một cách độc lập. Tốc độ chạy rất nhanh và **không yêu cầu quyền root**.

Để chạy toàn bộ các Unit Test, sử dụng lệnh sau:

```bash
pytest tests/test_entropy.py tests/test_stats.py tests/test_signature.py tests/test_mitigation.py -v
```
````

### 2.2. Integration Test (Cần Root)

Integration Test sẽ dựng toàn bộ hệ thống thực tế (bao gồm Ryu Controller, topo mạng Mininet, và luồng Detector) để kiểm tra kiểm thử đầu cuối (E2E).

Do cần can thiệp vào card mạng ảo, loại test này bắt buộc chạy với quyền root (`sudo`) và cần set timeout cao do thời gian dựng topology mạng.

Để chạy Integration Test, sử dụng lệnh sau:

```bash
sudo pytest tests/test_integration.py -v --timeout=120
```

````

---

### 12. tests/fixtures/baseline.json
```json
{
  "pps": {
    "mean": 11.4255,
    "std": 6.4299
  },
  "bps": {
    "mean": 10662.5532,
    "std": 6515.0966
  },
  "entropy_src": {
    "mean": 1.2983,
    "std": 0.2901
  },
  "entropy_dport": {
    "mean": 1.3328,
    "std": 0.3521
  }
}
````

---

## 📊 DATA FILES (Binary/Large)

### Datasets (PCAP files)

- `datasets/baseline.pcap` - Baseline traffic capture
- `datasets/s01_syn.pcap` - SYN Flood attack traffic
- `datasets/s02_udp.pcap` - UDP Flood attack traffic
- `datasets/s03_icmp.pcap` - ICMP Flood attack traffic
- `datasets/s04_http.pcap` - HTTP Flood attack traffic

### Features (CSV files)

- `datasets/features/baseline.csv` - Extracted features from baseline traffic
- `datasets/features/s01_syn.csv` - Extracted features from SYN Flood
- `datasets/features/s02_udp.csv` - Extracted features from UDP Flood
- `datasets/features/s03_icmp.csv` - Extracted features from ICMP Flood
- `datasets/features/s04_http.csv` - Extracted features from HTTP Flood

### Test Fixtures (CSV files)

- `tests/fixtures/features_attack.csv` - Attack features for testing
- `tests/fixtures/features_benign.csv` - Benign features for testing

---

## 📝 SUMMARY

**Total Files:** 25+

- **Python Scripts:** 5 (.py)
- **Shell Scripts:** 4 (.sh)
- **Data Files:** 5 PCAP + 8 CSV
- **Config Files:** 1 JSON
- **Documentation:** 1 MD

**Project Focus:** DDoS Detection and Mitigation using Entropy-based methods in SDN environment

```

File tổng hợp đã được tạo tại **PROJECT_SUMMARY.md** - chứa toàn bộ danh sách file và code của các file trong project!
```
