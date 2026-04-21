# 🖧 TOPOLOGY_V4.md — Topology nâng cấp cho đề tài phát hiện DoS/DDoS trên SDN

> File này cung cấp **mã nguồn đầy đủ** của `topology_v4.py` — bản nâng cấp từ `topology_nhom4.py` đã có. **TV2** chịu trách nhiệm triển khai, **TV1** review, **TV5** dùng để chạy 14 kịch bản benchmark.

---

## 1. So sánh nhanh V3 (cũ) vs V4 (mới)

| Mục | `topology_nhom4.py` (V3) | `topology_v4.py` (V4) |
|---|---|---|
| Số switch | 5 (s1–s5) | 5 (giữ nguyên) |
| Số host | 8 | **12** (+2 attacker, +2 PC client) |
| OpenFlow | Mặc định (1.0) | **OpenFlow 1.3** tường minh (bắt buộc cho Meter) |
| Link | Link thường | **TCLink** có `bw` + `delay` |
| Băng thông uplink s1↔s2 | Không giới hạn | **10 Mbps** (để đo bão hoà) |
| QoS Queue | Không có | **3 queue HTB** trên `s2-eth1` (critical / normal / suspect) |
| Port mirror | Không có | **Mirror s2-eth1 → s2-eth99** để TV2 capture pcap sạch |
| Attacker zone | 2 host (`h_att1`, `h_ext1`) | **4 host** (thêm `h_att2`, `h_att3`) cho kịch bản DDoS đa nguồn |
| Client zone PC | 2 host | **4 host** cho kịch bản flash crowd |

---

## 2. Sơ đồ logic

```
                        ┌──────── Controller Ryu (127.0.0.1:6653) ────────┐
                        │                                                 │
 [EXTERNAL/ATTACKER]    │        [ROUTER]         [SERVERS]               │
 h_att1  10.0.1.10 ─┐   │                     ┌── h_web1 10.0.2.10        │
 h_att2  10.0.1.11 ─┼── s1 ── 10Mbps/2ms ── s2 ── 100Mbps/1ms ── s3       │
 h_att3  10.0.1.12 ─┤                        │                ├── h_dns1  │
 h_ext1  10.0.1.20 ─┘                        │                             │
                                             ├── 100Mbps/1ms ── s4        │
                                             │                ├── h_db1   │
                                             │                └── h_app1  │
                                             │                             │
                                             └── 50Mbps/1ms  ── s5        │
                                                              ├── h_pc1   │
                                                              ├── h_pc2   │
                                                              ├── h_pc3   │
                                                              └── h_pc4   │

 Subnet:  10.0.1.0/24 (external)   10.0.2.0/24 (web/dns)
          10.0.3.0/24 (db/app)     10.0.4.0/24 (pc client)
 Gateway: .1 ở mỗi subnet, xử lý bởi L3 router trên s2 (Ryu app)
```

---

## 3. Mã nguồn đầy đủ — `code/topology/topology_v4.py`

```python
#!/usr/bin/env python3
"""
topology_v4.py — Topology nâng cấp cho đề tài phát hiện DoS/DDoS trên SDN.

Thay đổi so với topology_nhom4.py:
  1. OpenFlow 1.3 tường minh (cho Meter Table của TV4)
  2. TCLink có bw + delay để đo bão hoà băng thông
  3. Thêm 2 attacker (h_att2, h_att3) cho kịch bản DDoS đa nguồn
  4. Thêm 2 PC client (h_pc3, h_pc4) cho kịch bản flash crowd hợp pháp
  5. Cấu hình QoS HTB 3 queue trên s2-eth1 (critical/normal/suspect) cho DQoS
  6. Port mirror s2-eth1 → s2-eth99 để TV2 tcpdump pcap tập trung

Chạy:
    sudo python3 topology_v4.py
Sau khi mininet CLI mở:
    mininet> pingall        # kiểm tra L3 routing qua Ryu hoạt động
    mininet> xterm h_att1   # mở shell attacker
"""

import os
import sys
import time

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

# ---------------------------------------------------------------------------
# Cấu hình tập trung — TV2 chỉ sửa ở đây khi cần thử nghiệm giới hạn băng thông
# ---------------------------------------------------------------------------
CTRL_IP, CTRL_PORT = '127.0.0.1', 6653
OF_PROTO = 'OpenFlow13'

LINK_EXT = dict(bw=10,  delay='2ms')   # s1 ↔ s2 (uplink External, cố tình hẹp)
LINK_SRV = dict(bw=100, delay='1ms')   # s2 ↔ s3, s2 ↔ s4 (server nhanh)
LINK_PC  = dict(bw=50,  delay='1ms')   # s2 ↔ s5 (client)
LINK_HOST = dict(bw=100, delay='0.5ms')  # host ↔ switch (gần như lossless)

MIRROR_PORT = 99  # Port ảo dùng để TV2 tcpdump (xem phần setup_mirror)


def build_topology():
    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch,
                  link=TCLink, autoSetMacs=True, build=False)

    # -------- Controller --------
    c0 = net.addController('c0', controller=RemoteController,
                           ip=CTRL_IP, port=CTRL_PORT)

    # -------- Switches (OpenFlow 1.3) --------
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch, dpid='0000000000000001',
                       protocols=OF_PROTO)  # External zone
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch, dpid='0000000000000002',
                       protocols=OF_PROTO)  # Router trung tâm (L3)
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch, dpid='0000000000000003',
                       protocols=OF_PROTO)  # Web / DNS zone
    s4 = net.addSwitch('s4', cls=OVSKernelSwitch, dpid='0000000000000004',
                       protocols=OF_PROTO)  # DB / App zone
    s5 = net.addSwitch('s5', cls=OVSKernelSwitch, dpid='0000000000000005',
                       protocols=OF_PROTO)  # PC client zone

    # -------- Hosts --------
    # External / Attacker zone (10.0.1.0/24, GW .1)
    h_att1 = net.addHost('h_att1', ip='10.0.1.10/24', defaultRoute='via 10.0.1.1')
    h_att2 = net.addHost('h_att2', ip='10.0.1.11/24', defaultRoute='via 10.0.1.1')
    h_att3 = net.addHost('h_att3', ip='10.0.1.12/24', defaultRoute='via 10.0.1.1')
    h_ext1 = net.addHost('h_ext1', ip='10.0.1.20/24', defaultRoute='via 10.0.1.1')

    # Web / DNS zone (10.0.2.0/24)
    h_web1 = net.addHost('h_web1', ip='10.0.2.10/24', defaultRoute='via 10.0.2.1')
    h_dns1 = net.addHost('h_dns1', ip='10.0.2.11/24', defaultRoute='via 10.0.2.1')

    # DB / App zone (10.0.3.0/24)
    h_db1  = net.addHost('h_db1',  ip='10.0.3.10/24', defaultRoute='via 10.0.3.1')
    h_app1 = net.addHost('h_app1', ip='10.0.3.11/24', defaultRoute='via 10.0.3.1')

    # PC client zone (10.0.4.0/24) — 4 máy cho flash crowd
    h_pc1 = net.addHost('h_pc1', ip='10.0.4.10/24', defaultRoute='via 10.0.4.1')
    h_pc2 = net.addHost('h_pc2', ip='10.0.4.11/24', defaultRoute='via 10.0.4.1')
    h_pc3 = net.addHost('h_pc3', ip='10.0.4.12/24', defaultRoute='via 10.0.4.1')
    h_pc4 = net.addHost('h_pc4', ip='10.0.4.13/24', defaultRoute='via 10.0.4.1')

    # -------- Inter-switch links (s2 là trung tâm) --------
    net.addLink(s1, s2, cls=TCLink, **LINK_EXT)  # s2-eth1
    net.addLink(s3, s2, cls=TCLink, **LINK_SRV)  # s2-eth2
    net.addLink(s4, s2, cls=TCLink, **LINK_SRV)  # s2-eth3
    net.addLink(s5, s2, cls=TCLink, **LINK_PC)   # s2-eth4

    # -------- Host ↔ switch links --------
    for h in (h_att1, h_att2, h_att3, h_ext1):
        net.addLink(h, s1, cls=TCLink, **LINK_HOST)
    net.addLink(h_web1, s3, cls=TCLink, **LINK_HOST)
    net.addLink(h_dns1, s3, cls=TCLink, **LINK_HOST)
    net.addLink(h_db1,  s4, cls=TCLink, **LINK_HOST)
    net.addLink(h_app1, s4, cls=TCLink, **LINK_HOST)
    for h in (h_pc1, h_pc2, h_pc3, h_pc4):
        net.addLink(h, s5, cls=TCLink, **LINK_HOST)

    return net


# ---------------------------------------------------------------------------
# QoS / Mirror setup — chạy SAU net.start() vì cần interface đã tồn tại
# ---------------------------------------------------------------------------
def setup_qos():
    """Tạo 3 queue HTB trên s2-eth1 (uplink External ↔ Router):
        q0 = critical (≥5 Mbps)   → flow whitelist
        q1 = normal   (≥3 Mbps)   → flow thường
        q2 = suspect  (≤1 Mbps)   → flow bị nghi ngờ (TV4 Task 4.5 DQoS)
    """
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
    """Mirror toàn bộ traffic trên s2-eth1 sang s2-eth99 (dummy port)
    để TV2 chạy `tcpdump -i s2-eth99 -w capture.pcap` bắt gói tập trung,
    không bỏ sót traffic zone nào.
    """
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
    info('*** Cleaning QoS + mirror\n')
    os.system('ovs-vsctl -- --all destroy qos -- --all destroy queue')
    os.system('ovs-vsctl clear bridge s2 mirrors')
    os.system('ovs-vsctl -- --all destroy mirror')
    os.system(f'ip link del s2-eth{MIRROR_PORT} 2>/dev/null || true')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    setLogLevel('info')
    net = build_topology()
    net.build()
    net.start()

    # Chờ switch connect controller
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
    if os.geteuid() != 0:
        sys.exit('Phải chạy với sudo (Mininet cần quyền root).')
    main()
```

---

## 4. Kiểm thử nhanh sau khi chạy

```bash
sudo mn -c                                # dọn rác mininet trước đó
sudo python3 code/topology/topology_v4.py

# Trong mininet CLI:
mininet> pingall                          # 12 host, expect 100% (cần Ryu L3 chạy)
mininet> iperf h_pc1 h_web1               # kỳ vọng ≈ 50 Mbps (bottleneck s5↔s2)
mininet> iperf h_att1 h_web1              # kỳ vọng ≈ 10 Mbps (bottleneck s1↔s2)
mininet> h_att1 hping3 -S -p 80 --flood 10.0.2.10   # thử SYN flood
```

Ở shell khác, verify QoS + mirror:
```bash
sudo ovs-vsctl list qos                    # thấy 3 queue
sudo tcpdump -i s2-eth99 -c 20             # thấy gói mirror
```

---

## 5. Hướng mở rộng (ghi chú cho TV2)

- Nếu cần **kịch bản #11 DDoS đa nguồn quy mô lớn hơn**: nhân bản thêm `h_att4, h_att5` và link vào `s1`.
- Nếu cần **đo packet loss chính xác**: thêm `loss=1` vào `LINK_EXT` (mô phỏng 1% loss nền).
- Nếu chạy trên máy yếu: giảm `bw` đồng loạt xuống 1/10 để tránh CPU saturate Mininet.

---

**Tham chiếu chéo:** Xem `PHANCONGV4.md` §15 (thay đổi bắt buộc) và §16 (mapping port → zone cho signature matcher của TV3).
