# DEMO SCENARIO - SDN DDoS Detection & Mitigation

## Khoi dong he thong

### Terminal 1: Ryu Controller
```bash
cd ~/NT541.Q21-DoS
ryu-manager --ofp-tcp-listen-port 6653 --wsapi-port 8081 code/l3_router_extended.py
```

### Terminal 2: Mininet Topology
```bash
cd ~/NT541.Q21-DoS
sudo python3 code/topology/topology_v4.py
```

### Terminal 3: Detector
```bash
cd ~/NT541.Q21-DoS
python3 code/detector.py
```

### Terminal 4: Dashboard
```bash
cd ~/NT541.Q21-DoS
python3 code/dashboard.py
```
Truy cap: `http://<VM_IP>:8080`

### Kiem tra ket noi
```
mininet> pingall
```

---

## Kich ban 1: SYN Flood (s01)

**Dac diem:** TCP SYN, 1 nguon, PPS rat cao (--flood), port 80

**Lenh chay:**
```
mininet> h_att1 bash code/attack_scripts/s01_syn.sh
```

**Ket qua mong doi:**
| Metric | Gia tri |
|--------|---------|
| Entropy | ~0 (1 source IP) |
| PPS | >3000 |
| Attack type | s01_syn_flood |
| Signature | tcp_pct>0.5 AND entropy_src<1.5 AND pps>3000 |
| Dashboard | Trang thai: TAN CONG, IP 10.0.1.10 bi chan |

**Detector log:**
```
*** TAN CONG: s01_syn_flood | src=10.0.1.10 entropy=0 tcp=1.0
>>> Cap 1/3: GHI NHAN - s01_syn_flood (10.0.1.10)
>>> Cap 2/3: RATE-LIMIT - s01_syn_flood (10.0.1.10)
>>> Cap 3/3: CHAN IP - s01_syn_flood (10.0.1.10)
```

---

## Kich ban 2: UDP Flood (s02)

**Dac diem:** UDP, 1 nguon, PPS rat cao, port 53 (DNS)

**Lenh chay:**
```
mininet> h_att1 bash code/attack_scripts/s02_udp.sh
```

**Ket qua mong doi:**
| Metric | Gia tri |
|--------|---------|
| Entropy | ~0 (1 source IP) |
| PPS | >500 |
| Attack type | s02_udp_flood |
| Signature | udp_pct>0.5 AND entropy_src<1.5 AND pps>500 |
| Dashboard | Trang thai: TAN CONG, IP 10.0.1.10 bi chan |

---

## Kich ban 3: ICMP Flood (s03)

**Dac diem:** ICMP (ping), 1 nguon, PPS rat cao

**Lenh chay:**
```
mininet> h_att1 bash code/attack_scripts/s03_icmp.sh
```

**Ket qua mong doi:**
| Metric | Gia tri |
|--------|---------|
| Entropy | ~0 (1 source IP) |
| PPS | >500 |
| Attack type | s03_icmp_flood |
| Signature | icmp_pct>0.5 AND pps>500 |
| Dashboard | Trang thai: TAN CONG, IP 10.0.1.10 bi chan |

---

## Kich ban 4: HTTP Flood (s04)

**Dac diem:** TCP SYN port 80, 1 nguon, PPS trung binh-cao (2000 pps)

**Lenh chay:**
```
mininet> h_att1 bash code/attack_scripts/s04_http.sh
```

**Ket qua mong doi:**
| Metric | Gia tri |
|--------|---------|
| Entropy | ~0 (1 source IP) |
| PPS | 300-3000 |
| Attack type | s04_http_flood |
| Signature | tcp_pct>0.8 AND entropy_src<1.5 AND pps>300 AND pps<3000 |
| Dashboard | Trang thai: TAN CONG, IP 10.0.1.10 bi chan |

**Phan biet voi SYN Flood:** PPS thap hon (300-3000 vs >3000)

---

## Kich ban 5: DNS Amplification (s05)

**Dac diem:** UDP port 53, IP nguon gia (--rand-source), entropy cao

**Lenh chay:**
```
mininet> h_att1 bash code/attack_scripts/s05_dns_ampl.sh
```

**Ket qua mong doi:**
| Metric | Gia tri |
|--------|---------|
| Entropy | ~9-10 (rat nhieu IP nguon gia) |
| PPS | >500 |
| Attack type | s05_dns_ampl |
| Detection | Controller packet_in detect (UDP + port 53 + rand-source) |
| Dashboard | Trang thai: SPOOF, MAC bi chan |

**Giai thich:** DNS Amplification su dung IP spoofing (gia mao IP nguon thanh victim). Controller phat hien tu packet_in vi thay nhieu IP la + UDP port 53. Block bang MAC (vi IP gia).

---

## Kich ban 6: IP Spoof Flood (s06)

**Dac diem:** TCP SYN port 80, IP nguon gia (--rand-source), entropy rat cao

**Lenh chay:**
```
mininet> h_att1 bash code/attack_scripts/s06_ip_spoof.sh
```

**Ket qua mong doi:**
| Metric | Gia tri |
|--------|---------|
| Entropy | ~9-10 (hang nghin IP nguon gia) |
| PPS | >500 |
| Attack type | s06_ip_spoof |
| Detection | Controller packet_in detect (>100 pkts + >20 unique IPs trong 2s) |
| Dashboard | Trang thai: SPOOF, MAC 00:00:00:00:00:01 bi chan |

**Giai thich:** Attacker gia mao IP nguon moi goi. Entropy tang rat cao (~10) nhung MAC khong doi. He thong block theo MAC address (khong doi duoc) thay vi IP (thay doi lien tuc).

---

## Kich ban 7: Slowloris (s07)

**Dac diem:** TCP SYN port 80, 1 nguon, PPS THAP (~100 pps)

**Lenh chay:**
```
mininet> h_att1 bash code/attack_scripts/s07_slowloris.sh
```

**Ket qua mong doi:**
| Metric | Gia tri |
|--------|---------|
| Entropy | ~0 (1 source IP) |
| PPS | 30-300 (cham, dac trung Slowloris) |
| Attack type | s07_slowloris |
| Signature | tcp_pct>0.5 AND pps>30 AND pps<300 AND entropy_src<1.5 |
| Dashboard | Trang thai: TAN CONG, IP 10.0.1.10 bi chan |

**Giai thich:** Slowloris la tan cong cham — gui it goi nhung giu ket noi mo lau de chiem het tai nguyen server. PPS thap hon flood nhung van du de phat hien.

---

## Kich ban 8: Flash Crowd (s08) — KHONG BI CHAN

**Dac diem:** Nhieu nguon IP hop phap, PPS thap moi nguon, nhieu port khac nhau

**Lenh chay:**
```
mininet> h_att1 bash code/attack_scripts/s08_flash_crowd.sh
```

**Ket qua mong doi:**
| Metric | Gia tri |
|--------|---------|
| Entropy | ~2.5 (6 IP nguon khac nhau) |
| PPS | ~120 tong (20 pps/nguon) |
| Attack type | KHONG PHAT HIEN |
| Dashboard | Trang thai: Binh thuong, KHONG co IP bi chan |

**Giai thich:** Flash crowd mo phong nhieu nguoi dung hop phap truy cap cung luc. He thong KHONG phat hien la tan cong vi:
- PPS moi nguon rat thap (<200)
- Tat ca IP nguon deu nam trong whitelist
- Entropy vua phai (khong qua thap cung khong qua cao)
- Khong match bat ky signature tan cong nao

---

## Bang tom tat

| Kich ban | Entropy | PPS | Protocol | Detection | Block |
|----------|---------|-----|----------|-----------|-------|
| s01 SYN Flood | ~0 | >3000 | TCP | Signature + Stat | IP |
| s02 UDP Flood | ~0 | >500 | UDP | Signature + Stat | IP |
| s03 ICMP Flood | ~0 | >500 | ICMP | Signature + Stat | IP |
| s04 HTTP Flood | ~0 | 300-3000 | TCP | Signature + Stat | IP |
| s05 DNS Ampl | ~9-10 | >500 | UDP:53 | Packet_in (spoof) | MAC |
| s06 IP Spoof | ~9-10 | >500 | TCP | Packet_in (spoof) | MAC |
| s07 Slowloris | ~0 | 30-300 | TCP | Signature + Stat | IP |
| s08 Flash Crowd | ~2.5 | ~120 | TCP | **Khong phat hien** | **Khong** |

## Luu y quan trong

1. **Doi 30 giay** giua cac kich ban de he thong tu dong go chan
2. Kiem tra trang thai chan: `sudo ovs-ofctl -O OpenFlow13 dump-flows s2 | grep "priority=100"`
3. Go chan thu cong: Vao trang Alerts > nhap IP > bam "Go chan"
4. Dashboard tu dong cap nhat moi 2 giay
