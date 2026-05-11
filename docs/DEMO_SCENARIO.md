# KỊCH BẢN DEMO - Hệ thống SDN DDoS Detection & Mitigation

## Khởi động hệ thống

### Terminal 1: Ryu Controller
```bash
cd ~/NT541.Q21-DoS
ryu-manager --ofp-tcp-listen-port 6653 ryu.app.ofctl_rest code/l3_router_extended.py --wsapi-port 8081 --observe-links
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
Truy cập: `http://<VM_IP>:8080`

### Kiểm tra kết nối
```
mininet> pingall
```

---

## Kịch bản 1: SYN Flood (s01)

**Đặc điểm:** TCP SYN, 1 nguồn, PPS rất cao (--flood), port 80

**Lệnh chạy:**
```
mininet> h_att1 bash code/attack_scripts/s01_syn.sh
```

**Kết quả mong đợi:**
| Metric | Giá trị |
|--------|---------|
| Entropy | ~0 (1 source IP) |
| PPS | >3000 |
| Loại tấn công | s01_syn_flood |
| Signature | tcp_pct>0.5 AND entropy_src<1.5 AND pps>3000 |
| Dashboard | Trạng thái: TẤN CÔNG, IP 10.0.1.10 bị chặn |

**Detector log:**
```
*** TẤN CÔNG: s01_syn_flood | src=10.0.1.10 entropy=0 tcp=1.0
>>> Cấp 1/3: GHI NHẬN - s01_syn_flood (10.0.1.10)
>>> Cấp 2/3: RATE-LIMIT - s01_syn_flood (10.0.1.10)
>>> Cấp 3/3: CHẶN IP - s01_syn_flood (10.0.1.10)
```

---

## Kịch bản 2: UDP Flood (s02)

**Đặc điểm:** UDP, 1 nguồn, PPS rất cao, port 53 (DNS)

**Lệnh chạy:**
```
mininet> h_att1 bash code/attack_scripts/s02_udp.sh
```

**Kết quả mong đợi:**
| Metric | Giá trị |
|--------|---------|
| Entropy | ~0 (1 source IP) |
| PPS | >500 |
| Loại tấn công | s02_udp_flood |
| Signature | udp_pct>0.5 AND entropy_src<1.5 AND pps>500 |
| Dashboard | Trạng thái: TẤN CÔNG, IP 10.0.1.10 bị chặn |

---

## Kịch bản 3: ICMP Flood (s03)

**Đặc điểm:** ICMP (ping), 1 nguồn, PPS rất cao

**Lệnh chạy:**
```
mininet> h_att1 bash code/attack_scripts/s03_icmp.sh
```

**Kết quả mong đợi:**
| Metric | Giá trị |
|--------|---------|
| Entropy | ~0 (1 source IP) |
| PPS | >500 |
| Loại tấn công | s03_icmp_flood |
| Signature | icmp_pct>0.5 AND pps>500 |
| Dashboard | Trạng thái: TẤN CÔNG, IP 10.0.1.10 bị chặn |

---

## Kịch bản 4: HTTP Flood (s04)

**Đặc điểm:** TCP SYN port 80, 1 nguồn, PPS trung bình-cao (2000 pps)

**Lệnh chạy:**
```
mininet> h_att1 bash code/attack_scripts/s04_http.sh
```

**Kết quả mong đợi:**
| Metric | Giá trị |
|--------|---------|
| Entropy | ~0 (1 source IP) |
| PPS | 300-3000 |
| Loại tấn công | s04_http_flood |
| Signature | tcp_pct>0.8 AND entropy_src<1.5 AND pps>300 AND pps<3000 |
| Dashboard | Trạng thái: TẤN CÔNG, IP 10.0.1.10 bị chặn |

**Phân biệt với SYN Flood:** PPS thấp hơn (300-3000 vs >3000)

---

## Kịch bản 5: DNS Amplification (s05)

**Đặc điểm:** UDP port 53, IP nguồn giả (--rand-source), entropy cao

**Lệnh chạy:**
```
mininet> h_att1 bash code/attack_scripts/s05_dns_ampl.sh
```

**Kết quả mong đợi:**
| Metric | Giá trị |
|--------|---------|
| Entropy | ~9-10 (rất nhiều IP nguồn giả) |
| PPS | >500 |
| Loại tấn công | s05_dns_ampl |
| Phát hiện | Controller packet_in detect (UDP + port 53 + rand-source) |
| Dashboard | Trạng thái: SPOOF, MAC bị chặn |

**Giải thích:** DNS Amplification sử dụng IP spoofing (giả mạo IP nguồn thành victim). Controller phát hiện từ packet_in vì thấy nhiều IP lạ + UDP port 53. Block bằng MAC (vì IP giả).

---

## Kịch bản 6: IP Spoof Flood (s06)

**Đặc điểm:** TCP SYN port 80, IP nguồn giả (--rand-source), entropy rất cao

**Lệnh chạy:**
```
mininet> h_att1 bash code/attack_scripts/s06_ip_spoof.sh
```

**Kết quả mong đợi:**
| Metric | Giá trị |
|--------|---------|
| Entropy | ~9-10 (hàng nghìn IP nguồn giả) |
| PPS | >500 |
| Loại tấn công | s06_ip_spoof |
| Phát hiện | Controller packet_in detect (>100 pkts + >20 unique IPs trong 2s) |
| Dashboard | Trạng thái: SPOOF, MAC 00:00:00:00:00:01 bị chặn |

**Giải thích:** Attacker giả mạo IP nguồn mỗi gói. Entropy tăng rất cao (~10) nhưng MAC không đổi. Hệ thống block theo MAC address (không đổi được) thay vì IP (thay đổi liên tục).

---

## Kịch bản 7: Slowloris (s07)

**Đặc điểm:** TCP SYN port 80, 1 nguồn, PPS THẤP (~100 pps)

**Lệnh chạy:**
```
mininet> h_att1 bash code/attack_scripts/s07_slowloris.sh
```

**Kết quả mong đợi:**
| Metric | Giá trị |
|--------|---------|
| Entropy | ~0 (1 source IP) |
| PPS | 30-300 (chậm, đặc trưng Slowloris) |
| Loại tấn công | s07_slowloris |
| Signature | tcp_pct>0.5 AND pps>30 AND pps<300 AND entropy_src<1.5 |
| Dashboard | Trạng thái: TẤN CÔNG, IP 10.0.1.10 bị chặn |

**Giải thích:** Slowloris là tấn công chậm — gửi ít gói nhưng giữ kết nối mở lâu để chiếm hết tài nguyên server. PPS thấp hơn flood nhưng vẫn đủ để phát hiện.

---

## Kịch bản 8: Flash Crowd (s08) — KHÔNG BỊ CHẶN

**Đặc điểm:** Nhiều nguồn IP hợp pháp, PPS thấp mỗi nguồn, nhiều port khác nhau

**Lệnh chạy:**
```
mininet> h_att1 bash code/attack_scripts/s08_flash_crowd.sh
```

**Kết quả mong đợi:**
| Metric | Giá trị |
|--------|---------|
| Entropy | ~2.5 (6 IP nguồn khác nhau) |
| PPS | ~120 tổng (20 pps/nguồn) |
| Loại tấn công | KHÔNG PHÁT HIỆN |
| Dashboard | Trạng thái: Bình thường, KHÔNG có IP bị chặn |

**Giải thích:** Flash crowd mô phỏng nhiều người dùng hợp pháp truy cập cùng lúc. Hệ thống KHÔNG phát hiện là tấn công vì:
- PPS mỗi nguồn rất thấp (<200)
- Tất cả IP nguồn đều nằm trong whitelist
- Entropy vừa phải (không quá thấp cũng không quá cao)
- Không match bất kỳ signature tấn công nào

---

## Bảng tóm tắt

| Kịch bản | Entropy | PPS | Protocol | Phát hiện | Chặn |
|----------|---------|-----|----------|-----------|------|
| s01 SYN Flood | ~0 | >3000 | TCP | Signature + Stat | IP |
| s02 UDP Flood | ~0 | >500 | UDP | Signature + Stat | IP |
| s03 ICMP Flood | ~0 | >500 | ICMP | Signature + Stat | IP |
| s04 HTTP Flood | ~0 | 300-3000 | TCP | Signature + Stat | IP |
| s05 DNS Ampl | ~9-10 | >500 | UDP:53 | Packet_in (spoof) | MAC |
| s06 IP Spoof | ~9-10 | >500 | TCP | Packet_in (spoof) | MAC |
| s07 Slowloris | ~0 | 30-300 | TCP | Signature + Stat | IP |
| s08 Flash Crowd | ~2.5 | ~120 | TCP | **Không phát hiện** | **Không** |

## Lưu ý quan trọng

1. **Đợi 30 giây** giữa các kịch bản để hệ thống tự động gỡ chặn
2. Kiểm tra trạng thái chặn: `sudo ovs-ofctl -O OpenFlow13 dump-flows s2 | grep "priority=100"`
3. Gỡ chặn thủ công: Vào trang Alerts > nhập IP > bấm "Gỡ chặn"
4. Dashboard tự động cập nhật mỗi 2 giây
