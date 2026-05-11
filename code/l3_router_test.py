from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp, icmp
from ryu.lib import hub
from collections import Counter
import math
import time
import json
import os
import datetime

try:
    from influxdb import InfluxDBClient
    HAS_INFLUX = False
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
        self.proto_window = []             # DANH SACH PROTOCOL (tcp_syn, udp, icmp...)
        self.blocked_ips = set()           # TAP IP DA BI CHAN
        self.blocked_macs = set()          # TAP MAC DA BI CHAN
        self.packet_rate = 0               # DEM SO GOI TRONG MOI CHU KY
        self.ENTROPY_HIGH = 8.0            # NGUONG CAO (NGHI NGO SPOOF)
        self.ENTROPY_LOW = 1.5             # NGUONG THAP (NGHI NGO 1 IP TAN CONG)
        self.attack_status = 0             # 0: BINH THUONG, 1: TAN CONG IP, 2: SPOOF
        self.last_entropy = 0.0            # CACHE ENTROPY MOI NHAT CHO DASHBOARD

        # --- SPOOF DETECTION tu packet_in ---
        self._pktin_window_start = time.time()
        self._pktin_count = 0
        self._pktin_unique_ips = set()
        self._pktin_mac_counter = Counter()
        self._pktin_proto_counter = Counter()  # Dem protocol (tcp/udp/icmp)
        self._pktin_dport_counter = Counter()  # Dem destination port
        self._SPOOF_WINDOW = 2             # Kiem tra moi 2 giay
        self._SPOOF_PKT_THRESHOLD = 100    # > 100 packet_in trong 1 window
        self._SPOOF_IP_THRESHOLD = 20      # > 20 IP duy nhat
        self._SPOOF_IP_RATIO = 0.3         # Ty le unique_ip/total > 30%
        self._spoof_blocked_macs = set()   # MAC da bi block do spoof
        self._spoof_victim_ip = None       # IP bi tan cong

        # DANH SACH IP HOP LE (KHONG BI CHAN)
        self.WHITELIST_SRC = {
            '10.0.2.10', '10.0.2.11',
            '10.0.3.10', '10.0.3.11',
            '10.0.4.10', '10.0.4.11',
            '10.0.4.12', '10.0.4.13',
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
            self.logger.debug("[INFLUXDB] Thu vien influxdb chua duoc cai dat.")

        # --- FLOW STATS ---
        self.flow_stats = {}
        self.total_pps = 0

        self._startup_time = time.time()  # Thoi diem khoi dong (dung cho grace period)
        hub.spawn(self._monitor_entropy)
        hub.spawn(self._monitor_flows)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.dps[dp.id] = dp
            self.logger.info("[RYU] Switch s%d (dpid=%d) da ket noi", dp.id, dp.id)
        elif dp.id in self.dps:
            del self.dps[dp.id]
            self.logger.info("[RYU] Switch s%d (dpid=%d) da ngat ket noi", dp.id, dp.id)

# TINH ENTROPY CHO DASHBOARD (Khong block -- de detector.py + l3_router_extended.py xu ly)
    def _monitor_entropy(self):
        while True:
            hub.sleep(3)

            current_rate = self.packet_rate
            self.packet_rate = 0
            entropy = 0.0
            window_size = len(self.src_ip_window)

            if window_size >= 10:
                ip_counts = Counter(self.src_ip_window)
                total = len(self.src_ip_window)
                for count in ip_counts.values():
                    p = count / total
                    entropy -= p * math.log2(p)
                self.last_entropy = entropy
                # Chi cap nhat trang thai cho dashboard, KHONG block
                if window_size >= 100 and current_rate >= 50:
                    if entropy < self.ENTROPY_LOW:
                        self.attack_status = 1
                    elif entropy > self.ENTROPY_HIGH:
                        self.attack_status = 2
                    else:
                        self.attack_status = 0
                else:
                    self.attack_status = 0
                self.src_ip_window.clear()
                self.src_mac_window.clear()
                self.proto_window.clear()
            else:
                self.last_entropy = 0.0
                self.attack_status = 0

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

    def _classify_attack(self):
        """Phan loai tan cong dua tren protocol trong window -> map 8 kich ban."""
        if not self.proto_window:
            return "s01_syn_flood"
        proto_counts = Counter(self.proto_window)
        dominant, count = proto_counts.most_common(1)[0]
        total = len(self.proto_window)
        ratio = count / total

        if dominant == 'icmp' and ratio > 0.4:
            return "s03_icmp_flood"
        elif dominant == 'udp_dns' and ratio > 0.3:
            return "s05_dns_ampl"
        elif dominant == 'udp' and ratio > 0.4:
            return "s02_udp_flood"
        elif dominant == 'tcp_http' and ratio > 0.3:
            # Phan biet s04 vs s07: slowloris co PPS thap
            if self.packet_rate < 50:
                return "s07_slowloris"
            return "s04_http_flood"
        elif dominant == 'tcp_syn' and ratio > 0.4:
            return "s01_syn_flood"
        elif dominant == 'tcp' and ratio > 0.3:
            if self.packet_rate < 50:
                return "s07_slowloris"
            return "s04_http_flood"
        return "s01_syn_flood"

    def _log_alert(self, src, attack_type, severity, action):
        """Ghi alert vao file JSON de dashboard /alerts page hien thi."""
        try:
            alert = {
                "timestamp": time.time(),
                "src_ip": src,
                "attack": attack_type,
                "severity": severity,
                "n_rules": 1 if severity == "INFO" else (2 if severity == "WARN" else 3),
                "action": action
            }
            alerts_file = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                       '..', 'results', 'raw', 'alerts.json')
            os.makedirs(os.path.dirname(alerts_file), exist_ok=True)
            with open(alerts_file, 'a') as f:
                f.write(json.dumps(alert) + "\n")
        except Exception as e:
            self.logger.error("[ALERT LOG] Loi ghi alert: %s", e)

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
                    # Khong block o day — de detector.py + l3_router_extended.py xu ly
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
            # Cac switch khac (s1, s3, s4, s5) dung L2 forwarding cua SimpleSwitch13
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

            # --- SPOOF DETECTION: theo doi packet_in rate + unique IPs ---
            if p_ip.src not in self.gateways and p_ip.src not in self.WHITELIST_SRC:
                now_pkt = time.time()
                self._pktin_count += 1
                self._pktin_unique_ips.add(p_ip.src)
                self._pktin_mac_counter[p_eth.src] += 1
                # Theo doi protocol va port de phan loai attack
                self._pktin_proto_counter[p_ip.proto] += 1  # 6=TCP, 17=UDP, 1=ICMP
                p_tcp_spoof = pkt.get_protocol(tcp.tcp)
                p_udp_spoof = pkt.get_protocol(udp.udp)
                if p_tcp_spoof:
                    self._pktin_dport_counter[p_tcp_spoof.dst_port] += 1
                elif p_udp_spoof:
                    self._pktin_dport_counter[p_udp_spoof.dst_port] += 1

                if now_pkt - self._pktin_window_start >= self._SPOOF_WINDOW:
                    # Neu window qua cu (vd nghi > 3s), khong phan tich ma chi reset
                    if now_pkt - self._pktin_window_start <= self._SPOOF_WINDOW + 1.0:
                        self._check_spoof_flood(dp, p_ip.dst)
                    # Reset window
                    self._pktin_window_start = now_pkt
                    self._pktin_count = 0
                    self._pktin_unique_ips.clear()
                    self._pktin_mac_counter.clear()
                    self._pktin_proto_counter.clear()
                    self._pktin_dport_counter.clear()

            # Ghi TAT CA IP vao window (ke ca whitelist) de pingall tao entropy cao
            # Chi loai gateway IP (khong phai traffic thuc)
            if p_ip.src not in self.gateways:
                self.src_ip_window.append(p_ip.src)
                self.src_mac_window.append(p_eth.src)
                # Theo doi protocol de phan loai tan cong
                p_tcp = pkt.get_protocol(tcp.tcp)
                p_udp = pkt.get_protocol(udp.udp)
                p_icmp = pkt.get_protocol(icmp.icmp)
                if p_icmp:
                    self.proto_window.append('icmp')
                elif p_tcp:
                    if (p_tcp.bits & 0x02) and not (p_tcp.bits & 0x10):
                        if p_tcp.dst_port == 80 or p_tcp.dst_port == 443:
                            self.proto_window.append('tcp_http')
                        else:
                            self.proto_window.append('tcp_syn')
                    else:
                        self.proto_window.append('tcp')
                elif p_udp:
                    if p_udp.dst_port == 53:
                        self.proto_window.append('udp_dns')
                    else:
                        self.proto_window.append('udp')
                else:
                    self.proto_window.append('other')
                if len(self.src_ip_window) > self.WINDOW_SIZE:
                    self.src_ip_window.pop(0)
                    self.src_mac_window.pop(0)
                    self.proto_window.pop(0)

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

            # Cai flow cho TAT CA IP de flow stats ghi nhan traffic chinh xac.
            # Them ip_proto vao match de detector.py doc duoc icmp_pct/syn_pct/udp_pct
            # TAT CA flows deu permanent (idle_timeout=0) de pingall luon nhanh sau attack
            proto_num = p_ip.proto  # 1=ICMP, 6=TCP, 17=UDP
            if proto_num == 6:
                p_tcp = pkt.get_protocol(tcp.tcp)
                if p_tcp:
                    match = parser.OFPMatch(eth_type=0x0800, ipv4_src=p_ip.src, ipv4_dst=p_ip.dst, ip_proto=proto_num, tcp_dst=p_tcp.dst_port)
                else:
                    match = parser.OFPMatch(eth_type=0x0800, ipv4_src=p_ip.src, ipv4_dst=p_ip.dst, ip_proto=proto_num)
            elif proto_num == 17:
                p_udp = pkt.get_protocol(udp.udp)
                if p_udp:
                    match = parser.OFPMatch(eth_type=0x0800, ipv4_src=p_ip.src, ipv4_dst=p_ip.dst, ip_proto=proto_num, udp_dst=p_udp.dst_port)
                else:
                    match = parser.OFPMatch(eth_type=0x0800, ipv4_src=p_ip.src, ipv4_dst=p_ip.dst, ip_proto=proto_num)
            else:
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=p_ip.src, ipv4_dst=p_ip.dst, ip_proto=proto_num)
            self.add_flow(dp, 5, match, actions, idle_timeout=0)

            dp.send_msg(parser.OFPPacketOut(
                datapath=dp, buffer_id=msg.buffer_id,
                in_port=in_port, actions=actions, data=msg.data))

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, **kwargs):
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match,
            instructions=inst, idle_timeout=idle_timeout))

    def _check_spoof_flood(self, dp, victim_ip):
        """Kiem tra spoof flood tu packet_in rate. Goi moi _SPOOF_WINDOW giay."""
        if self._pktin_count < self._SPOOF_PKT_THRESHOLD:
            return
        if len(self._pktin_unique_ips) < self._SPOOF_IP_THRESHOLD:
            return

        unique_ratio = len(self._pktin_unique_ips) / self._pktin_count
        if unique_ratio < self._SPOOF_IP_RATIO:
            return

        # --- SPOOF FLOOD DETECTED ---
        top_mac, top_count = self._pktin_mac_counter.most_common(1)[0]

        # Tinh entropy thuc te tu cac IP trong window
        ip_counts = Counter(list(self._pktin_unique_ips))
        total_ips = len(self._pktin_unique_ips)
        if total_ips > 1:
            spoof_entropy = -sum((1/total_ips) * math.log2(1/total_ips) for _ in ip_counts)
        else:
            spoof_entropy = 0.0
        self.last_entropy = round(spoof_entropy, 4)
        self.attack_status = 2
        self._spoof_victim_ip = victim_ip

        # Phan loai attack type dua tren protocol va port
        top_proto = self._pktin_proto_counter.most_common(1)
        top_dport = self._pktin_dport_counter.most_common(1)
        dominant_proto = top_proto[0][0] if top_proto else 6  # Default TCP
        dominant_port = top_dport[0][0] if top_dport else 80

        if dominant_proto == 17 and dominant_port == 53:
            attack_name = "s05_dns_ampl"
            attack_label = "DNS AMPLIFICATION"
        elif dominant_proto == 17:
            attack_name = "s02_udp_flood"
            attack_label = "UDP FLOOD (spoofed)"
        elif dominant_proto == 1:
            attack_name = "s03_icmp_flood"
            attack_label = "ICMP FLOOD (spoofed)"
        else:
            attack_name = "s06_ip_spoof"
            attack_label = "IP SPOOF FLOOD"

        if top_mac in self._spoof_blocked_macs:
            return  # Da block roi

        self._spoof_blocked_macs.add(top_mac)
        self.logger.warning(
            "[DETECT] === PHAT HIEN %s ===", attack_label)
        self.logger.warning(
            "[DETECT] %d unique IPs, %d pkts trong %ds, entropy=%.2f",
            len(self._pktin_unique_ips), self._pktin_count,
            self._SPOOF_WINDOW, spoof_entropy)
        self.logger.warning(
            "[DETECT] Proto=%s, Port=%s, Attacker MAC: %s, Victim: %s",
            {6:'TCP',17:'UDP',1:'ICMP'}.get(dominant_proto, str(dominant_proto)),
            dominant_port, top_mac, victim_ip)
        self.logger.warning(
            "[DETECT] >> BLOCK MAC %s trong 20s", top_mac)

        # Block MAC tren switch s2 (truc tiep, tranh conflict voi override cua L3RouterExtended)
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_src=top_mac)
        mod = parser.OFPFlowMod(datapath=dp, priority=100,
                                match=match, instructions=[],
                                hard_timeout=20)
        dp.send_msg(mod)
        self.blocked_macs.add(top_mac)

        # Ghi alert vao file cho dashboard
        self._write_spoof_alert(top_mac, victim_ip, spoof_entropy, attack_name)

        # Tu dong go block sau 20s
        def _unblock_spoof():
            hub.sleep(20)
            self._spoof_blocked_macs.discard(top_mac)
            self.blocked_macs.discard(top_mac)
            self.attack_status = 0
            self._spoof_victim_ip = None
            self.logger.info("[SPOOF] Da go block MAC %s sau 20s", top_mac)
        hub.spawn(_unblock_spoof)

    def _write_spoof_alert(self, mac, victim_ip, entropy, attack_name='s06_ip_spoof'):
        """Ghi 3 cap alert (Log, Rate-Limit, Block) vao alerts.json."""
        alerts_file = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   '..', 'results', 'raw', 'alerts.json')
        os.makedirs(os.path.dirname(alerts_file), exist_ok=True)

        # Tim IP tuong ung voi MAC
        src_ip = None
        for ip, m in self.arp_table.items():
            if m == mac:
                src_ip = ip
                break
        if not src_ip:
            src_ip = f"spoof_mac_{mac}"

        now = time.time()
        levels = [
            {"severity": "INFO",     "action": "Logged",       "n_rules": 1},
            {"severity": "WARN",     "action": "Rate-Limited", "n_rules": 2},
            {"severity": "CRITICAL", "action": "Blocked",      "n_rules": 3},
        ]
        with open(alerts_file, 'a') as f:
            for lvl in levels:
                alert = {
                    "timestamp": now,
                    "src_ip": src_ip,
                    "attack": attack_name,
                    "severity": lvl["severity"],
                    "n_rules": lvl["n_rules"],
                    "action": lvl["action"],
                    "evidence": [{
                        "source": "packet_in_spoof_detect",
                        "mac": mac,
                        "victim": victim_ip,
                        "entropy": entropy,
                        "unique_ips": len(self._pktin_unique_ips),
                        "pkts": self._pktin_count
                    }]
                }
                f.write(json.dumps(alert) + "\n")
                now += 1  # Tang timestamp 1s cho moi cap

        self.logger.warning("[DETECT] Da ghi 3 cap alert (%s) vao alerts.json", attack_name)

        # Gui alert toi Ryu REST API (cho l3_router_extended xu ly)
        try:
            import requests
            for lvl in levels:
                requests.post('http://127.0.0.1:8081/api/alert', json={
                    "src_ip": src_ip,
                    "attack": attack_name,
                    "severity": lvl["severity"],
                    "action": lvl["action"],
                    "mac": mac
                }, timeout=1)
        except Exception:
            pass  # Controller co the dang ban, da block bang flow roi

    def _send_arp(self, dp, port, eth_dst, opcode, s_mac, s_ip, d_mac, d_ip):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=0x0806, dst=eth_dst, src=self.mac))
        pkt.add_protocol(arp.arp(opcode=opcode, src_mac=s_mac, src_ip=s_ip, dst_mac=d_mac, dst_ip=d_ip))
        pkt.serialize()
        dp.send_msg(dp.ofproto_parser.OFPPacketOut(
            datapath=dp, buffer_id=dp.ofproto.OFP_NO_BUFFER,
            in_port=dp.ofproto.OFPP_CONTROLLER,
            actions=[dp.ofproto_parser.OFPActionOutput(port)], data=pkt.data))
