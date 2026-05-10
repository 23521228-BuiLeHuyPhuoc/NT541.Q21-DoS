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

    def _send_arp(self, dp, port, eth_dst, opcode, s_mac, s_ip, d_mac, d_ip):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=0x0806, dst=eth_dst, src=self.mac))
        pkt.add_protocol(arp.arp(opcode=opcode, src_mac=s_mac, src_ip=s_ip, dst_mac=d_mac, dst_ip=d_ip))
        pkt.serialize()
        dp.send_msg(dp.ofproto_parser.OFPPacketOut(
            datapath=dp, buffer_id=dp.ofproto.OFP_NO_BUFFER,
            in_port=dp.ofproto.OFPP_CONTROLLER,
            actions=[dp.ofproto_parser.OFPActionOutput(port)], data=pkt.data))
