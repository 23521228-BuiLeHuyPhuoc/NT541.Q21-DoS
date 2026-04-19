from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.lib import hub
from collections import Counter, deque
import math
import time

# === PROMETHEUS (Grafana) ===
try:
    from prometheus_client import start_http_server, Gauge
    from prometheus_client import Counter as PromCounter
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False


class SimpleRouterEntropy(simple_switch_13.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(SimpleRouterEntropy, self).__init__(*args, **kwargs)

        # ============================
        # CAU HINH MANG
        # ============================
        self.mac = '00:00:00:00:00:FE'
        self.arp_table = {}
        self.routes = {'10.0.1.': 1, '10.0.2.': 2, '10.0.3.': 3, '10.0.4.': 4}
        self.gateways = ['10.0.1.1', '10.0.2.1', '10.0.3.1', '10.0.4.1']
        self.dps = {}

        # ============================
        # WHITELIST - IP noi bo KHONG duoc block va KHONG thu thap entropy
        # ============================
        self.whitelist_ips = set(self.gateways) | {
            '10.0.2.10',   # h_web1 (Web Server)
            '10.0.2.11',   # h_dns1 (DNS Server)
            '10.0.3.10',   # h_db1  (Database)
            '10.0.3.11',   # h_app1 (App Server)
            '10.0.4.10',   # h_pc1
            '10.0.4.11',   # h_pc2
        }

        # ============================
        # ENTROPY - Phat hien DDoS
        # ============================
        self.WINDOW_SIZE = 1000
        self.src_ip_window = deque(maxlen=self.WINDOW_SIZE)  # Tu dong xoa phan tu cu
        self.blocked_ips = set()

        # Nguong Entropy (da calibrate)
        self.ENTROPY_HIGH = 5.5   # > 5.5 : Spoofed IP (qua nhieu IP la)
        self.ENTROPY_LOW  = 1.5   # < 1.5 : Botnet     (qua it IP lap lai)

        # ============================
        # THONG KE TAN CONG
        # ============================
        self.attack_count_botnet = 0
        self.attack_count_spoof  = 0
        self.total_blocked_ips   = 0

        # ============================
        # RATE LIMITING - Dem Packet-In / giay
        # ============================
        self.packet_in_count = 0
        self.last_rate_check = time.time()
        self.current_pps = 0.0
        self.PPS_THRESHOLD = 500   # Canh bao khi > 500 Packet-In/s

        # ============================
        # PORT STATS
        # ============================
        self.port_stats_prev = {}

        # ============================
        # PROMETHEUS METRICS (cho Grafana)
        # ============================
        if PROMETHEUS_AVAILABLE:
            self._init_prometheus()
        else:
            self.logger.warning(
                "[GRAFANA] prometheus_client chua cai! "
                "Chay: pip install prometheus_client"
            )

        # Khoi dong luong giam sat
        hub.spawn(self._monitor_entropy)
        hub.spawn(self._monitor_port_stats)

    # ==========================================================
    # KHOI TAO PROMETHEUS METRICS
    # ==========================================================
    def _init_prometheus(self):
        # --- Nhom 1: Entropy ---
        self.prom_entropy = Gauge(
            'sdn_entropy_value',
            'Shannon Entropy hien tai cua Source IP')
        self.prom_window_size = Gauge(
            'sdn_entropy_window_packets',
            'So goi tin trong cua so entropy')
        self.prom_unique_ips = Gauge(
            'sdn_entropy_unique_ips',
            'So IP duy nhat trong cua so')
        self.prom_entropy_high = Gauge(
            'sdn_entropy_threshold_high',
            'Nguong Entropy cao (Spoofed)')
        self.prom_entropy_low = Gauge(
            'sdn_entropy_threshold_low',
            'Nguong Entropy thap (Botnet)')
        self.prom_entropy_high.set(self.ENTROPY_HIGH)
        self.prom_entropy_low.set(self.ENTROPY_LOW)

        # --- Nhom 2: Tan cong ---
        self.prom_attack_botnet = PromCounter(
            'sdn_attack_botnet_total',
            'Tong cuoc tan cong Botnet')
        self.prom_attack_spoof = PromCounter(
            'sdn_attack_spoof_total',
            'Tong cuoc tan cong Spoofed IP')
        self.prom_blocked_ips = Gauge(
            'sdn_blocked_ips_current',
            'So IP dang bi block')
        self.prom_total_blocked = PromCounter(
            'sdn_blocked_ips_total',
            'Tong so IP da tung bi block')

        # --- Nhom 3: Luu luong ---
        self.prom_pps = Gauge(
            'sdn_packet_in_pps',
            'Packet-In moi giay (PPS)')
        self.prom_total_pkt_in = PromCounter(
            'sdn_packet_in_total',
            'Tong su kien Packet-In')

        # --- Nhom 4: Port Stats ---
        self.prom_port_rx_pps = Gauge(
            'sdn_port_rx_pps',
            'RX Packets/s', ['dpid', 'port'])
        self.prom_port_tx_pps = Gauge(
            'sdn_port_tx_pps',
            'TX Packets/s', ['dpid', 'port'])
        self.prom_port_rx_bytes = Gauge(
            'sdn_port_rx_bytes_total',
            'RX Bytes tong', ['dpid', 'port'])
        self.prom_port_tx_bytes = Gauge(
            'sdn_port_tx_bytes_total',
            'TX Bytes tong', ['dpid', 'port'])
        self.prom_port_rx_errors = Gauge(
            'sdn_port_rx_errors_total',
            'RX Errors', ['dpid', 'port'])
        self.prom_port_tx_errors = Gauge(
            'sdn_port_tx_errors_total',
            'TX Errors', ['dpid', 'port'])
        self.prom_port_rx_dropped = Gauge(
            'sdn_port_rx_dropped_total',
            'RX Dropped', ['dpid', 'port'])
        self.prom_port_tx_dropped = Gauge(
            'sdn_port_tx_dropped_total',
            'TX Dropped', ['dpid', 'port'])

        # --- Nhom 5: Trang thai ---
        self.prom_status = Gauge(
            'sdn_system_status',
            '0=Normal, 1=Botnet, 2=Spoofed')
        self.prom_status.set(0)

        # Khoi dong HTTP server Prometheus tren port 9100
        start_http_server(9100)
        self.logger.info(
            "[GRAFANA] Prometheus metrics: http://0.0.0.0:9100/metrics"
        )

    # ==========================================================
    # THEO DOI SWITCH KET NOI / NGAT KET NOI
    # ==========================================================
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.dps[dp.id] = dp
        elif dp.id in self.dps:
            del self.dps[dp.id]

    # ==========================================================
    # 1. GIAM SAT ENTROPY + RATE LIMITING  (moi 3 giay)
    # ==========================================================
    def _monitor_entropy(self):
        while True:
            hub.sleep(3)

            # --- Tinh PPS (Packet-In / giay) ---
            now = time.time()
            elapsed = now - self.last_rate_check
            if elapsed > 0:
                self.current_pps = self.packet_in_count / elapsed
            self.packet_in_count = 0
            self.last_rate_check = now

            # Cap nhat Prometheus PPS
            if PROMETHEUS_AVAILABLE:
                self.prom_pps.set(self.current_pps)

            # Canh bao neu PPS vuot nguong
            if self.current_pps > self.PPS_THRESHOLD:
                self.logger.warning(
                    "[!] CANH BAO: Packet-In PPS = %.1f (vuot nguong %d)",
                    self.current_pps, self.PPS_THRESHOLD
                )

            # --- Tinh Entropy ---
            window_len = len(self.src_ip_window)
            if window_len < 100:
                # Log trang thai cho qua (chua du mau)
                self.logger.info(
                    "[ENTROPY] Chua du mau: %d/100 | PPS=%.1f",
                    window_len, self.current_pps
                )
                if PROMETHEUS_AVAILABLE:
                    self.prom_window_size.set(window_len)
                continue

            # Dem IP
            ip_counts = Counter(self.src_ip_window)
            total_packets = window_len
            unique_ips = len(ip_counts)

            # Shannon Entropy: H = -sum(p * log2(p))
            entropy = 0.0
            for count in ip_counts.values():
                p = count / total_packets
                entropy -= p * math.log2(p)

            # Cap nhat Prometheus
            if PROMETHEUS_AVAILABLE:
                self.prom_entropy.set(entropy)
                self.prom_window_size.set(total_packets)
                self.prom_unique_ips.set(unique_ips)
                self.prom_blocked_ips.set(len(self.blocked_ips))

            # ---------------------------------------------------
            # KICH BAN 1: BOTNET (LOW ENTROPY) - IP co dinh
            # ---------------------------------------------------
            if entropy < self.ENTROPY_LOW:
                self.attack_count_botnet += 1
                if PROMETHEUS_AVAILABLE:
                    self.prom_attack_botnet.inc()
                    self.prom_status.set(1)

                self.logger.warning(
                    "\n" + "="*60 +
                    "\n[!] PHAT HIEN DDoS BOTNET (LOW ENTROPY)"
                    "\n    Entropy  = %.4f  (nguong < %.1f)"
                    "\n    Unique IP= %d | Tong goi= %d"
                    "\n    Cuoc tan cong Botnet thu: %d"
                    "\n" + "="*60,
                    entropy, self.ENTROPY_LOW,
                    unique_ips, total_packets,
                    self.attack_count_botnet
                )

                # Tim thu pham: IP chiem > 20% luu luong
                for ip, count in ip_counts.most_common():
                    ratio = count / total_packets
                    if ratio <= 0.20:
                        break
                    if ip in self.blocked_ips:
                        continue
                    if ip in self.whitelist_ips:
                        self.logger.info(
                            "  => Bo qua %s (Whitelist)", ip)
                        continue

                    self.logger.warning(
                        "  => BLOCK %s (%d goi, %.1f%%) trong 60s",
                        ip, count, ratio * 100
                    )
                    self._block_ip(ip)

                self.src_ip_window.clear()

            # ---------------------------------------------------
            # KICH BAN 2: SPOOFED IP (HIGH ENTROPY) - IP gia mao
            # ---------------------------------------------------
            elif entropy > self.ENTROPY_HIGH:
                self.attack_count_spoof += 1
                if PROMETHEUS_AVAILABLE:
                    self.prom_attack_spoof.inc()
                    self.prom_status.set(2)

                self.logger.warning(
                    "\n" + "="*60 +
                    "\n[!] PHAT HIEN DDoS SPOOFED IP (HIGH ENTROPY)"
                    "\n    Entropy  = %.4f  (nguong > %.1f)"
                    "\n    Unique IP= %d | Tong goi= %d"
                    "\n    Cuoc tan cong Spoof thu: %d"
                    "\n    => DROP ALL Packet-In 10 giay!"
                    "\n" + "="*60,
                    entropy, self.ENTROPY_HIGH,
                    unique_ips, total_packets,
                    self.attack_count_spoof
                )

                # Cai luat DROP toan bo IPv4 moi tren tat ca switch
                for dp in self.dps.values():
                    parser = dp.ofproto_parser
                    match = parser.OFPMatch(eth_type=0x0800)
                    inst = [parser.OFPInstructionActions(
                        dp.ofproto.OFPIT_APPLY_ACTIONS, [])]
                    mod = parser.OFPFlowMod(
                        datapath=dp, priority=50,
                        match=match, instructions=inst,
                        hard_timeout=10
                    )
                    dp.send_msg(mod)

                self.src_ip_window.clear()

                # Tu dong reset trang thai sau 10s
                def _reset_spoof_status():
                    hub.sleep(11)
                    if PROMETHEUS_AVAILABLE:
                        self.prom_status.set(0)
                    self.logger.info("[INFO] Het thoi gian DROP ALL. He thong binh thuong.")
                hub.spawn(_reset_spoof_status)

            # ---------------------------------------------------
            # BINH THUONG
            # ---------------------------------------------------
            else:
                if PROMETHEUS_AVAILABLE:
                    self.prom_status.set(0)
                self.logger.info(
                    "[ENTROPY] NORMAL | H=%.4f | Unique=%d | "
                    "Window=%d | PPS=%.1f | Blocked=%d",
                    entropy, unique_ips, total_packets,
                    self.current_pps, len(self.blocked_ips)
                )

    # ==========================================================
    # 2. GIAM SAT PORT STATS  (moi 5 giay)
    # ==========================================================
    def _monitor_port_stats(self):
        while True:
            hub.sleep(5)
            for dp in self.dps.values():
                parser = dp.ofproto_parser
                req = parser.OFPPortStatsRequest(
                    dp, 0, dp.ofproto.OFPP_ANY)
                dp.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        now = time.time()

        for stat in ev.msg.body:
            port_no = stat.port_no
            if port_no >= 0xFFFFFF00:  # Bo qua port dac biet (LOCAL, v.v.)
                continue

            key = (dpid, port_no)
            dpid_s = str(dpid)
            port_s = str(port_no)

            # Tinh PPS neu co du lieu truoc do
            if key in self.port_stats_prev:
                prev = self.port_stats_prev[key]
                dt = now - prev['time']
                if dt > 0:
                    rx_pps = (stat.rx_packets - prev['rx_packets']) / dt
                    tx_pps = (stat.tx_packets - prev['tx_packets']) / dt

                    if PROMETHEUS_AVAILABLE:
                        self.prom_port_rx_pps.labels(
                            dpid=dpid_s, port=port_s).set(rx_pps)
                        self.prom_port_tx_pps.labels(
                            dpid=dpid_s, port=port_s).set(tx_pps)

            # Cap nhat gia tri tuyet doi
            if PROMETHEUS_AVAILABLE:
                self.prom_port_rx_bytes.labels(
                    dpid=dpid_s, port=port_s).set(stat.rx_bytes)
                self.prom_port_tx_bytes.labels(
                    dpid=dpid_s, port=port_s).set(stat.tx_bytes)
                self.prom_port_rx_errors.labels(
                    dpid=dpid_s, port=port_s).set(stat.rx_errors)
                self.prom_port_tx_errors.labels(
                    dpid=dpid_s, port=port_s).set(stat.tx_errors)
                self.prom_port_rx_dropped.labels(
                    dpid=dpid_s, port=port_s).set(stat.rx_dropped)
                self.prom_port_tx_dropped.labels(
                    dpid=dpid_s, port=port_s).set(stat.tx_dropped)

            # Luu cho lan tinh tiep
            self.port_stats_prev[key] = {
                'rx_packets': stat.rx_packets,
                'tx_packets': stat.tx_packets,
                'time': now,
            }

    # ==========================================================
    # 3. BLOCK / UNBLOCK IP  (Botnet mitigation)
    # ==========================================================
    def _block_ip(self, bad_ip):
        self.blocked_ips.add(bad_ip)
        self.total_blocked_ips += 1

        if PROMETHEUS_AVAILABLE:
            self.prom_total_blocked.inc()
            self.prom_blocked_ips.set(len(self.blocked_ips))

        for dp in self.dps.values():
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=bad_ip)
            inst = [parser.OFPInstructionActions(
                dp.ofproto.OFPIT_APPLY_ACTIONS, [])]
            mod = parser.OFPFlowMod(
                datapath=dp, priority=100,
                match=match, instructions=inst,
                hard_timeout=60
            )
            dp.send_msg(mod)

        # Tu dong mo khoa sau 60 giay
        def _unblock():
            hub.sleep(61)
            if bad_ip in self.blocked_ips:
                self.blocked_ips.remove(bad_ip)
                if PROMETHEUS_AVAILABLE:
                    self.prom_blocked_ips.set(len(self.blocked_ips))
                self.logger.info("[INFO] Mo block IP: %s", bad_ip)
        hub.spawn(_unblock)

    # ==========================================================
    # 4. XU LY GOI TIN  (PACKET-IN)
    # ==========================================================
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        p_eth = pkt.get_protocol(ethernet.ethernet)
        if p_eth.ethertype == 0x88CC:
            return  # Bo qua LLDP

        # Dem Packet-In cho Rate Limiting
        self.packet_in_count += 1
        if PROMETHEUS_AVAILABLE:
            self.prom_total_pkt_in.inc()

        # Switch KHONG phai core router => xu ly L2 binh thuong
        if dp.id != 2:
            return super(SimpleRouterEntropy, self)._packet_in_handler(ev)

        p_arp = pkt.get_protocol(arp.arp)
        p_ip = pkt.get_protocol(ipv4.ipv4)

        # --- XU LY ARP ---
        if p_arp:
            self.arp_table[p_arp.src_ip] = p_arp.src_mac
            if (p_arp.opcode == arp.ARP_REQUEST and
                    p_arp.dst_ip in self.gateways):
                self._send_arp(
                    dp, in_port, p_eth.src,
                    arp.ARP_REPLY, self.mac, p_arp.dst_ip,
                    p_arp.src_mac, p_arp.src_ip
                )
            return

        # --- XU LY IPv4 ---
        if p_ip:
            # Thu thap IP nguon (chi thu thap IP KHONG nam trong whitelist)
            if p_ip.src not in self.whitelist_ips:
                self.src_ip_window.append(p_ip.src)

            # Tim port dau ra
            out_port = None
            for net, port in self.routes.items():
                if p_ip.dst.startswith(net):
                    out_port = port
                    break

            if not out_port:
                return  # Khong co route => DROP

            # Neu chua biet MAC dich => gui ARP Request
            if p_ip.dst not in self.arp_table:
                self._send_arp(
                    dp, out_port, 'ff:ff:ff:ff:ff:ff',
                    arp.ARP_REQUEST, self.mac, '0.0.0.0',
                    '00:00:00:00:00:00', p_ip.dst
                )
                return

            parser = dp.ofproto_parser
            actions = [
                parser.OFPActionSetField(eth_src=self.mac),
                parser.OFPActionSetField(
                    eth_dst=self.arp_table[p_ip.dst]),
                parser.OFPActionOutput(out_port),
            ]

            # Match theo ca src va dst de phan biet tung luong
            match = parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=p_ip.src,
                ipv4_dst=p_ip.dst
            )
            self.add_flow(dp, 10, match, actions, idle_timeout=5)

            out = parser.OFPPacketOut(
                datapath=dp, buffer_id=msg.buffer_id,
                in_port=in_port, actions=actions,
                data=msg.data
            )
            dp.send_msg(out)

    # ==========================================================
    # 5. HELPER: Add Flow
    # ==========================================================
    def add_flow(self, datapath, priority, match, actions,
                 idle_timeout=0):
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(
            datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority,
            match=match, instructions=inst,
            idle_timeout=idle_timeout
        )
        datapath.send_msg(mod)

    # ==========================================================
    # 6. HELPER: Gui goi ARP
    # ==========================================================
    def _send_arp(self, dp, port, eth_dst, opcode,
                  s_mac, s_ip, d_mac, d_ip):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            ethertype=0x0806, dst=eth_dst, src=self.mac))
        pkt.add_protocol(arp.arp(
            opcode=opcode, src_mac=s_mac, src_ip=s_ip,
            dst_mac=d_mac, dst_ip=d_ip))
        pkt.serialize()

        out = dp.ofproto_parser.OFPPacketOut(
            datapath=dp,
            buffer_id=dp.ofproto.OFP_NO_BUFFER,
            in_port=dp.ofproto.OFPP_CONTROLLER,
            actions=[dp.ofproto_parser.OFPActionOutput(port)],
            data=pkt.data
        )
        dp.send_msg(out)