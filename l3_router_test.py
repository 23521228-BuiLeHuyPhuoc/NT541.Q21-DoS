from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.lib import hub
from collections import Counter
import math
import time

class SimpleRouterEntropy(simple_switch_13.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(SimpleRouterEntropy, self).__init__(*args, **kwargs)
        
        # --- CAU HINH MANG ---
        self.mac = '00:00:00:00:00:FE'
        self.arp_table = {}
        self.routes = {'10.0.1.': 1, '10.0.2.': 2, '10.0.3.': 3, '10.0.4.': 4}
        self.gateways = ['10.0.1.1', '10.0.2.1', '10.0.3.1', '10.0.4.1']
        self.dps = {}
        
        # --- BIEN THONG KE ENTROPY ---
        self.WINDOW_SIZE = 1000       # Kich thuoc cua so truot (luu 1000 IP gan nhat)
        self.src_ip_window = []       # Mang luu tru IP
        self.blocked_ips = set()      # Danh sach cac IP dang bi khoa
        
        # Nguong Entropy (Tuong doi, co the tinh chinh theo mang thuc te)
        self.ENTROPY_HIGH = 8.0       # > 8.0: Gia mao IP (Spoofed IP)
        self.ENTROPY_LOW = 1.5        # < 1.5: Botnet (Fixed IP)
        
        hub.spawn(self._monitor_entropy)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER: 
            self.dps[dp.id] = dp
        elif dp.id in self.dps: 
            del self.dps[dp.id]

    # ==========================================
    # 1. THUAT TOAN TINH ENTROPY & MITIGATION
    # ==========================================
    def _monitor_entropy(self):
        while True:
            hub.sleep(3) # Kiem tra moi 3 giay
            
            # Khong du mau thi bo qua de tranh bao dong gia
            if len(self.src_ip_window) < 100: 
                continue 
            
            # Dem so lan xuat hien cua tung IP trong cua so
            ip_counts = Counter(self.src_ip_window)
            total_packets = len(self.src_ip_window)
            
            # Tinh Shannon Entropy: H = - sum(p * log2(p))
            entropy = 0.0
            for count in ip_counts.values():
                probability = count / total_packets
                entropy -= probability * math.log2(probability)
            
            # KICH BAN 1: TAN CONG TU IP CO DINH (BOTNET)
            if entropy < self.ENTROPY_LOW:
                self.logger.warning("\n[!] PHAT HIEN DDoS BOTNET (LOW ENTROPY = %.2f)", entropy)
                
                # Khai bao danh sach cac Server quan trong khong duoc phep block
                whitelist_ips = ['10.0.2.10', '10.0.3.10', '10.0.2.11'] 
                
                # Tim thu pham: Cac IP chiem hon 20% luu luong
                for ip, count in ip_counts.items():
                    if (count / total_packets) > 0.20 and ip not in self.blocked_ips:
                        # Kiem tra neu IP nam trong Whitelist thi bo qua
                        if ip in whitelist_ips:
                            self.logger.info(" => Bo qua IP %s vi day la Server noi bo (Whitelist)!", ip)
                            continue
                            
                        self.logger.warning(" => Thu pham: %s (Giao %d goi tin). DROP TRONG 60 GIAY!", ip, count)
                        self._block_ip(ip)
                        
                # Xoa cua so de tinh lai tu dau
                self.src_ip_window.clear()
                
            # KICH BAN 2: TAN CONG GIA MAO IP (SPOOFED IP / RANDOM SOURCE)
            elif entropy > self.ENTROPY_HIGH:
                self.logger.warning("\n[!] PHAT HIEN DDoS SPOOFED IP (HIGH ENTROPY = %.2f)", entropy)
                self.logger.warning(" => Hang ngan IP gia mao dang tan cong. Kich hoat DROP ALL PACKET-IN trong 10 giay de bao ve he thong!")
                
                # MITIGATION CHO SPOOFED IP:
                # Cai mot luat Drop moi goi tin moi (chua biet MAC) de giam tai cho Controller
                for dp in self.dps.values():
                    parser = dp.ofproto_parser
                    match = parser.OFPMatch(eth_type=0x0800) # Match toan bo IPv4
                    inst = [parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, [])]
                    
                    # Cai luat uu tien 50 (Cao hon luat Routing binh thuong 10, thap hon luat Block IP 100)
                    mod = parser.OFPFlowMod(
                        datapath=dp, priority=50, match=match, instructions=inst,
                        hard_timeout=10 # Chi Drop mu trong 10 giay de giam tai
                    )
                    dp.send_msg(mod)
                
                # Xoa cua so de tinh lai tu dau
                self.src_ip_window.clear()

    # Ham chan 1 IP cu the (Dung cho kich ban Low Entropy)
    def _block_ip(self, bad_ip):
        self.blocked_ips.add(bad_ip)
        for dp in self.dps.values():
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=bad_ip)
            # Actions rong = DROP. Uu tien cao nhat (100)
            inst = [parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, [])]
            mod = parser.OFPFlowMod(
                datapath=dp, priority=100, match=match, instructions=inst,
                hard_timeout=60 # Block trong 60 giay
            )
            dp.send_msg(mod)
            
        # Ham phu de mo khoa IP sau 60s
        def unblock():
            hub.sleep(61)
            if bad_ip in self.blocked_ips:
                self.blocked_ips.remove(bad_ip)
                self.logger.info("[INFO] Da mo block cho IP: %s", bad_ip)
        hub.spawn(unblock)

    # ==========================================
    # 2. XU LY GOI TIN (PACKET IN) & THU THAP DATA
    # ==========================================
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        p_eth = pkt.get_protocol(ethernet.ethernet)
        if p_eth.ethertype == 0x88CC: return 

        if dp.id != 2:
            return super(SimpleRouterEntropy, self)._packet_in_handler(ev)

        p_arp = pkt.get_protocol(arp.arp)
        p_ip = pkt.get_protocol(ipv4.ipv4)

        if p_arp:
            self.arp_table[p_arp.src_ip] = p_arp.src_mac
            if p_arp.opcode == arp.ARP_REQUEST and p_arp.dst_ip in self.gateways:
                self._send_arp(dp, in_port, p_eth.src, arp.ARP_REPLY, self.mac, p_arp.dst_ip, p_arp.src_mac, p_arp.src_ip)
            return

        if p_ip:
            # --- THU THAP IP NGUON DE TINH ENTROPY ---
            # Khong thu thap IP cua chinh Server (10.0.2.10) hoac Gateway
            if p_ip.src not in self.gateways and p_ip.src != '10.0.2.10': 
                self.src_ip_window.append(p_ip.src)
                # Neu cua so vuot qua gioi han, xoa phan tu cu nhat
                if len(self.src_ip_window) > self.WINDOW_SIZE:
                    self.src_ip_window.pop(0)
            # -----------------------------------------

            out_port = None
            for net, port in self.routes.items():
                if p_ip.dst.startswith(net):
                    out_port = port
                    break
            
            # Neu khong co port dau ra, DROP luon de giam tai
            if not out_port: 
                return

            if p_ip.dst not in self.arp_table:
                self._send_arp(dp, out_port, 'ff:ff:ff:ff:ff:ff', arp.ARP_REQUEST, self.mac, '0.0.0.0', '00:00:00:00:00:00', p_ip.dst)
                return

            parser = dp.ofproto_parser
            actions = [
                parser.OFPActionSetField(eth_src=self.mac),
                parser.OFPActionSetField(eth_dst=self.arp_table[p_ip.dst]),
                parser.OFPActionOutput(out_port)
            ]
            
            # EP SWITCH PHAI PHAN BIET TUNG IP NGUON
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=p_ip.src, ipv4_dst=p_ip.dst)
            
            # Them idle_timeout=5 de luong duoc xoa khi ranh roi, 
            self.add_flow(dp, 10, match, actions, idle_timeout=5)
            
            out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
            dp.send_msg(out)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0):
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst, idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    # ==========================================
    # 3. HAM TAO VA GUI GOI ARP
    # ==========================================
    def _send_arp(self, dp, port, eth_dst, opcode, s_mac, s_ip, d_mac, d_ip):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=0x0806, dst=eth_dst, src=self.mac))
        pkt.add_protocol(arp.arp(opcode=opcode, src_mac=s_mac, src_ip=s_ip, dst_mac=d_mac, dst_ip=d_ip))
        pkt.serialize()
        
        out = dp.ofproto_parser.OFPPacketOut(
            datapath=dp, buffer_id=dp.ofproto.OFP_NO_BUFFER,
            in_port=dp.ofproto.OFPP_CONTROLLER,
            actions=[dp.ofproto_parser.OFPActionOutput(port)], data=pkt.data)
        dp.send_msg(out)
