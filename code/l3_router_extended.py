"""Mitigation router — kế thừa SimpleRouterEntropy + REST + graduated response."""
import json
import yaml
import time
import logging

# Tắt log packet_in của simple_switch_13 để tránh rác log làm treo Ryu
logging.getLogger('ryu.app.simple_switch_13').setLevel(logging.WARNING)

from ryu.ofproto import ofproto_v1_3
from ryu.app.wsgi import WSGIApplication, ControllerBase, route, Response
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER
from ryu.lib.packet import packet, ethernet, ipv4

from l3_router_test import SimpleRouterEntropy
from mitigation import BlockModule, RateLimitModule, BlacklistManager

class L3RouterExtended(SimpleRouterEntropy):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(AlertAPI, {'router': self})
        self.WHITELIST_SRC = self._load_whitelist('code/whitelist.txt')
        try:
            self.policy = yaml.safe_load(open('code/policy.yaml'))
        except Exception:
            self.policy = {}
        self.violation_count = {}
        self.last_violation = {}
        self.block = BlockModule(self)
        self.ratelimit = RateLimitModule(self)
        self.blacklist = BlacklistManager(self)

    def _load_whitelist(self, path):
        try:
            return set(l.strip() for l in open(path) if l.strip() and not l.startswith('#'))
        except FileNotFoundError:
            return set()

    # FIX TẬN GỐC SELF-DOS: Cài flow xuống Switch thay vì đẩy hết gói tin lên Controller
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        
        # Gọi hàm của class cha để xử lý ARP và các logic cơ bản trước
        super()._packet_in_handler(ev)
        
        # Nếu là switch s2 (router L3) và là gói tin IP
        if dp.id == 2:
            pkt = packet.Packet(msg.data)
            p_ip = pkt.get_protocol(ipv4.ipv4)
            
            if p_ip and p_ip.dst in self.arp_table:
                # Tìm cổng đầu ra
                out_port = None
                for net, port in self.routes.items():
                    if p_ip.dst.startswith(net):
                        out_port = port
                        break
                        
                if out_port:
                    parser = dp.ofproto_parser
                    actions =[
                        parser.OFPActionSetField(eth_src=self.mac),
                        parser.OFPActionSetField(eth_dst=self.arp_table[p_ip.dst]),
                        parser.OFPActionOutput(out_port)
                    ]
                    match = parser.OFPMatch(eth_type=0x0800, ipv4_src=p_ip.src, ipv4_dst=p_ip.dst)
                    
                    # Cài flow: Whitelist thì lưu 30s, IP lạ (Attacker) thì lưu 5s
                    idle_timeout = 30 if p_ip.src in self.WHITELIST_SRC else 5
                    
                    inst =[parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    mod = parser.OFPFlowMod(datapath=dp, priority=10, match=match,
                                            instructions=inst, idle_timeout=idle_timeout)
                    dp.send_msg(mod)

    def handle_alert(self, payload):
        src = payload.get('src_ip')
        if not src: return
        
        if src in self.WHITELIST_SRC:
            self.logger.info(f"[whitelist] skip {src}")
            return
            
        if time.time() - self.last_violation.get(src, 0) > 60:
            self.violation_count[src] = 0
            
        self.violation_count[src] = self.violation_count.get(src, 0) + 1
        self.last_violation[src] = time.time()
        
        n = self.violation_count[src]
        
        for dp in self.dps.values():
            if n == 1:
                self.logger.warning(f"[GR1 LOG] {src} attack={payload.get('attack')}")
            elif n == 2:
                self.ratelimit.apply(dp, src, pps=1000)
            else:
                self.block.apply(dp, src, timeout=60)
                self.blacklist.add(src, ttl=60)

class AlertAPI(ControllerBase):
    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.router = data['router']

    @route('alert', '/api/alert', methods=['POST'])
    def receive_alert(self, req, **kw):
        payload = json.loads(req.body)
        self.router.handle_alert(payload)
        return Response(content_type='application/json', body=b'{"ok":true}')

    @route('entropy', '/api/entropy', methods=['GET'])
    def get_entropy(self, req, **kw):
        """Expose entropy real-time cho dashboard — cùng giá trị với Ryu log."""
        import math
        from collections import Counter
        window = self.router.src_ip_window
        window_size = len(window)
        unique_ips = len(set(window))
        entropy = 0.0
        if window_size >= 10:
            ip_counts = Counter(window)
            total = window_size
            entropy = -sum((c/total) * math.log2(c/total) for c in ip_counts.values())
        body = json.dumps({
            "entropy": round(entropy, 4),
            "window_size": window_size,
            "unique_ips": unique_ips,
            "attack_status": self.router.attack_status,
            "blocked_ips": list(self.router.blocked_ips)
        })
        return Response(content_type='application/json', body=body.encode())