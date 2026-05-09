"""Mitigation router — kế thừa SimpleRouterEntropy + REST + graduated response."""
import json
import yaml
import time

from ryu.ofproto import ofproto_v1_3
from ryu.app.wsgi import WSGIApplication, ControllerBase, route, Response
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER
from ryu.lib.packet import packet, ipv4

from l3_router_test import SimpleRouterEntropy
from mitigation import BlockModule, RateLimitModule, BlacklistManager

class L3RouterExtended(SimpleRouterEntropy):
    OFP_VERSIONS =[ofproto_v1_3.OFP_VERSION]
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
        
        # FIX BÃO FLOWMOD: Lưu vết thời gian cài Flow lấy mẫu
        self._last_sample_time = {}

    def _load_whitelist(self, path):
        try:
            return set(l.strip() for l in open(path) if l.strip() and not l.startswith('#'))
        except FileNotFoundError:
            return set()

    def _install_sample_flow(self, dp, src_ip):
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        actions =[parser.OFPActionOutput(ofp.OFPP_NORMAL),
                   parser.OFPActionOutput(ofp.OFPP_CONTROLLER, max_len=128)]
        inst =[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=10,
                                match=match, instructions=inst, idle_timeout=5)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        pkt = packet.Packet(msg.data)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        if ipv4_pkt:
            src_ip = ipv4_pkt.src
            if src_ip not in self.WHITELIST_SRC:
                now = time.time()
                # CHỈ GỬI LỆNH XUỐNG SWITCH NẾU ĐÃ QUA 5 GIÂY (Tránh Ryu bị ngập lụt)
                if now - self._last_sample_time.get(src_ip, 0) > 5:
                    self._install_sample_flow(dp, src_ip)
                    self._last_sample_time[src_ip] = now

        if hasattr(super(), '_packet_in_handler'):
            super()._packet_in_handler(ev)

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
        
        # Dùng self.dps của class cha để đảm bảo luôn lấy được Datapath
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

    @route('block', '/api/block', methods=['POST'])
    def manual_block(self, req, **kw):
        payload = json.loads(req.body)
        self.router.handle_alert({**payload, "attack": "manual"})
        return Response(content_type='application/json', body=b'{"ok":true}')