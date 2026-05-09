"""Mitigation router — kế thừa SimpleRouterEntropy + REST + graduated response."""
import json
import yaml
import time

from ryu.ofproto import ofproto_v1_3
from ryu.app.wsgi import WSGIApplication, ControllerBase, route, Response
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.lib.packet import packet, ipv4  # THÊM IMPORT: Dùng để phân tích IP gói tin

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
        self.policy = yaml.safe_load(open('code/policy.yaml'))
        self.violation_count = {}
        self.last_violation = {}
        self.block = BlockModule(self)
        self.ratelimit = RateLimitModule(self)
        self.blacklist = BlacklistManager(self)
        
        self.datapaths = {}

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            if dp.id in self.datapaths:
                del self.datapaths[dp.id]

    def _load_whitelist(self, path):
        try:
            return set(l.strip() for l in open(path) if l.strip()
                       and not l.startswith('#'))
        except FileNotFoundError:
            return set()

    # =====================================================================
    # TASK 4.2c: FIX SELF-DOS (CHỐNG NGẬP LỤT CONTROLLER)
    # =====================================================================
    def _install_sample_flow(self, dp, src_ip):
        """Cài đặt flow tạm thời để chống Self-DoS (chỉ lấy mẫu 128 byte)."""
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        
        # Actions: Vừa chuyển tiếp bình thường (NORMAL), vừa gửi mẫu 128 byte lên Ryu
        actions = [parser.OFPActionOutput(ofp.OFPP_NORMAL),
                   parser.OFPActionOutput(ofp.OFPP_CONTROLLER, max_len=128)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        
        # Flow có hiệu lực 5 giây (idle_timeout=5)
        mod = parser.OFPFlowMod(datapath=dp, priority=10,
                                match=match, instructions=inst, idle_timeout=5)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Đón lỏng gói tin để cài Sample Flow trước khi xử lý phức tạp."""
        msg = ev.msg
        dp = msg.datapath
        pkt = packet.Packet(msg.data)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        if ipv4_pkt:
            src_ip = ipv4_pkt.src
            # Nếu IP lạ (không có trong whitelist), cài flow chặn ngập lụt 5s
            if src_ip not in self.WHITELIST_SRC:
                self._install_sample_flow(dp, src_ip)

        # Gọi lại hàm xử lý mặc định của SimpleRouterEntropy cũ (nếu có)
        if hasattr(super(), '_packet_in_handler'):
            super()._packet_in_handler(ev)
    # =====================================================================

    def handle_alert(self, payload):
        src = payload['src_ip']
        
        if src in self.WHITELIST_SRC:
            self.logger.info(f"[whitelist] skip {src}")
            return
            
        if time.time() - self.last_violation.get(src, 0) > 60:
            self.violation_count[src] = 0
            
        self.violation_count[src] = self.violation_count.get(src, 0) + 1
        self.last_violation[src] = time.time()
        
        n = self.violation_count[src]
        
        for dp in self.datapaths.values():
            if n == 1:
                self.logger.warning(f"[GR1 LOG] {src} attack={payload['attack']}")
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