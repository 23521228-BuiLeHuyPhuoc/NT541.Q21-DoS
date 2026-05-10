"""Mitigation router -- ke thua SimpleRouterEntropy + REST + graduated response."""
import json
import yaml
import time
import logging

# Tat log packet_in cua simple_switch_13 de tranh rac log lam treo Ryu
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

    # Khong override _packet_in_handler -- de class cha (SimpleRouterEntropy) xu ly.
    # Class cha chi cai flow cho whitelist IP, non-whitelist luon di qua controller
    # -> entropy window duoc cap nhat lien tuc khi bi tan cong.

    def handle_alert(self, payload):
        src = payload.get('src_ip')
        if not src: return
        
        if src in self.WHITELIST_SRC:
            return
            
        if time.time() - self.last_violation.get(src, 0) > 60:
            self.violation_count[src] = 0
            
        self.violation_count[src] = self.violation_count.get(src, 0) + 1
        self.last_violation[src] = time.time()
        
        n = self.violation_count[src]
        attack = payload.get('attack', 'unknown')
        
        for dp in self.dps.values():
            if n == 1:
                self.logger.warning(f"[ALERT] {src} attack={attack}")
                self._log_alert(src, attack, "INFO", "Logged")
            elif n == 2:
                self.ratelimit.apply(dp, src, pps=1000)
                self._log_alert(src, attack, "WARN", "Rate-Limited")
            else:
                self.block.apply(dp, src, timeout=60)
                self.blacklist.add(src, ttl=60)
                self._log_alert(src, attack, "CRITICAL", "Blocked")

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
        """Expose entropy real-time cho dashboard -- cung gia tri voi Ryu log."""
        body = json.dumps({
            "entropy": round(self.router.last_entropy, 4),
            "window_size": len(self.router.src_ip_window),
            "unique_ips": len(set(self.router.src_ip_window)),
            "attack_status": self.router.attack_status,
            "blocked_ips": list(self.router.blocked_ips),
            "packet_rate": self.router.packet_rate
        })
        return Response(content_type='application/json', body=body.encode())