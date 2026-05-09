"""Mitigation router — kế thừa SimpleRouterEntropy + REST + graduated response."""
from ryu.ofproto import ofproto_v1_3
from ryu.app.wsgi import WSGIApplication, ControllerBase, route
from code.l3_router_test import SimpleRouterEntropy
from code.mitigation import BlockModule, RateLimitModule, BlacklistManager
import json, yaml, time

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

    def _load_whitelist(self, path):
        try:
            return set(l.strip() for l in open(path) if l.strip()
                       and not l.startswith('#'))
        except FileNotFoundError:
            return set()

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
        for dp in self._datapaths.values():
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
        return req.create_response(body=b'{"ok":true}',
                                   content_type='application/json')

    @route('block', '/api/block', methods=['POST'])
    def manual_block(self, req, **kw):
        payload = json.loads(req.body)
        self.router.handle_alert({**payload, "attack": "manual"})
        return req.create_response(body=b'{"ok":true}')