"""Mitigation router -- ke thua SimpleRouterEntropy + REST + graduated response."""
import json
import yaml
import time
import logging

# Tat log rac de console sach khi demo
logging.getLogger('ryu.app.simple_switch_13').setLevel(logging.WARNING)
logging.getLogger('ryu.app.ofctl_rest').setLevel(logging.WARNING)
logging.getLogger('eventlet.wsgi.server').setLevel(logging.WARNING)
logging.getLogger('ryu.lib.hub').setLevel(logging.WARNING)
logging.getLogger('SimpleSwitch13').setLevel(logging.WARNING)
logging.getLogger('wsgi').setLevel(logging.WARNING)

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
        self._startup_time = time.time()
        self._GRACE_PERIOD = 15
        self._grace_logged = False

        self.logger.info("[RYU] Controller san sang. Cho %ds de flow table on dinh...", self._GRACE_PERIOD)

        from ryu.lib import hub
        hub.spawn(self._notify_grace_end)

    def _notify_grace_end(self):
        from ryu.lib import hub
        hub.sleep(self._GRACE_PERIOD)
        self.logger.info("[RYU] He thong san sang phat hien tan cong.")

    def _load_whitelist(self, path):
        try:
            return set(l.strip() for l in open(path) if l.strip() and not l.startswith('#'))
        except FileNotFoundError:
            return set()

    # Khong override _packet_in_handler -- de class cha (SimpleRouterEntropy) xu ly.

    def handle_alert(self, payload):
        src = payload.get('src_ip')
        if not src: return

        # Da bi block roi -> bo qua hoan toan
        if self.blacklist.is_blocked(src):
            return

        # Grace period
        elapsed = time.time() - self._startup_time
        if elapsed < self._GRACE_PERIOD:
            return

        if src in self.WHITELIST_SRC:
            return

        attack = payload.get('attack', 'unknown')
        action = payload.get('action', 'Logged')
        is_spoof = 'spoof' in attack.lower()

        # Chi thao tac tren switch s2 (dpid=2) — switch phat hien
        # Khong can block tren tat ca switch, tranh anh huong L2 flows
        dp = self.dps.get(2)
        if not dp:
            self.logger.error("[MITIGATION] Switch s2 chua ket noi!")
            return

        if action == 'Logged':
            self.logger.warning(f"[MITIGATION] Cap 1/3: GHI NHAN — {src} ({attack})")
            self.attack_status = 2 if is_spoof else 1

        elif action == 'Rate-Limited':
            self.logger.warning(f"[MITIGATION] Cap 2/3: RATE-LIMIT — {src} (1000 pps)")
            self.ratelimit.apply(dp, src, pps=1000)
            self.attack_status = 2 if is_spoof else 1

        else:  # Blocked
            if is_spoof:
                src_mac = self._find_mac_for_ip(src)
                if src_mac:
                    self.logger.warning(f"[MITIGATION] Cap 3/3: BLOCK MAC — {src_mac} ({attack}, 20s)")
                    self._block_mac(dp, src_mac, timeout=20)
                    self.blocked_macs.add(src_mac)
                else:
                    self.logger.warning(f"[MITIGATION] Cap 3/3: BLOCK IP — {src} ({attack}, 20s)")
                    self.block.apply(dp, src, timeout=20)
            else:
                self.logger.warning(f"[MITIGATION] Cap 3/3: CHAN IP — {src} ({attack}, 20s)")
                self.block.apply(dp, src, timeout=20)

            self.blocked_ips.add(src)
            self.blacklist.add(src, ttl=20)
            self.attack_status = 2 if is_spoof else 1

            # Tu dong go chan va reset trang thai sau 20s
            from ryu.lib import hub
            def _auto_unblock():
                hub.sleep(20)
                self.blocked_ips.discard(src)
                if is_spoof and src_mac:
                    self.blocked_macs.discard(src_mac)
                if not self.blocked_ips and not self.blocked_macs:
                    self.attack_status = 0
                self.logger.info(f"[MITIGATION] Da go chan {src} sau 20s")
            hub.spawn(_auto_unblock)

    def _find_mac_for_ip(self, ip):
        """Tim MAC address tuong ung voi IP tu ARP table."""
        return self.arp_table.get(ip)

    def _block_mac(self, dp, mac, timeout=20):
        """Cai flow drop theo MAC address — dung cho spoof attack."""
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_src=mac)
        inst = []
        mod = parser.OFPFlowMod(datapath=dp, priority=100,
                                match=match, instructions=inst,
                                hard_timeout=timeout)
        dp.send_msg(mod)

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
        """Expose entropy real-time cho dashboard — doc tu detector.py output, fallback tu controller."""
        import os
        features_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     '..', 'results', 'raw', 'current_features.json')
        entropy_val = 0.0
        pps = 0
        unique_ips = 0

        # Khi spoof detected -> LUON dung entropy tu controller (file khong dang tin cay)
        if self.router.attack_status == 2 and self.router.last_entropy > 0:
            entropy_val = self.router.last_entropy
            unique_ips = len(self.router._pktin_unique_ips) if self.router._pktin_unique_ips else self.router._pktin_count
            pps = self.router.total_pps if self.router.total_pps > 0 else self.router._pktin_count
        else:
            # Binh thuong: doc tu file detector.py
            try:
                mtime = os.path.getmtime(features_path)
                if time.time() - mtime < 5:
                    with open(features_path) as f:
                        features = json.load(f)
                    entropy_val = features.get('entropy_realtime', 0.0)
                    pps = features.get('pps', 0)
                    unique_ips = features.get('unique_ips', 0)
                elif self.router.last_entropy > 0:
                    entropy_val = self.router.last_entropy
                    unique_ips = len(self.router.src_ip_window) if self.router.src_ip_window else 0
                    pps = self.router.total_pps
            except Exception:
                if self.router.last_entropy > 0:
                    entropy_val = self.router.last_entropy

        body = json.dumps({
            "entropy": round(entropy_val, 4),
            "window_size": unique_ips,
            "unique_ips": unique_ips,
            "attack_status": self.router.attack_status,
            "blocked_ips": list(self.router.blocked_ips),
            "blocked_macs": list(self.router.blocked_macs),
            "packet_rate": pps,
            "spoof_detected": self.router.attack_status == 2
        })
        return Response(content_type='application/json', body=body.encode())