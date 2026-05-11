"""Mitigation modules — Block + RateLimit + Blacklist."""
import time
import threading

class BlockModule:
    def __init__(self, app):
        self.app = app

    def apply(self, dp, src_ip, timeout=60):
        parser = dp.ofproto_parser
        # Cai rieng cho tung giao thuc de detector van doc duoc ip_proto
        for proto in [1, 6, 17]:
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ip_proto=proto)
            mod = parser.OFPFlowMod(datapath=dp, priority=100,
                                    match=match, instructions=[],
                                    hard_timeout=timeout)
            dp.send_msg(mod)
            
        # Generic block cho cac loai protocol khac
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        mod = parser.OFPFlowMod(datapath=dp, priority=99,
                                match=match, instructions=[],
                                hard_timeout=timeout)
        dp.send_msg(mod)

class RateLimitModule:
    """Meter Table OF1.3 -- yeu cau protocols='OpenFlow13'."""
    def __init__(self, app):
        self.app = app
        self.meter_ids = {}

    def apply(self, dp, src_ip, pps=1000):
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        mid = abs(hash(src_ip)) & 0xffff
        self.meter_ids[src_ip] = mid
        band = parser.OFPMeterBandDrop(rate=pps, burst_size=pps//10)
        mmod = parser.OFPMeterMod(dp, command=ofp.OFPMC_ADD,
                                  flags=ofp.OFPMF_PKTPS,
                                  meter_id=mid, bands=[band])
        dp.send_msg(mmod)
        # Cai rieng cho tung giao thuc de giu ip_proto
        inst = [parser.OFPInstructionMeter(meter_id=mid),
                parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    [parser.OFPActionOutput(ofp.OFPP_NORMAL)])]
                    
        for proto in [1, 6, 17]:
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ip_proto=proto)
            fmod = parser.OFPFlowMod(datapath=dp, priority=80,
                                     match=match, instructions=inst,
                                     hard_timeout=120)
            dp.send_msg(fmod)
            
        # Generic rate-limit cho cac loai khac
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        fmod = parser.OFPFlowMod(datapath=dp, priority=79,
                                 match=match, instructions=inst,
                                 hard_timeout=120)
        dp.send_msg(fmod)

class BlacklistManager:
    """{src_ip: expire_ts} voi auto-release."""
    def __init__(self, app):
        self.app = app
        self.entries = {}
        self._stop = False
        threading.Thread(target=self._gc_loop, daemon=True).start()

    def add(self, src_ip, ttl=60):
        self.entries[src_ip] = time.time() + ttl

    def is_blocked(self, src_ip):
        exp = self.entries.get(src_ip)
        return exp is not None and exp > time.time()

    def _gc_loop(self):
        while not self._stop:
            now = time.time()
            expired = [ip for ip, exp in self.entries.items() if exp <= now]
            for ip in expired:
                del self.entries[ip]
                if self.app and hasattr(self.app, 'logger'):
                    self.app.logger.info(f"[blacklist] auto-release {ip}")
            time.sleep(3)