"""Mitigation modules — Block + RateLimit + Blacklist."""
import time
import threading

class BlockModule:
    def __init__(self, app):
        self.app = app

    def apply(self, dp, src_ip, timeout=60):
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        
        # Danh sách hành động trống (empty = drop packet)
        inst = []  
        
        # Tạo luồng với mức ưu tiên cao (100) và tự động xóa sau 60s (hard_timeout)
        mod = parser.OFPFlowMod(datapath=dp, priority=100,
                                match=match, instructions=inst,
                                hard_timeout=timeout)
        dp.send_msg(mod)
        self.app.logger.warning(f"[BLOCK] {src_ip} for {timeout}s")


# --- GIỮ NGUYÊN PLACEHOLDER CHO CÁC TASK SAU ---
class RateLimitModule:
    def __init__(self, app):
        self.app = app
    def apply(self, dp, src_ip, pps=1000):
        self.app.logger.warning(f"[DUMMY RATELIMIT] {src_ip} -> {pps} pps")

class BlacklistManager:
    def __init__(self, app):
        self.app = app
    def add(self, src_ip, ttl=60):
        pass