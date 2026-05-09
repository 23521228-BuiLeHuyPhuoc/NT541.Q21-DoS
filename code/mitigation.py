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
    """Meter Table OF1.3 — yêu cầu protocols='OpenFlow13'."""
    def __init__(self, app):
        self.app = app
        self.meter_ids = {}

    def apply(self, dp, src_ip, pps=1000):
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        
        # Băm IP ra một số ID duy nhất từ 1 đến 65535
        mid = abs(hash(src_ip)) & 0xffff
        self.meter_ids[src_ip] = mid
        
        # 1. Tạo một cái "Đồng hồ nước" (Meter) bóp tốc độ xuống mức pps
        band = parser.OFPMeterBandDrop(rate=pps, burst_size=pps//10)
        mmod = parser.OFPMeterMod(dp, command=ofp.OFPMC_ADD,
                                  flags=ofp.OFPMF_PKTPS,
                                  meter_id=mid, bands=[band])
        dp.send_msg(mmod)
        
        # 2. Tạo một luồng (Flow) điều hướng traffic của IP này chui qua cái Meter đó
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        inst = [parser.OFPInstructionMeter(meter_id=mid),
                parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    [parser.OFPActionOutput(ofp.OFPP_NORMAL)])]
                    
        fmod = parser.OFPFlowMod(datapath=dp, priority=80,
                                 match=match, instructions=inst,
                                 hard_timeout=120)
        dp.send_msg(fmod)
        self.app.logger.warning(f"[RATELIMIT] {src_ip} -> {pps} pps (meter={mid})")

class BlacklistManager:
    def __init__(self, app):
        self.app = app
    def add(self, src_ip, ttl=60):
        pass