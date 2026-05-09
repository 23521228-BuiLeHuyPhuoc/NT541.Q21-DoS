"""Placeholder cho các module Mitigation (Sẽ hoàn thiện ở Task 4.3, 4.4, 4.6)"""

class BlockModule:
    def __init__(self, app):
        self.app = app
    def apply(self, dp, src_ip, timeout=60):
        self.app.logger.warning(f"[DUMMY BLOCK] {src_ip} for {timeout}s")

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