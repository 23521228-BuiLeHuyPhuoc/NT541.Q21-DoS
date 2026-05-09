import json, time, requests, os
from collections import defaultdict

TV4_ENDPOINT = "http://127.0.0.1:8081/api/alert"
DEDUP_WINDOW = 5
LOG_PATH = "results/raw/alerts.json"

class AlertSystem:
    def __init__(self):
        self.last_seen = defaultdict(float)
        # Đảm bảo thư mục lưu log tồn tại
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

    def severity(self, n_rules):
        if n_rules == 0: return None
        if n_rules == 1: return "INFO"
        if n_rules == 2: return "WARN"
        return "CRITICAL"

    def emit(self, src_ip, attack, n_rules, evidence):
        key = (attack, src_ip)
        now = time.time()
        
        if now - self.last_seen[key] < DEDUP_WINDOW: return
        self.last_seen[key] = now
        
        payload = {
            "timestamp": now, 
            "src_ip": src_ip, 
            "attack": attack,
            "severity": self.severity(n_rules),
            "n_rules": n_rules, 
            "evidence": evidence
        }
        
        with open(LOG_PATH, 'a') as f:
            f.write(json.dumps(payload) + "\n")
            
        try: 
            requests.post(TV4_ENDPOINT, json=payload, timeout=1)
        except Exception as e: 
            print(f"[alert] TV4 unreachable: {e}")