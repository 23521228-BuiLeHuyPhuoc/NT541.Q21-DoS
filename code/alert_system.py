import json, time, requests, os
from collections import defaultdict

TV4_ENDPOINT = "http://127.0.0.1:8081/api/alert"
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(_BASE_DIR, '..', 'results', 'raw', 'alerts.json')

class AlertSystem:
    """
    He thong phat canh bao 3 cap:
    - Emit #1 -> LOG (INFO)
    - Emit #2 -> RATE-LIMIT (WARN)
    - Emit #3 -> BLOCK (CRITICAL)
    Khong dedup theo time window, de detector kiem soat so lan emit.
    """
    def __init__(self):
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

    def emit(self, src_ip, attack, n_rules, evidence, level=None):
        """
        Gui canh bao toi Ryu controller va ghi log.
        level: so thu tu (1=LOG, 2=RATE-LIMIT, 3=BLOCK) - neu None thi tu dong tinh tu n_rules
        """
        if level == 1:
            severity = "INFO"
            action = "Logged"
        elif level == 2:
            severity = "WARN"
            action = "Rate-Limited"
        else:
            severity = "CRITICAL"
            action = "Blocked"

        now = time.time()
        payload = {
            "timestamp": now,
            "src_ip": src_ip,
            "attack": attack,
            "severity": severity,
            "n_rules": n_rules,
            "action": action,
            "evidence": evidence
        }

        with open(LOG_PATH, 'a') as f:
            f.write(json.dumps(payload) + "\n")

        try:
            requests.post(TV4_ENDPOINT, json=payload, timeout=1)
        except Exception as e:
            print(f"[alert] Ryu unreachable: {e}")