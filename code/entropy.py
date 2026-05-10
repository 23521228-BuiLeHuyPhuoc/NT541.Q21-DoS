"""Shannon + Renyi entropy detector. Cite: A1 Kumar 2018, B4 Bhuyan 2015."""
import math, json
from collections import Counter, deque

def shannon(items):
    c = Counter(items); n = sum(c.values())
    return -sum((v/n)*math.log2(v/n) for v in c.values()) if n else 0

def renyi(items, q=2):
    c = Counter(items); n = sum(c.values())
    if n == 0: return 0
    s = sum((v/n)**q for v in c.values())
    return (1/(1-q)) * math.log2(s) if s > 0 else 0

class EntropyDetector:
    def __init__(self, baseline_path='datasets/baseline_stats.json',
                 k_sigma=3, adaptive_window_sec=300):
        b = json.load(open(baseline_path))
        self.mu = {k: v["mean"] for k,v in b.items()}
        self.sigma = {k: v["std"] for k,v in b.items()}
        self.k = k_sigma
        self.recent = deque(maxlen=adaptive_window_sec)

    def check(self, features):
        alerts =[]

        # Flash crowd check: CHI loai tru khi entropy cao + syn_pct thap + dst_port entropy cao
        # Spoof flood co entropy cao NHUNG syn_pct cao va dst_port entropy thap
        entropy_src = features.get('entropy_src_ip', 0)
        syn_pct = features.get('syn_pct', 0)
        dst_port_entropy = features.get('entropy_dst_port', 0)

        is_flash_crowd = (
            entropy_src > 4.0 and
            features.get('pps', 0) > self.mu.get('pps', 0) and
            syn_pct < 0.3 and          # Flash crowd: nhieu loai traffic, khong chi SYN
            dst_port_entropy > 2.0     # Flash crowd: nhieu port khac nhau
        )
        if is_flash_crowd:
            return {"anomaly": False, "alerts":[], "reason": "flash_crowd_pattern"}

        # Spoof detection: entropy cao + syn_pct cao = spoof flood
        if entropy_src > 3.5 and syn_pct > 0.5:
            alerts.append({"source": "entropy", "feature": "entropy_src_ip",
                           "value": entropy_src, "deviation": 99.0,
                           "reason": "spoof_high_entropy_high_syn"})

        for key in ('entropy_src_ip', 'entropy_dst_port', 'entropy_renyi_src'):
            v = features.get(key, 0)
            mu_key = 'entropy_dport' if 'dst_port' in key else 'entropy_src'
            
            mu, sig = self.mu.get(mu_key, 0), self.sigma.get(mu_key, 1)
            if abs(v - mu) > self.k * sig:
                alerts.append({"source": "entropy", "feature": key,
                               "value": v, "deviation": (v-mu)/sig})
        self.recent.append(features)
        return {"anomaly": len(alerts) > 0, "alerts": alerts}

    def update_baseline(self):
        """Goi moi 5' neu KHONG co alert -- adaptive baseline."""
        if len(self.recent) < 60: return
        import statistics
        for key in self.mu:
            vals = [f[key] for f in self.recent if key in f]
            if len(vals) > 10:
                self.mu[key] = statistics.mean(vals)
                self.sigma[key] = max(statistics.stdev(vals), 1e-6)