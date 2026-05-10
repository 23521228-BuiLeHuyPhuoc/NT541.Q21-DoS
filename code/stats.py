"""Z-score + EWMA + CUSUM detector. Cite: E4 Page 1954."""
import json
from collections import deque

class StatsDetector:
    def __init__(self, baseline_path='datasets/baseline_stats.json',
                 alpha=0.3, k_factor=0.5, h_factor=5):
        b = json.load(open(baseline_path))
        self.mu = {k: v["mean"] for k,v in b.items()}
        self.sigma = {k: v["std"] for k,v in b.items()}
        self.alpha = alpha
        self.k_factor = k_factor
        self.h_factor = h_factor
        self.ewma = {k: v["mean"] for k,v in b.items()}
        self.cusum = {k: 0.0 for k in b}

    def zscore(self, key, x):
        mu, sig = self.mu[key], max(self.sigma[key], 1e-6)
        z = (x - mu) / sig
        return {"alert": abs(z) > 3, "score": z, "source": "zscore", "feature": key}

    def ewma_check(self, key, x):
        self.ewma[key] = self.alpha * x + (1-self.alpha) * self.ewma[key]
        dev = abs(x - self.ewma[key])
        return {"alert": dev > 3*self.sigma[key], "score": dev,
                "source": "ewma", "feature": key}

    def cusum_check(self, key, x):
        mu, sig = self.mu[key], max(self.sigma[key], 1e-6)
        k = self.k_factor * sig
        h = self.h_factor * sig
        self.cusum[key] = max(0, self.cusum[key] + (x - mu - k))
        alert = self.cusum[key] > h
        if alert: self.cusum[key] = 0
        return {"alert": alert, "score": self.cusum[key],
                "source": "cusum", "feature": key}

    def check(self, features):
        alerts =[]
        for key in ('pps', 'bps', 'new_flows_per_sec'):
            if key not in features: continue
            if key not in self.mu: continue  # Safeguard tranh KeyError
            for fn in (self.zscore, self.ewma_check, self.cusum_check):
                r = fn(key, features[key])
                if r["alert"]: alerts.append(r)
        return {"anomaly": len(alerts) > 0, "alerts": alerts}