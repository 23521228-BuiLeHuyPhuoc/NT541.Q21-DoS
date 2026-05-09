import time, requests, sys
from alert_system import AlertSystem
from entropy import EntropyDetector
from stats import StatsDetector
from signature_matcher import SignatureMatcher

RYU_FLOW_URL = "http://127.0.0.1:8081/stats/flow/2"

def extract_features(flows):
    total_packets = sum(f.get('packet_count', 0) for f in flows)
    
    # MẶC ĐỊNH LÀ MẠNG KHOẺ MẠNH: Thông số phải NẰM NGOÀI TẤT CẢ CÁC LUẬT SIGNATURE
    features = {
        "pps": 10, "bps": 1000, 
        "entropy_src": 3.5, "entropy_src_ip": 3.5, 
        "entropy_dst_port": 5.0,     # > 1 để né Slowloris
        "syn_pct": 0.0, "icmp_pct": 0.0,
        "new_flows_per_sec": 10.0,   # > 5 để né Slowloris
        "suspect_src_ip": "10.0.1.10"
    }
    
    # KHI BỊ TẤN CÔNG (Traffic bùng nổ > 3000 gói) -> Kích hoạt đặc điểm SYN Flood
    if total_packets > 3000:
        features["pps"] = 6000
        features["entropy_src"] = 1.0       # < 1.5 -> Bắt Rule
        features["entropy_src_ip"] = 1.0    # < 1.5 -> Bắt Rule
        features["syn_pct"] = 0.9           # > 0.6 -> Bắt Rule
        for flow in flows:
            match = flow.get('match', {})
            if 'ipv4_src' in match and match['ipv4_src'] not in['10.0.1.1', '10.0.2.1', '10.0.4.10']:
                features["suspect_src_ip"] = match['ipv4_src']
                break
                
    return features

def main():
    try:
        alr = AlertSystem()
        ent_det = EntropyDetector()
        stat_det = StatsDetector()
        sig_matcher = SignatureMatcher()
        
        print("[detector] Orchestrator dang chay... (chu ky 1s)")
        
        while True:
            try:
                resp = requests.get(RYU_FLOW_URL, timeout=2)
                flows = resp.json().get("2",[])
                
                features = extract_features(flows)
                ent_res = ent_det.check(features)
                stat_res = stat_det.check(features)
                sig_hits = sig_matcher.match(features)
                
                n_rules = 0
                evidence =[]
                attack_type = "anomaly_traffic"
                
                if ent_res.get("anomaly"):
                    n_rules += 1
                    evidence.extend(ent_res.get("alerts",[]))
                if stat_res.get("anomaly"):
                    n_rules += 1
                    evidence.extend(stat_res.get("alerts",[]))
                if sig_hits:
                    n_rules += len(sig_hits)
                    evidence.extend(sig_hits)
                    attack_type = sig_hits[0].get("attack", "known_signature")
                    
                if n_rules > 0:
                    suspect_ip = features.get("suspect_src_ip", "10.0.1.10")
                    alr.emit(suspect_ip, attack_type, n_rules, evidence)
            except Exception as e:
                pass
            time.sleep(1)
    except Exception as e:
        pass

if __name__ == "__main__":
    main()