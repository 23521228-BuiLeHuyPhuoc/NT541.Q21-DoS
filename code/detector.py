import time, requests
from alert_system import AlertSystem
from entropy import EntropyDetector
from stats import StatsDetector
from signature_matcher import SignatureMatcher

RYU_FLOW_URL = "http://127.0.0.1:8080/stats/flow/2"

def extract_features(flows):
    """
    Trích xuất features từ dữ liệu flow của Ryu.
    (Hàm giả lập/rút gọn: tính tổng packet, byte và xác định IP khả nghi nhất)
    """
    features = {
        "pps": 0, "bps": 0, 
        "entropy_src_ip": 0.0, "entropy_dst_port": 0.0,
        "syn_pct": 0.0, "icmp_pct": 0.0,
        "suspect_src_ip": "10.0.1.10" # Mặc định
    }
    
    total_packets = 0
    total_bytes = 0
    
    for flow in flows:
        total_packets += flow.get('packet_count', 0)
        total_bytes += flow.get('byte_count', 0)
        # Bóc tách IP khả nghi nếu có match ipv4_src
        match = flow.get('match', {})
        if 'ipv4_src' in match:
            features["suspect_src_ip"] = match['ipv4_src']
            
    features["pps"] = total_packets # Giả sử window = 1s
    features["bps"] = total_bytes * 8
    
    # Thực tế, phần entropy sẽ được lấy thêm từ module InfluxDB/features extractor
    return features

def main():
    alr = AlertSystem()
    
    # Khởi tạo 3 layer phát hiện
    ent_det = EntropyDetector()
    stat_det = StatsDetector()
    sig_matcher = SignatureMatcher()

    print("[detector] Orchestrator dang chay... (chu ky 1s)")
    
    while True:
        try:
            # 1. Gọi Ryu REST /stats/flow/2
            resp = requests.get(RYU_FLOW_URL, timeout=2)
            flows = resp.json().get("2", [])
            
            # 2. Trích xuất features
            features = extract_features(flows)
            
            # 3. Chạy qua các Detectors
            ent_res = ent_det.check(features)
            stat_res = stat_det.check(features)
            sig_hits = sig_matcher.match(features)
            
            # 4. Aggregate n_rules & evidence
            n_rules = 0
            evidence = []
            attack_type = "anomaly_traffic"
            
            if ent_res.get("anomaly"):
                n_rules += 1
                evidence.extend(ent_res.get("alerts", []))
                
            if stat_res.get("anomaly"):
                n_rules += 1
                evidence.extend(stat_res.get("alerts", []))
                
            if sig_hits:
                n_rules += len(sig_hits)
                evidence.extend(sig_hits)
                attack_type = sig_hits[0].get("attack", "known_signature")
                
            # 5. Phát cảnh báo nếu có rule bị vi phạm
            if n_rules > 0:
                suspect_ip = features.get("suspect_src_ip", "unknown_ip")
                alr.emit(suspect_ip, attack_type, n_rules, evidence)
                
        except Exception as e:
            print(f"[detector] Loi trong vong lap orchestrator: {e}")
            
        time.sleep(1)

if __name__ == "__main__":
    main()