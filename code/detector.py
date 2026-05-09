import time, requests, sys, math, json, os
from collections import Counter
from alert_system import AlertSystem
from entropy import EntropyDetector
from stats import StatsDetector
from signature_matcher import SignatureMatcher

RYU_FLOW_URL = "http://127.0.0.1:8081/stats/flow/2"
JSON_PATH = "results/raw/current_features.json"

last_total_packets = 0
last_check_time = time.time()
first_run = True

def extract_features(flows):
    global last_total_packets, last_check_time, first_run
    current_total = sum(f.get('packet_count', 0) for f in flows)
    now = time.time()
    
    if first_run:
        last_total_packets = current_total
        last_check_time = now
        first_run = False
        pps = 0.0
    else:
        delta_packets = current_total - last_total_packets
        delta_time = now - last_check_time
        pps = delta_packets / delta_time if delta_time > 0 else 0
        last_total_packets = current_total
        last_check_time = now

    src_ip_counts = Counter()
    dst_port_counts = Counter()
    icmp_packets = 0
    syn_packets = 0
    
    for flow in flows:
        match = flow.get('match', {})
        pkt_count = flow.get('packet_count', 0)
        
        # Tương thích cả 2 chuẩn API của Ryu
        src_ip = match.get('ipv4_src') or match.get('nw_src')
        if src_ip:
            src_ip_counts[src_ip] += pkt_count
            
        dst_port = match.get('tcp_dst') or match.get('tp_dst') or match.get('udp_dst')
        if dst_port:
            dst_port_counts[dst_port] += pkt_count
            
        ip_proto = match.get('ip_proto') or match.get('nw_proto')
        if ip_proto == 1:
            icmp_packets += pkt_count
            
        if match.get('tcp_flags') == 2:
            syn_packets += pkt_count

    total_src_pkts = sum(src_ip_counts.values())
    entropy_src_ip = 0.0
    if total_src_pkts > 0:
        entropy_src_ip = -sum((c/total_src_pkts) * math.log2(c/total_src_pkts) for c in src_ip_counts.values())

    # --- IN RA TERMINAL GIẢI THÍCH LÝ DO CHO BẠN HIỂU ---
    timestamp = time.strftime('%H:%M:%S')
    if total_src_pkts == 0:
        print(f"[{timestamp}] Mạng ĐANG TRỐNG (Flow đã bị xóa/Chưa có traffic) -> Entropy = 0.0")
    elif len(src_ip_counts) == 1:
        ip = list(src_ip_counts.keys())[0]
        print(f"[{timestamp}] Traffic chỉ từ 1 IP duy nhất ({ip}) -> Entropy = 0.0 (Dấu hiệu bị DDoS)")
    else:
        print(f"[{timestamp}] Mạng BÌNH THƯỜNG: Có {len(src_ip_counts)} IPs đang gửi | Tổng gói: {total_src_pkts} | Entropy = {round(entropy_src_ip, 2)}")

    features = {
        "pps": pps, "bps": pps * 800, 
        "entropy_src_ip": round(entropy_src_ip, 3), 
        "syn_pct": round(syn_packets / total_src_pkts, 3) if total_src_pkts > 0 else 0.0, 
        "icmp_pct": round(icmp_packets / total_src_pkts, 3) if total_src_pkts > 0 else 0.0,
        "suspect_src_ip": src_ip_counts.most_common(1)[0][0] if src_ip_counts else "10.0.1.10"
    }
    return features

def main():
    try:
        alr = AlertSystem()
        ent_det = EntropyDetector()
        stat_det = StatsDetector()
        sig_matcher = SignatureMatcher()
        os.makedirs(os.path.dirname(JSON_PATH), exist_ok=True)
        
        while True:
            try:
                resp = requests.get(RYU_FLOW_URL, timeout=2)
                flows = resp.json().get("2",[])
                features = extract_features(flows)
                
                temp_path = JSON_PATH + ".tmp"
                with open(temp_path, "w") as f:
                    json.dump(features, f)
                os.replace(temp_path, JSON_PATH)
                
                # Nới lỏng kiểm tra để detector luôn đọc dù mạng có ít gói
                if features.get("pps", 0) < 1:
                    time.sleep(1)
                    continue
                
                ent_res = ent_det.check(features)
                stat_res = stat_det.check(features)
                sig_hits = sig_matcher.match(features)
                
                n_rules = 0
                evidence =[]
                attack_type = "anomaly_traffic"
                
                if ent_res.get("anomaly"): n_rules += 1; evidence.extend(ent_res.get("alerts",[]))
                if stat_res.get("anomaly"): n_rules += 1; evidence.extend(stat_res.get("alerts",[]))
                if sig_hits:
                    n_rules += len(sig_hits); evidence.extend(sig_hits)
                    attack_type = sig_hits[0].get("attack", "known_signature")
                    
                if n_rules > 0:
                    alr.emit(features["suspect_src_ip"], attack_type, n_rules, evidence)
            except Exception: 
                pass
            time.sleep(1)
    except Exception as e: print(f"Error: {e}")

if __name__ == "__main__":
    main()