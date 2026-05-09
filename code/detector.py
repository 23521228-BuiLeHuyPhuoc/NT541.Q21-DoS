import time
import requests
import sys
import math
from collections import Counter

from alert_system import AlertSystem
from entropy import EntropyDetector
from stats import StatsDetector
from signature_matcher import SignatureMatcher

RYU_FLOW_URL = "http://127.0.0.1:8081/stats/flow/2"

last_total_packets = 0
last_check_time = time.time()
first_run = True

def extract_features(flows):
    global last_total_packets, last_check_time, first_run
    
    current_total = sum(f.get('packet_count', 0) for f in flows)
    now = time.time()
    
    # Tính PPS (Packets Per Second)
    if first_run:
        last_total_packets = current_total
        last_check_time = now
        first_run = False
        pps = 0.0  # Khởi tạo pps thực tế bằng 0 để mạng nhận diện đúng trạng thái Idle
    else:
        delta_packets = current_total - last_total_packets
        delta_time = now - last_check_time
        pps = delta_packets / delta_time if delta_time > 0 else 0
        last_total_packets = current_total
        last_check_time = now

    # Khởi tạo bộ đếm để tính Entropy
    src_ip_counts = Counter()
    dst_port_counts = Counter()
    icmp_packets = 0
    syn_packets = 0
    
    for flow in flows:
        match = flow.get('match', {})
        pkt_count = flow.get('packet_count', 0)
        
        # Đếm IP nguồn
        if 'ipv4_src' in match:
            src_ip_counts[match['ipv4_src']] += pkt_count
            
        # Đếm Port đích (TCP hoặc UDP)
        if 'tcp_dst' in match:
            dst_port_counts[match['tcp_dst']] += pkt_count
        elif 'udp_dst' in match:
            dst_port_counts[match['udp_dst']] += pkt_count
            
        # Đếm ICMP (ip_proto == 1)
        if match.get('ip_proto') == 1:
            icmp_packets += pkt_count
            
        # Heuristic cho SYN (nếu Ryu có đẩy match tcp_flags)
        if match.get('tcp_flags') == 2:
            syn_packets += pkt_count

    total_src_pkts = sum(src_ip_counts.values())
    
    # Tính Shannon & Renyi Entropy cho IP Nguồn
    entropy_src_ip = 0.0
    entropy_renyi_src = 0.0
    if total_src_pkts > 0:
        entropy_src_ip = -sum((c/total_src_pkts) * math.log2(c/total_src_pkts) for c in src_ip_counts.values())
        sum_sq = sum((c/total_src_pkts)**2 for c in src_ip_counts.values())
        entropy_renyi_src = -math.log2(sum_sq) if sum_sq > 0 else 0.0

    # Tính Shannon Entropy cho Port Đích
    total_dst_pkts = sum(dst_port_counts.values())
    entropy_dst_port = 0.0
    if total_dst_pkts > 0:
        entropy_dst_port = -sum((c/total_dst_pkts) * math.log2(c/total_dst_pkts) for c in dst_port_counts.values())

    # Xác định IP tình nghi (IP gửi nhiều gói tin nhất)
    suspect = "10.0.1.10"
    if src_ip_counts:
        suspect = src_ip_counts.most_common(1)[0][0]

    features = {
        "pps": pps, 
        "bps": pps * 800, 
        "entropy_src_ip": round(entropy_src_ip, 3), 
        "entropy_dst_port": round(entropy_dst_port, 3), 
        "entropy_renyi_src": round(entropy_renyi_src, 3),
        "syn_pct": round(syn_packets / total_src_pkts, 3) if total_src_pkts > 0 else 0.0, 
        "icmp_pct": round(icmp_packets / total_src_pkts, 3) if total_src_pkts > 0 else 0.0,
        "new_flows_per_sec": len(flows),
        "suspect_src_ip": suspect
    }
                
    return features

def main():
    try:
        alr = AlertSystem()
        ent_det = EntropyDetector()
        stat_det = StatsDetector()
        sig_matcher = SignatureMatcher()  # Luật được load vào RAM tại đây
        
        print("[detector] Orchestrator dang chay... (chu ky 1s)")
        
        while True:
            try:
                resp = requests.get(RYU_FLOW_URL, timeout=2)
                flows = resp.json().get("2", [])
                features = extract_features(flows)
                
                # CHỐT CHẶN TRAFFIC GUARD: Bỏ qua nếu mạng đang rảnh (Idle Network Paradox)
                if features.get("pps", 0) < 5:
                    time.sleep(1)
                    continue
                
                ent_res = ent_det.check(features)
                stat_res = stat_det.check(features)
                sig_hits = sig_matcher.match(features)
                
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
                    
                if n_rules > 0:
                    suspect_ip = features.get("suspect_src_ip", "10.0.1.10")
                    alr.emit(suspect_ip, attack_type, n_rules, evidence)
            except Exception as e:
                # Bỏ qua lỗi kết nối tạm thời khi gọi Ryu API
                pass
            time.sleep(1)
    except Exception as e:
        print(f"[detector] Orchestrator dung dot ngot: {e}")

if __name__ == "__main__":
    main()