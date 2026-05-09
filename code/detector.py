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
        if 'ipv4_src' in match:
            src_ip_counts[match['ipv4_src']] += pkt_count
        if 'tcp_dst' in match:
            dst_port_counts[match['tcp_dst']] += pkt_count
        elif 'udp_dst' in match:
            dst_port_counts[match['udp_dst']] += pkt_count
        if match.get('ip_proto') == 1:
            icmp_packets += pkt_count
        if match.get('tcp_flags') == 2:
            syn_packets += pkt_count

    total_src_pkts = sum(src_ip_counts.values())
    entropy_src_ip = 0.0
    if total_src_pkts > 0:
        entropy_src_ip = -sum((c/total_src_pkts) * math.log2(c/total_src_pkts) for c in src_ip_counts.values())

    # Log ra terminal giong ban dang dung de doi chieu
    if total_src_pkts > 0:
        print(f"[ENTROPY] Gia tri entropy = {round(entropy_src_ip, 2)} | Tong goi = {total_src_pkts} | So IP duy nhat = {len(src_ip_counts)}")

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
        ent_det = EntropyDetector(); stat_det = StatsDetector(); sig_matcher = SignatureMatcher()
        os.makedirs(os.path.dirname(JSON_PATH), exist_ok=True)
        
        while True:
            try:
                resp = requests.get(RYU_FLOW_URL, timeout=2)
                flows = resp.json().get("2", [])
                features = extract_features(flows)
                
                # Ghi file Atomic (ghi ra file tam roi rename) de Dashboard khong doc file trong
                temp_path = JSON_PATH + ".tmp"
                with open(temp_path, "w") as f:
                    json.dump(features, f)
                os.replace(temp_path, JSON_PATH)
                
                if features.get("pps", 0) < 5:
                    time.sleep(1); continue
                
                ent_res = ent_det.check(features); stat_res = stat_det.check(features)
                sig_hits = sig_matcher.match(features)
                
                n_rules = 0; evidence = []; attack_type = "anomaly_traffic"
                if ent_res.get("anomaly"): n_rules += 1; evidence.extend(ent_res.get("alerts", []))
                if stat_res.get("anomaly"): n_rules += 1; evidence.extend(stat_res.get("alerts", []))
                if sig_hits:
                    n_rules += len(sig_hits); evidence.extend(sig_hits)
                    attack_type = sig_hits[0].get("attack", "known_signature")
                    
                if n_rules > 0:
                    alr.emit(features["suspect_src_ip"], attack_type, n_rules, evidence)
            except Exception: pass
            time.sleep(1)
    except Exception as e: print(f"Error: {e}")

if __name__ == "__main__":
    main()