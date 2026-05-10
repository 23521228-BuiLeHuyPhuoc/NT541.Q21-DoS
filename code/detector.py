import time, requests, sys, math, json, os, traceback
from collections import Counter
from alert_system import AlertSystem
from entropy import EntropyDetector
from stats import StatsDetector
from signature_matcher import SignatureMatcher

RYU_FLOW_URL = "http://127.0.0.1:8081/stats/flow/2"
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
JSON_PATH = os.path.join(_BASE_DIR, "..", "results", "raw", "current_features.json")

# --- Nguong toi thieu de tranh false positive khi traffic thap (vd: pingall) ---
# Entropy chi co y nghia thong ke khi co du goi tin trong 1 chu ky.
# Duoi nguong nay, entropy thap la do it goi, KHONG PHAI do tan cong.
MIN_PKTS_FOR_ALERT = 50   # So goi tin toi thieu trong 1 chu ky de xet alert
WARMUP_CYCLES = 10        # So chu ky dau khong alert (de flow table on dinh)

last_total_packets = 0
last_check_time = time.time()
first_run = True
cycle_count = 0
_idle_logged = False    # Chi in "Mang trong" 1 lan
_warmup_logged = False  # Chi in warmup 1 lan
_skip_logged = False    # Chi in skip 1 lan

# Them bien Global nay o dau file detector.py (duoi dong first_run = True)
last_flow_counts = {}

def extract_features(flows):
    global last_total_packets, last_check_time, first_run, last_flow_counts
    now = time.time()
    
    current_total = sum(f.get('packet_count', 0) for f in flows)
    if first_run:
        last_total_packets = current_total
        last_check_time = now
        first_run = False
        pps = 11.4  # Baseline PPS mac dinh de khong bi skip o vong dau
    else:
        delta_time = now - last_check_time
        pps = (current_total - last_total_packets) / delta_time if delta_time > 0 else 0
        pps = max(0, pps)  # Flow expiry co the lam current_total giam -> PPS am
        last_total_packets = current_total
        last_check_time = now

    src_ip_counts = Counter()
    dst_port_counts = Counter()
    icmp_packets = 0
    syn_packets = 0
    udp_packets = 0
    tcp_packets = 0
    
    current_flow_counts = {}
    
    for flow in flows:
        match = flow.get('match', {})
        pkt_count = flow.get('packet_count', 0)
        
        # Tao dinh danh (ID) duy nhat cho moi luong
        match_str = str(match)
        current_flow_counts[match_str] = pkt_count
        
        # TINH DELTA (Chenh lech goi tin trong 1 giay qua cua tung luong)
        last_count = last_flow_counts.get(match_str, 0)
        # Neu flow moi bi reset (so packet < so cu), lay luon so packet hien tai
        delta_pkt = pkt_count - last_count if pkt_count >= last_count else pkt_count
        
        if delta_pkt == 0:
            continue # Bo qua flow khong co traffic moi

        src_ip = match.get('ipv4_src') or match.get('nw_src')
        if src_ip:
            src_ip_counts[src_ip] += delta_pkt
            
        dst_port = match.get('tcp_dst') or match.get('tp_dst') or match.get('udp_dst')
        if dst_port:
            dst_port_counts[dst_port] += delta_pkt
            
        ip_proto = match.get('ip_proto') or match.get('nw_proto')
        if ip_proto == 1:
            icmp_packets += delta_pkt
        elif ip_proto == 17:
            udp_packets += delta_pkt
        elif ip_proto == 6:
            tcp_packets += delta_pkt
            
        if match.get('tcp_flags') == 2:
            syn_packets += delta_pkt

    # Cap nhat bo nho de dung cho chu ky giay tiep theo
    last_flow_counts = current_flow_counts

    # 1. Tinh Shannon Entropy cho Source IP
    total_src_pkts_delta = sum(src_ip_counts.values())
    if total_src_pkts_delta > 0:
        entropy_src_ip = -sum((c/total_src_pkts_delta) * math.log2(c/total_src_pkts_delta) for c in src_ip_counts.values())
    else:
        # Khi idle (0 goi), giu entropy = baseline mean (1.3) de KHONG trigger detector.
        # Truoc day dung 3.4 nhung gia tri nay > baseline_mean + 3*sigma = 2.17
        # -> EntropyDetector coi la bat thuong (qua cao) -> false positive ngay khi khoi dong!
        entropy_src_ip = 1.3

    # 2. Tinh Shannon Entropy cho Destination Port (Danh cho s04_http_flood)
    total_dst_pkts_delta = sum(dst_port_counts.values())
    if total_dst_pkts_delta > 0:
        entropy_dst_port = -sum((c/total_dst_pkts_delta) * math.log2(c/total_dst_pkts_delta) for c in dst_port_counts.values())
    else:
        entropy_dst_port = 1.3  # Baseline mean khi idle

    timestamp = time.strftime('%H:%M:%S')
    if total_src_pkts_delta == 0:
        global _idle_logged
        if not _idle_logged:
            print(f"[{timestamp}] Mang trong -> Entropy giu baseline = {entropy_src_ip}")
            _idle_logged = True
    else:
        _idle_logged = False  # Reset khi co traffic
        print(f"[{timestamp}] {len(src_ip_counts)} IPs | {total_src_pkts_delta} pkts | Entropy: {round(entropy_src_ip, 2)}")

    features = {
        "pps": pps, 
        "bps": pps * 800, 
        "entropy_src": round(entropy_src_ip, 3),
        "entropy_src_ip": round(entropy_src_ip, 3),
        "entropy_dst_port": round(entropy_dst_port, 3),
        "syn_pct": round(syn_packets / total_src_pkts_delta, 3) if total_src_pkts_delta > 0 else 0.0, 
        "icmp_pct": round(icmp_packets / total_src_pkts_delta, 3) if total_src_pkts_delta > 0 else 0.0,
        "udp_pct": round(udp_packets / total_src_pkts_delta, 3) if total_src_pkts_delta > 0 else 0.0,
        "tcp_pct": round(tcp_packets / total_src_pkts_delta, 3) if total_src_pkts_delta > 0 else 0.0,
        "suspect_src_ip": src_ip_counts.most_common(1)[0][0] if src_ip_counts else "10.0.1.10",
        "_total_pkts_delta": total_src_pkts_delta
    }
    return features

def main():
    try:
        alr = AlertSystem()
        baseline_path = os.path.join(_BASE_DIR, '..', 'datasets', 'baseline_stats.json')
        ent_det = EntropyDetector(baseline_path=baseline_path)
        stat_det = StatsDetector(baseline_path=baseline_path)
        sig_matcher = SignatureMatcher(csv_path=os.path.join(_BASE_DIR, '..', 'docs', 'attack_signatures.csv'))
        os.makedirs(os.path.dirname(JSON_PATH), exist_ok=True)
        print(f"[{time.strftime('%H:%M:%S')}] [DETECTOR] San sang. Theo doi switch s2 moi 1s...")
        
        while True:
            try:
                global cycle_count
                cycle_count += 1
                
                resp = requests.get(RYU_FLOW_URL, timeout=2)
                flows = resp.json().get("2",[])
                features = extract_features(flows)
                
                temp_path = JSON_PATH + ".tmp"
                with open(temp_path, "w") as f:
                    json.dump(features, f)
                os.replace(temp_path, JSON_PATH)
                
                # Luon chay detection pipeline de dashboard co du lieu
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
                elif n_rules > 0:
                    # Fallback: suy doan attack type tu features kha dung
                    if features.get("icmp_pct", 0) > 0.3:
                        attack_type = "icmp_flood"
                    elif features.get("udp_pct", 0) > 0.3:
                        attack_type = "udp_flood"
                    elif features.get("tcp_pct", 0) > 0.3:
                        attack_type = "tcp_flood"
                    elif features.get("entropy_src", 5) < 1.0:
                        attack_type = "single_src_flood"
                    elif features.get("entropy_src", 0) > 3.5:
                        attack_type = "spoofed_flood"
                
                # --- GUARD ---
                total_pkts = features.get("_total_pkts_delta", 0)
                current_pps = features.get("pps", 0)
                has_traffic = total_pkts > 30 or current_pps > 50
                
                if n_rules > 0 and cycle_count <= WARMUP_CYCLES:
                    global _warmup_logged
                    if not _warmup_logged:
                        print(f"[{time.strftime('%H:%M:%S')}] [WARMUP] Bo qua alert trong {WARMUP_CYCLES} chu ky dau...")
                        _warmup_logged = True
                elif n_rules > 0 and not has_traffic:
                    global _skip_logged
                    if not _skip_logged:
                        print(f"[{time.strftime('%H:%M:%S')}] [SKIP] Traffic thap (pkts={total_pkts}, pps={int(current_pps)}) -> khong alert")
                        _skip_logged = True
                elif n_rules > 0:
                    _skip_logged = False
                    print(f"[{time.strftime('%H:%M:%S')}] >>> PHAT HIEN: {attack_type} | entropy={features.get('entropy_src','?')} icmp={features.get('icmp_pct',0)} tcp={features.get('tcp_pct',0)} udp={features.get('udp_pct',0)} | {n_rules} rules")
                    alr.emit(features["suspect_src_ip"], attack_type, n_rules, evidence)
            except Exception as e:
                print(f"[detector] Loi: {e}", flush=True)
            time.sleep(1)
    except Exception as e: print(f"Error: {e}")

if __name__ == "__main__":
    main()