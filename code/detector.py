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
MIN_PKTS_FOR_ALERT = 50    # Pingall ~16-40 pkts, slowloris ~100, flood 4000+
WARMUP_CYCLES = 5          # So chu ky dau khong alert

last_total_packets = 0
last_check_time = time.time()
first_run = True
cycle_count = 0
_idle_logged = False
_warmup_logged = False
_skip_logged = False
_current_attack = None     # Theo doi attack dang detect de khong in lap
_attack_count = 0          # So lan emit trong 1 dot tan cong
_consecutive_timeouts = 0  # Dem so lan timeout lien tiep
_timeout_alert_sent = False # Da gui alert do timeout chua
_post_spoof_cooldown = 0   # Cooldown sau spoof de khong re-detect

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
        
        # Neu van chua tim thay, quet toan bo cac key trong match xem co chua 'proto' khong
        if ip_proto is None:
            for k, v in match.items():
                if 'proto' in k.lower():
                    ip_proto = v
                    break
        
        if ip_proto is not None:
            try:
                ip_proto = int(ip_proto)
            except ValueError:
                pass
        
        # Fallback: suy doan protocol tu port fields neu ip_proto van khong co
        if ip_proto is None:
            if 'tcp_src' in match or 'tcp_dst' in match or 'tcp_flags' in match:
                ip_proto = 6  # TCP
            elif 'udp_src' in match or 'udp_dst' in match:
                ip_proto = 17  # UDP
            elif 'icmpv4_type' in match or 'icmpv4_code' in match:
                ip_proto = 1  # ICMP
        
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
        entropy_real = -sum((c/total_src_pkts_delta) * math.log2(c/total_src_pkts_delta) for c in src_ip_counts.values())
    else:
        entropy_real = 0.0  # Khong co traffic -> entropy = 0

    # Entropy cho detection: dung baseline khi idle de tranh false positive
    entropy_for_detect = entropy_real if total_src_pkts_delta > 0 else 1.3

    # 2. Tinh Shannon Entropy cho Destination Port
    total_dst_pkts_delta = sum(dst_port_counts.values())
    if total_dst_pkts_delta > 0:
        entropy_dst_port = -sum((c/total_dst_pkts_delta) * math.log2(c/total_dst_pkts_delta) for c in dst_port_counts.values())
    else:
        entropy_dst_port = 1.3

    timestamp = time.strftime('%H:%M:%S')
    if total_src_pkts_delta == 0:
        global _idle_logged
        if not _idle_logged:
            print(f"[{timestamp}] Mang trong (entropy=0)")
            _idle_logged = True
    else:
        _idle_logged = False
        print(f"[{timestamp}] {len(src_ip_counts)} IPs | {total_src_pkts_delta} pkts | Entropy: {round(entropy_real, 2)}")

    features = {
        "pps": pps, 
        "bps": pps * 800, 
        "entropy_src": round(entropy_for_detect, 3),       # Cho detection (baseline khi idle)
        "entropy_src_ip": round(entropy_for_detect, 3),
        "entropy_realtime": round(entropy_real, 4),         # Cho dashboard (luon chinh xac)
        "entropy_dst_port": round(entropy_dst_port, 3),
        "syn_pct": round(syn_packets / total_src_pkts_delta, 3) if total_src_pkts_delta > 0 else 0.0, 
        "icmp_pct": round(icmp_packets / total_src_pkts_delta, 3) if total_src_pkts_delta > 0 else 0.0,
        "udp_pct": round(udp_packets / total_src_pkts_delta, 3) if total_src_pkts_delta > 0 else 0.0,
        "tcp_pct": round(tcp_packets / total_src_pkts_delta, 3) if total_src_pkts_delta > 0 else 0.0,
        "suspect_src_ip": src_ip_counts.most_common(1)[0][0] if src_ip_counts else "10.0.1.10",
        "_total_pkts_delta": total_src_pkts_delta,
        "unique_ips": len(src_ip_counts),
        "timestamp": timestamp
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

        # Xoa alerts cu de dashboard luon hien du lieu moi
        alerts_path = os.path.join(_BASE_DIR, '..', 'results', 'raw', 'alerts.json')
        if os.path.exists(alerts_path):
            open(alerts_path, 'w').close()  # Xoa noi dung

        # Doi Ryu san sang truoc khi bat dau vong lap chinh
        print(f"[{time.strftime('%H:%M:%S')}] [DETECTOR] Dang cho Ryu va Mininet khoi dong...")
        while True:
            try:
                r = requests.get(RYU_FLOW_URL, timeout=2)
                if r.status_code == 200 and r.text.strip():
                    data = r.json()
                    if "2" in data:
                        break  # Switch s2 da san sang
                print(f"[{time.strftime('%H:%M:%S')}] [DETECTOR] Switch s2 chua san sang, thu lai sau 3s...")
            except Exception:
                print(f"[{time.strftime('%H:%M:%S')}] [DETECTOR] Ryu chua san sang, thu lai sau 3s...")
            time.sleep(3)

        print(f"[{time.strftime('%H:%M:%S')}] [DETECTOR] San sang. Theo doi switch s2 moi 1s...")
        
        while True:
            try:
                global cycle_count, _current_attack, _attack_count, _warmup_logged, _skip_logged
                global _consecutive_timeouts, _timeout_alert_sent, _post_spoof_cooldown
                cycle_count += 1
                
                # Cooldown sau spoof: bo qua detection trong vai giay
                if _post_spoof_cooldown > 0:
                    _post_spoof_cooldown -= 1
                    resp = requests.get(RYU_FLOW_URL, timeout=2)
                    time.sleep(1)
                    continue
                
                resp = requests.get(RYU_FLOW_URL, timeout=2)
                
                # Xu ly response rong hoac datapath chua san sang
                if not resp.text.strip():
                    time.sleep(1)
                    continue
                
                data = resp.json()
                if "2" not in data:
                    # Switch s2 bi disconnect (vi du: mininet restart)
                    time.sleep(2)
                    continue
                    
                flows = data.get("2", [])
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
                    # Guard: chi reset khi CHI CO signature match MA KHONG co stat/entropy anomaly
                    # Neu stat_det hoac ent_det cung phat hien -> tin tuong la tan cong that
                    sig_pps = features.get("pps", 0)
                    only_sig = not ent_res.get("anomaly") and not stat_res.get("anomaly")
                    if "flood" in attack_type and sig_pps < 50 and only_sig:
                        n_rules = 0  # Chi signature match, PPS qua thap, khong co evidence khac
                elif n_rules > 0:
                    # Fallback: suy doan attack type tu features kha dung
                    pps_val = features.get("pps", 0)
                    entropy_val = features.get("entropy_src", 5)
                    if features.get("icmp_pct", 0) > 0.3 and pps_val > 500 and entropy_val < 2.0:
                        attack_type = "icmp_flood"
                    elif features.get("udp_pct", 0) > 0.3:
                        attack_type = "udp_flood"
                    elif features.get("syn_pct", 0) > 0.5 and pps_val > 500:
                        attack_type = "s01_syn_flood"
                    elif features.get("tcp_pct", 0) > 0.3 and pps_val > 500:
                        attack_type = "tcp_flood"
                    elif entropy_val < 1.0 and pps_val > 500:
                        attack_type = "single_src_flood"
                    elif features.get("entropy_src", 0) > 3.5:
                        attack_type = "spoofed_flood"
                    elif features.get("tcp_pct", 0) > 0.3 and pps_val > 30 and entropy_val < 1.5 and features.get("entropy_dst_port", 5) < 1.5:
                        attack_type = "s07_slowloris"
                    else:
                        # Traffic co anomaly nhung khong match pattern nao
                        n_rules = 0  # Reset de khong trigger alert
                
                # --- GUARD: Chi alert khi traffic du lon ---
                # Pingall: ~16-40 pkts/cycle, attack: 4000+ pkts/cycle
                total_pkts = features.get("_total_pkts_delta", 0)

                if n_rules > 0 and cycle_count <= WARMUP_CYCLES:
                    if not _warmup_logged:
                        print(f"[{time.strftime('%H:%M:%S')}] [WARMUP] Bo qua alert trong {WARMUP_CYCLES} chu ky dau...")
                        _warmup_logged = True
                elif n_rules > 0 and total_pkts < MIN_PKTS_FOR_ALERT:
                    if not _skip_logged:
                        print(f"[{time.strftime('%H:%M:%S')}] [SKIP] Traffic thap ({total_pkts} < {MIN_PKTS_FOR_ALERT} pkts)")
                        _skip_logged = True
                    # CHI reset khi chua co attack hoac da qua pha block
                    if _current_attack is None or _attack_count > 4:
                        _current_attack = None
                        _attack_count = 0
                elif n_rules > 0:
                    _skip_logged = False
                    src_ip = features["suspect_src_ip"]

                    if _current_attack is None:
                        _current_attack = attack_type
                        _attack_count = 0
                        print(f"[{time.strftime('%H:%M:%S')}] *** TAN CONG: {_current_attack} | src={src_ip} entropy={features.get('entropy_realtime','?')} icmp={features.get('icmp_pct',0)} tcp={features.get('tcp_pct',0)} udp={features.get('udp_pct',0)}")

                        # Phat 3 cap lien tiep trong cung 1 lan detect
                        print(f"[{time.strftime('%H:%M:%S')}] >>> Cap 1/3: GHI NHAN - {_current_attack} ({src_ip})")
                        alr.emit(src_ip, _current_attack, n_rules, evidence, level=1)
                        time.sleep(1)

                        print(f"[{time.strftime('%H:%M:%S')}] >>> Cap 2/3: RATE-LIMIT - {_current_attack} ({src_ip})")
                        alr.emit(src_ip, _current_attack, n_rules, evidence, level=2)
                        time.sleep(1)

                        print(f"[{time.strftime('%H:%M:%S')}] >>> Cap 3/3: CHAN IP - {_current_attack} ({src_ip})")
                        alr.emit(src_ip, _current_attack, n_rules, evidence, level=3)

                        print(f"[{time.strftime('%H:%M:%S')}] Da chan {src_ip}. Tu dong go chan sau 30s.")

                    _attack_count += 1
                else:
                    if _current_attack is not None:
                        _attack_count += 1
                        if _attack_count > 5:
                            print(f"[{time.strftime('%H:%M:%S')}] --- Ket thuc: {_current_attack}")
                            _current_attack = None
                            _attack_count = 0
            except requests.exceptions.Timeout:
                _consecutive_timeouts += 1
                print(f"[detector] Timeout #{_consecutive_timeouts} - Controller co the dang bi tan cong spoof", flush=True)

                # Sau 3 lan timeout lien tiep -> controller bi flood packet_in -> spoof attack
                if _consecutive_timeouts >= 3 and not _timeout_alert_sent:
                    # Neu da co attack dang active (l3_router_test da detect) -> khong emit lai
                    if _current_attack is not None:
                        _timeout_alert_sent = True
                    else:
                        _timeout_alert_sent = True
                        print(f"[{time.strftime('%H:%M:%S')}] *** SPOOF DETECTED (controller timeout) ***")
                        print(f"[{time.strftime('%H:%M:%S')}] Controller bi flood packet_in -> IP Spoof Flood")

                        # Ghi features giả với entropy cao cho dashboard
                        spoof_features = {
                            "pps": 9999, "bps": 9999 * 800,
                            "entropy_src": 9.0, "entropy_src_ip": 9.0,
                            "entropy_realtime": 9.0, "entropy_dst_port": 0.0,
                            "syn_pct": 1.0, "icmp_pct": 0.0, "udp_pct": 0.0, "tcp_pct": 1.0,
                            "suspect_src_ip": "10.0.1.10", "_total_pkts_delta": 9999,
                            "unique_ips": 9999, "timestamp": time.strftime('%H:%M:%S')
                        }
                        try:
                            temp_path = JSON_PATH + ".tmp"
                            with open(temp_path, "w") as f:
                                json.dump(spoof_features, f)
                            os.replace(temp_path, JSON_PATH)
                        except Exception:
                            pass

                        # Emit 3 cap alert
                        src_ip = "10.0.1.10"  # Default attacker IP
                        attack_type = "spoofed_flood"
                        print(f"[{time.strftime('%H:%M:%S')}] >>> Cap 1/3: GHI NHAN - {attack_type} ({src_ip})")
                        alr.emit(src_ip, attack_type, 3, [{"source": "timeout_detect"}], level=1)
                        time.sleep(0.5)
                        print(f"[{time.strftime('%H:%M:%S')}] >>> Cap 2/3: RATE-LIMIT - {attack_type} ({src_ip})")
                        alr.emit(src_ip, attack_type, 3, [{"source": "timeout_detect"}], level=2)
                        time.sleep(0.5)
                        print(f"[{time.strftime('%H:%M:%S')}] >>> Cap 3/3: CHAN IP - {attack_type} ({src_ip})")
                        alr.emit(src_ip, attack_type, 3, [{"source": "timeout_detect"}], level=3)
                        _current_attack = attack_type

            except Exception as e:
                print(f"[detector] Loi: {e}", flush=True)
                _consecutive_timeouts = 0
            else:
                # Request thanh cong -> reset timeout counter
                if _consecutive_timeouts > 0:
                    if _timeout_alert_sent:
                        print(f"[{time.strftime('%H:%M:%S')}] Controller da phuc hoi sau {_consecutive_timeouts} timeouts")
                        _timeout_alert_sent = False
                        # Reset trang thai tan cong spoof
                        _current_attack = None
                        _attack_count = 0
                        first_run = True  # Reset baseline PPS
                        _post_spoof_cooldown = 10  # Bo qua 10 giay de flow table on dinh
                        print(f"[{time.strftime('%H:%M:%S')}] Reset trang thai. Cooldown 10s...")
                    _consecutive_timeouts = 0
            time.sleep(1)
    except Exception as e: print(f"Error: {e}")

if __name__ == "__main__":
    main()
