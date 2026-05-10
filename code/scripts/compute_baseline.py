import math
import json
import sys
import os
import statistics
from collections import Counter
 
# Kiem tra scapy
try:
    from scapy.all import PcapReader, IP, TCP, UDP
    HAS_SCAPY = True
except ImportError:
    print("[ERROR] Scapy chua cai. Chay: pip3 install scapy")
    sys.exit(1)
 
 
def shannon_entropy(items):
    """Tinh Shannon entropy cua danh sach items."""
    if not items:
        return 0.0
    c = Counter(items)
    total = sum(c.values())
    entropy = 0.0
    for count in c.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy
 
 
def compute_baseline(pcap_path, window_sec=1.0, output_path=None):
    """
    Doc pcap, chia window 1s, tinh pps/bps/entropy_src/entropy_dport.
    Tra ve dict stats voi mean va std.
    """
    print(f"[INFO] Dang doc: {pcap_path}")
 
    if not os.path.exists(pcap_path):
        print(f"[ERROR] File khong ton tai: {pcap_path}")
        sys.exit(1)
 
    # Thu thap tat ca packet voi timestamp
    packets = []
    total_read = 0
    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            total_read += 1
            if total_read % 10000 == 0:
                print(f"  Da doc {total_read} goi...")
            if pkt.haslayer(IP):
                ts = float(pkt.time)
                size = len(pkt)
                src_ip = pkt[IP].src
                dport = None
                if pkt.haslayer(TCP):
                    dport = pkt[TCP].dport
                elif pkt.haslayer(UDP):
                    dport = pkt[UDP].dport
                packets.append((ts, size, src_ip, dport))
 
    if len(packets) < 10:
        print(f"[ERROR] Qua it packet IP ({len(packets)}). Kiem tra lai pcap.")
        sys.exit(1)
 
    print(f"[INFO] Tong goi IP: {len(packets)}")
 
    # Tinh features theo window 1s
    t_start = packets[0][0]
    t_end   = packets[-1][0]
    total_duration = t_end - t_start
    print(f"[INFO] Thoi gian capture: {total_duration:.1f}s ({total_duration/60:.1f} phut)")
 
    pps_list      = []
    bps_list      = []
    entropy_src_list   = []
    entropy_dport_list = []
 
    t = t_start
    while t < t_end:
        window = [(ts, sz, src, dp) for (ts, sz, src, dp) in packets if t <= ts < t + window_sec]
        if not window:
            t += window_sec
            continue
 
        n        = len(window)
        byte_sum = sum(sz for (_, sz, _, _) in window)
        srcs     = [src for (_, _, src, _) in window]
        dports   = [dp for (_, _, _, dp) in window if dp is not None]
 
        pps_list.append(n / window_sec)
        bps_list.append(byte_sum * 8 / window_sec)
        entropy_src_list.append(shannon_entropy(srcs))
        entropy_dport_list.append(shannon_entropy(dports) if dports else 0.0)
 
        t += window_sec
 
    if len(pps_list) < 2:
        print("[ERROR] Khong du window de tinh stats. Can pcap dai hon.")
        sys.exit(1)
 
    print(f"[INFO] So window (1s): {len(pps_list)}")
 
    # Tinh mean va std
    def stats(lst):
        return {
            "mean": round(statistics.mean(lst), 4),
            "std":  round(statistics.stdev(lst), 4)
        }
 
    baseline = {
        "pps":           stats(pps_list),
        "bps":           stats(bps_list),
        "entropy_src":   stats(entropy_src_list),
        "entropy_dport": stats(entropy_dport_list)
    }
 
    # In ket qua
    print("\n[BASELINE STATS]")
    for k, v in baseline.items():
        print(f"  {k:20s}: mean={v['mean']:.4f}, std={v['std']:.4f}")
 
    # Luu file
    if output_path is None:
        output_path = "tests/fixtures/baseline.json"
 
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(baseline, f, indent=2)
 
    print(f"\n[OK] Da luu baseline -> {output_path}")
    return baseline
 
 
def generate_mock_baseline(output_path="tests/fixtures/baseline.json"):
    """
    Tao baseline.json gia (dung khi chua co pcap that)
    """
    mock = {
        "pps":           {"mean": 50.0,  "std": 10.0},
        "bps":           {"mean": 400000.0, "std": 80000.0},
        "entropy_src":   {"mean": 3.5,   "std": 0.5},
        "entropy_dport": {"mean": 4.0,   "std": 0.8}
    }
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(mock, f, indent=2)
    print(f"[OK] Da tao mock baseline -> {output_path}")
    return mock
 
 
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 compute_baseline.py <pcap_path> [output_json]")
        print("       python3 compute_baseline.py --mock")
        sys.exit(1)
 
    if sys.argv[1] == '--mock':
        generate_mock_baseline()
    else:
        pcap = sys.argv[1]
        out  = sys.argv[2] if len(sys.argv) > 2 else None
        compute_baseline(pcap, output_path=out)
