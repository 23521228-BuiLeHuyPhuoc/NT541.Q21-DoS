import math
import csv
import sys
import os
from collections import Counter
 
 
try:
    from scapy.all import PcapReader, IP, TCP, UDP, ICMP
except ImportError:
    print("[ERROR] Scapy chưa cài. Chạy: pip3 install scapy")
    sys.exit(1)
 
 
def shannon(items):
    """Shannon entropy (bits)."""
    if not items:
        return 0.0
    c = Counter(items)
    n = sum(c.values())
    return -sum((v / n) * math.log2(v / n) for v in c.values())
 
 
def renyi(items, q=2):
    """Rényi entropy bậc q (bits). q=2 là Collision entropy."""
    if not items:
        return 0.0
    c = Counter(items)
    n = sum(c.values())
    s = sum((v / n) ** q for v in c.values())
    if s <= 0:
        return 0.0
    return (1 / (1 - q)) * math.log2(s)
 
 
def extract(pcap_path, out_csv, win=1.0, slide=0.5):
    """
    Đọc pcap, trích features theo sliding window.
 
    Args:
        pcap_path: Đường dẫn đến file .pcap
        out_csv:   Đường dẫn file CSV output
        win:       Kích thước window (giây)
        slide:     Bước trượt (giây)
    """
    print(f"[EXTRACT] Đọc: {pcap_path}")
 
    if not os.path.exists(pcap_path):
        print(f"[ERROR] File không tồn tại: {pcap_path}")
        sys.exit(1)
 
    # Đọc tất cả IP packet vào memory
    pkts = []
    count = 0
    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            count += 1
            if count % 50000 == 0:
                print(f"  Đọc {count} gói...")
            if pkt.haslayer(IP):
                pkts.append((float(pkt.time), pkt))
 
    if not pkts:
        print("[ERROR] Không có IP packet nào trong pcap.")
        return
 
    print(f"[EXTRACT] Tổng {len(pkts)} IP packets từ {count} tổng gói")
 
    t0    = pkts[0][0]
    t_end = pkts[-1][0]
    print(f"[EXTRACT] Duration: {t_end - t0:.1f}s")
 
    # Tạo thư mục output
    os.makedirs(os.path.dirname(out_csv) if os.path.dirname(out_csv) else '.', exist_ok=True)
 
    HEADER = [
        't',
        'entropy_src_ip', 'entropy_dst_ip', 'entropy_dst_port', 'entropy_renyi_src',
        'pps', 'bps',
        'syn_pct', 'icmp_pct',
        'new_flows_per_sec', 'avg_pkt_size'
    ]
 
    row_count = 0
    flows_seen = set()
 
    with open(out_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(HEADER)
 
        t = t0
        while t < t_end:
            t_next = t + win
            # Lấy packet trong window [t, t+win)
            window = [pkt for (ts, pkt) in pkts if t <= ts < t_next]
 
            if not window:
                t += slide
                continue
 
            n        = len(window)
            byte_sum = sum(len(p) for p in window)
 
            # Features IP
            src_ips = [p[IP].src for p in window]
            dst_ips = [p[IP].dst for p in window]
 
            # Features port
            dst_ports = []
            for p in window:
                if p.haslayer(TCP):
                    dst_ports.append(p[TCP].dport)
                elif p.haslayer(UDP):
                    dst_ports.append(p[UDP].dport)
 
            # SYN count
            syn_count = sum(
                1 for p in window
                if p.haslayer(TCP) and (p[TCP].flags & 0x02)
            )
 
            # ICMP count
            icmp_count = sum(1 for p in window if p.haslayer(ICMP))
 
            # New flows (5-tuple: src_ip, dst_ip, proto, src_port, dst_port)
            flows_now = set()
            for p in window:
                src_ip = p[IP].src
                dst_ip = p[IP].dst
                proto  = p[IP].proto
                sport  = p[TCP].sport if p.haslayer(TCP) else (p[UDP].sport if p.haslayer(UDP) else 0)
                dport  = p[TCP].dport if p.haslayer(TCP) else (p[UDP].dport if p.haslayer(UDP) else 0)
                flows_now.add((src_ip, dst_ip, proto, sport, dport))
 
            new_flows = len(flows_now - flows_seen)
            flows_seen |= flows_now
 
            # Ghi row
            writer.writerow([
                round(t, 2),
                round(shannon(src_ips),  3),
                round(shannon(dst_ips),  3),
                round(shannon(dst_ports) if dst_ports else 0.0, 3),
                round(renyi(src_ips),    3),
                round(n / win,           2),                          # pps
                round(byte_sum * 8 / win, 2),                        # bps
                round(syn_count / n,     3),                          # syn_pct
                round(icmp_count / n,    3),                          # icmp_pct
                round(new_flows / win,   2),                          # new_flows_per_sec
                round(byte_sum / n,      1)                           # avg_pkt_size
            ])
            row_count += 1
            t += slide
 
    print(f"[EXTRACT] Đã ghi {row_count} rows → {out_csv}")
    return row_count
 
 
def verify_csv(csv_path):
    """Kiểm tra nhanh file CSV output."""
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        rows = list(reader)
 
    if not rows:
        print(f"[VERIFY] ⚠️  {csv_path}: không có row dữ liệu!")
        return False
 
    print(f"[VERIFY] {csv_path}: {len(rows)} rows, {len(rows[0])} cột")
 
    # Lấy giá trị min/max entropy_src_ip để kiểm tra
    ent_vals = [float(r['entropy_src_ip']) for r in rows]
    pps_vals = [float(r['pps']) for r in rows]
    print(f"  entropy_src_ip: min={min(ent_vals):.3f}, max={max(ent_vals):.3f}, avg={sum(ent_vals)/len(ent_vals):.3f}")
    print(f"  pps:            min={min(pps_vals):.1f},  max={max(pps_vals):.1f},  avg={sum(pps_vals)/len(pps_vals):.1f}")
    return True
 
 
if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python3 feature_extraction.py <pcap> <output.csv> [window=1.0] [slide=0.5]")
        print("")
        print("Example:")
        print("  python3 code/feature_extraction.py datasets/baseline.pcap datasets/features/baseline.csv")
        sys.exit(1)
 
    pcap_in  = sys.argv[1]
    csv_out  = sys.argv[2]
    win_size = float(sys.argv[3]) if len(sys.argv) > 3 else 1.0
    slide_sz = float(sys.argv[4]) if len(sys.argv) > 4 else 0.5
 
    rows = extract(pcap_in, csv_out, win=win_size, slide=slide_sz)
    if rows and rows > 0:
        verify_csv(csv_out)
