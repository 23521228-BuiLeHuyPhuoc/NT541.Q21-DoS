#!/usr/bin/env python3
"""
analyze_benchmark.py — Phan tich ket qua benchmark tu run_benchmark.sh
Tao bang tong hop, bieu do va bao cao chi tiet cho bao cao.

Cach dung:
    python3 code/analyze_benchmark.py
"""
import os, json, sys
from collections import defaultdict
from datetime import datetime
import numpy as np

# Matplotlib backend khong can GUI (cho VM khong co display)
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BENCHMARK_DIR = os.path.join(BASE_DIR, '..', 'results', 'benchmark')
REPORT_PATH = os.path.join(BASE_DIR, '..', 'results', 'benchmark_report.md')
CHARTS_DIR = os.path.join(BASE_DIR, '..', 'results', 'charts')

# Ket qua mong doi cho tung kich ban
EXPECTED = {
    "s01_syn":       {"attack": True,  "type": "s01_syn_flood",  "block": "IP",  "entropy": "low",  "pps": "high"},
    "s02_udp":       {"attack": True,  "type": "s02_udp_flood",  "block": "IP",  "entropy": "low",  "pps": "high"},
    "s03_icmp":      {"attack": True,  "type": "s03_icmp_flood", "block": "IP",  "entropy": "low",  "pps": "high"},
    "s04_http":      {"attack": True,  "type": "s04_http_flood", "block": "IP",  "entropy": "low",  "pps": "medium"},
    "s05_dns_ampl":  {"attack": True,  "type": "s05_dns_ampl",   "block": "MAC", "entropy": "high", "pps": "medium"},
    "s06_ip_spoof":  {"attack": True,  "type": "s06_spoof",      "block": "MAC", "entropy": "high", "pps": "medium"},
    "s07_slowloris": {"attack": True,  "type": "s07_slowloris",  "block": "IP",  "entropy": "low",  "pps": "low"},
    "s08_flash_crowd":{"attack": False, "type": "none",          "block": "none","entropy": "medium","pps": "low"},
}

def load_metrics(scenario_dir):
    """Doc file metrics.jsonl"""
    metrics = []
    metrics_file = os.path.join(scenario_dir, 'metrics.jsonl')
    if not os.path.exists(metrics_file):
        return metrics
    with open(metrics_file) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    metrics.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return metrics

def load_alerts(scenario_dir):
    """Doc file alerts_after.json"""
    alerts_file = os.path.join(scenario_dir, 'alerts_after.json')
    alerts = []
    if os.path.exists(alerts_file):
        with open(alerts_file) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        alerts.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    return alerts

def analyze_scenario(scenario_id, scenario_dir):
    """Phan tich 1 kich ban"""
    metrics = load_metrics(scenario_dir)
    alerts = load_alerts(scenario_dir)
    metadata_file = os.path.join(scenario_dir, 'metadata.json')
    
    metadata = {}
    if os.path.exists(metadata_file):
        with open(metadata_file) as f:
            metadata = json.load(f)
    
    # Phan loai metrics theo giai doan
    baseline_metrics = [m for m in metrics if m.get('label', '').startswith('baseline')]
    attack_metrics = [m for m in metrics if m.get('label', '').startswith('attack')]
    post_metrics = [m for m in metrics if m.get('label', '').startswith('post_attack')]
    
    result = {
        "id": scenario_id,
        "name": metadata.get("name", scenario_id),
        "timestamp": metadata.get("timestamp", ""),
        "total_metrics": len(metrics),
        "total_alerts": len(alerts),
    }
    
    # --- Phan tich Entropy ---
    def get_entropy_values(metric_list):
        values = []
        for m in metric_list:
            # Uu tien lay tu features (detector output)
            feat = m.get('features', {})
            ryu = m.get('ryu', {})
            e = feat.get('entropy_realtime') or feat.get('entropy_src') or ryu.get('entropy', 0)
            if e is not None:
                values.append(float(e))
        return values
    
    baseline_entropy = get_entropy_values(baseline_metrics)
    attack_entropy = get_entropy_values(attack_metrics)
    post_entropy = get_entropy_values(post_metrics)
    
    result["entropy"] = {
        "baseline_avg": round(sum(baseline_entropy) / max(len(baseline_entropy), 1), 4),
        "attack_avg": round(sum(attack_entropy) / max(len(attack_entropy), 1), 4),
        "attack_min": round(min(attack_entropy) if attack_entropy else 0, 4),
        "attack_max": round(max(attack_entropy) if attack_entropy else 0, 4),
        "post_avg": round(sum(post_entropy) / max(len(post_entropy), 1), 4),
    }
    
    # --- Phan tich PPS ---
    def get_pps_values(metric_list):
        values = []
        for m in metric_list:
            feat = m.get('features', {})
            ryu = m.get('ryu', {})
            p = feat.get('pps') or ryu.get('packet_rate', 0)
            if p is not None:
                values.append(float(p))
        return values
    
    baseline_pps = get_pps_values(baseline_metrics)
    attack_pps = get_pps_values(attack_metrics)
    
    result["pps"] = {
        "baseline_avg": round(sum(baseline_pps) / max(len(baseline_pps), 1), 1),
        "attack_avg": round(sum(attack_pps) / max(len(attack_pps), 1), 1),
        "attack_max": round(max(attack_pps) if attack_pps else 0, 1),
    }
    
    # --- Phan tich Protocol ---
    def get_protocol_pcts(metric_list):
        tcp = [m.get('features', {}).get('tcp_pct', 0) for m in metric_list]
        udp = [m.get('features', {}).get('udp_pct', 0) for m in metric_list]
        icmp = [m.get('features', {}).get('icmp_pct', 0) for m in metric_list]
        syn = [m.get('features', {}).get('syn_pct', 0) for m in metric_list]
        return {
            "tcp_avg": round(sum(tcp) / max(len(tcp), 1), 3),
            "udp_avg": round(sum(udp) / max(len(udp), 1), 3),
            "icmp_avg": round(sum(icmp) / max(len(icmp), 1), 3),
            "syn_avg": round(sum(syn) / max(len(syn), 1), 3),
        }
    
    result["protocol"] = get_protocol_pcts(attack_metrics)
    
    # --- Phan tich Blocked IPs/MACs ---
    blocked_ips = set()
    blocked_macs = set()
    for m in attack_metrics + post_metrics:
        ryu = m.get('ryu', {})
        for ip in ryu.get('blocked_ips', []):
            blocked_ips.add(ip)
        for mac in ryu.get('blocked_macs', []):
            blocked_macs.add(mac)
    
    result["mitigation"] = {
        "blocked_ips": list(blocked_ips),
        "blocked_macs": list(blocked_macs),
        "total_blocked_ips": len(blocked_ips),
        "total_blocked_macs": len(blocked_macs),
    }
    
    # --- Phan tich Alerts ---
    attack_types_detected = set()
    actions_taken = set()
    for a in alerts:
        attack_types_detected.add(a.get('attack', 'unknown'))
        actions_taken.add(a.get('action', 'unknown'))
    
    result["detection"] = {
        "detected": len(alerts) > 0,
        "attack_types": list(attack_types_detected),
        "actions": list(actions_taken),
        "alert_count": len(alerts),
    }
    
    # --- Phan tich Unique IPs ---
    unique_ips_list = [m.get('features', {}).get('unique_ips', 0) for m in attack_metrics]
    result["unique_ips"] = {
        "avg": round(sum(unique_ips_list) / max(len(unique_ips_list), 1), 1),
        "max": max(unique_ips_list) if unique_ips_list else 0,
    }
    
    # --- Phan tich Flow count ---
    flow_counts = [m.get('flow_count', 0) for m in attack_metrics]
    result["flows"] = {
        "avg": round(sum(flow_counts) / max(len(flow_counts), 1), 1),
        "max": max(flow_counts) if flow_counts else 0,
    }
    
    # --- Thoi gian phat hien ---
    if alerts:
        first_alert_time = min(a.get('timestamp', 9999999999) for a in alerts)
        attack_start = metadata.get('attack_start', first_alert_time)
        detection_time = round(first_alert_time - attack_start, 1)
        result["detection_time_sec"] = max(0, detection_time)
    else:
        result["detection_time_sec"] = None
    
    # --- Kiem tra ket qua voi mong doi ---
    expected = EXPECTED.get(scenario_id, {})
    result["expected"] = expected
    result["match"] = {
        "detected_correct": result["detection"]["detected"] == expected.get("attack", True),
    }
    
    return result

def generate_report(results):
    """Tao bao cao Markdown"""
    lines = []
    lines.append("# Báo cáo Benchmark — Hệ thống SDN DDoS Detection & Mitigation\n")
    lines.append(f"**Thời gian chạy:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    lines.append(f"**Tổng số kịch bản:** {len(results)}\n")
    lines.append("---\n")
    
    # =========================================
    # BANG TONG HOP
    # =========================================
    lines.append("## 1. Bảng tổng hợp kết quả\n")
    lines.append("| Kịch bản | Entropy (TB) | PPS (TB) | PPS (Max) | Phát hiện | Loại phát hiện | Chặn IP | Chặn MAC | Thời gian PH (s) |")
    lines.append("|----------|-------------|---------|----------|-----------|---------------|---------|---------|-----------------|")
    
    for r in results:
        detected = "✅" if r["detection"]["detected"] else "❌"
        attack_types = ", ".join(r["detection"]["attack_types"]) if r["detection"]["attack_types"] else "—"
        blocked_ips = ", ".join(r["mitigation"]["blocked_ips"]) if r["mitigation"]["blocked_ips"] else "—"
        blocked_macs = ", ".join(r["mitigation"]["blocked_macs"]) if r["mitigation"]["blocked_macs"] else "—"
        det_time = str(r["detection_time_sec"]) if r["detection_time_sec"] is not None else "—"
        
        lines.append(f"| {r['name']} | {r['entropy']['attack_avg']} | {r['pps']['attack_avg']} | {r['pps']['attack_max']} | {detected} | {attack_types} | {blocked_ips} | {blocked_macs} | {det_time} |")
    
    lines.append("")
    
    # =========================================
    # BANG PROTOCOL
    # =========================================
    lines.append("## 2. Phân tích Protocol\n")
    lines.append("| Kịch bản | TCP (%) | UDP (%) | ICMP (%) | SYN (%) |")
    lines.append("|----------|---------|---------|----------|---------|")
    
    for r in results:
        p = r["protocol"]
        lines.append(f"| {r['name']} | {p['tcp_avg']} | {p['udp_avg']} | {p['icmp_avg']} | {p['syn_avg']} |")
    
    lines.append("")
    
    # =========================================
    # BANG ENTROPY CHI TIET
    # =========================================
    lines.append("## 3. Phân tích Entropy\n")
    lines.append("| Kịch bản | Baseline | Tấn công (TB) | Tấn công (Min) | Tấn công (Max) | Sau tấn công |")
    lines.append("|----------|----------|--------------|----------------|----------------|-------------|")
    
    for r in results:
        e = r["entropy"]
        lines.append(f"| {r['name']} | {e['baseline_avg']} | {e['attack_avg']} | {e['attack_min']} | {e['attack_max']} | {e['post_avg']} |")
    
    lines.append("")
    
    # =========================================
    # BANG MITIGATION
    # =========================================
    lines.append("## 4. Phân tích Mitigation\n")
    lines.append("| Kịch bản | Số IP bị chặn | Số MAC bị chặn | Số alert | Actions |")
    lines.append("|----------|--------------|----------------|----------|---------|")
    
    for r in results:
        actions = ", ".join(r["detection"]["actions"]) if r["detection"]["actions"] else "—"
        lines.append(f"| {r['name']} | {r['mitigation']['total_blocked_ips']} | {r['mitigation']['total_blocked_macs']} | {r['detection']['alert_count']} | {actions} |")
    
    lines.append("")
    
    # =========================================
    # BANG DO CHINH XAC
    # =========================================
    lines.append("## 5. Đánh giá độ chính xác\n")
    
    tp = fp = tn = fn = 0
    for r in results:
        expected_attack = r["expected"].get("attack", True)
        actual_detected = r["detection"]["detected"]
        
        if expected_attack and actual_detected:
            tp += 1
        elif not expected_attack and not actual_detected:
            tn += 1
        elif not expected_attack and actual_detected:
            fp += 1
        elif expected_attack and not actual_detected:
            fn += 1
    
    total = tp + tn + fp + fn
    accuracy = round((tp + tn) / max(total, 1) * 100, 1)
    precision = round(tp / max(tp + fp, 1) * 100, 1)
    recall = round(tp / max(tp + fn, 1) * 100, 1)
    f1 = round(2 * precision * recall / max(precision + recall, 1), 1)
    
    lines.append("| Metric | Giá trị |")
    lines.append("|--------|---------|")
    lines.append(f"| True Positive (TP) | {tp} |")
    lines.append(f"| True Negative (TN) | {tn} |")
    lines.append(f"| False Positive (FP) | {fp} |")
    lines.append(f"| False Negative (FN) | {fn} |")
    lines.append(f"| **Accuracy** | **{accuracy}%** |")
    lines.append(f"| **Precision** | **{precision}%** |")
    lines.append(f"| **Recall** | **{recall}%** |")
    lines.append(f"| **F1-Score** | **{f1}%** |")
    
    lines.append("")
    
    lines.append("### Confusion Matrix\n")
    lines.append("|  | Predicted Attack | Predicted Normal |")
    lines.append("|--|-----------------|-----------------|")
    lines.append(f"| **Actual Attack** | TP = {tp} | FN = {fn} |")
    lines.append(f"| **Actual Normal** | FP = {fp} | TN = {tn} |")
    
    lines.append("")
    
    # =========================================
    # CHI TIET TUNG KICH BAN
    # =========================================
    lines.append("---\n")
    lines.append("## 6. Chi tiết từng kịch bản\n")
    
    for r in results:
        lines.append(f"### {r['name']} (`{r['id']}`)\n")
        
        expected = r["expected"]
        match_icon = "✅" if r["match"]["detected_correct"] else "❌"
        
        lines.append(f"- **Kết quả phát hiện:** {match_icon} {'Phát hiện' if r['detection']['detected'] else 'Không phát hiện'} (mong đợi: {'Phát hiện' if expected.get('attack') else 'Không phát hiện'})")
        lines.append(f"- **Loại tấn công phát hiện:** {', '.join(r['detection']['attack_types']) or 'Không'}")
        lines.append(f"- **Entropy trung bình (khi tấn công):** {r['entropy']['attack_avg']}")
        lines.append(f"- **PPS trung bình:** {r['pps']['attack_avg']} | PPS max: {r['pps']['attack_max']}")
        lines.append(f"- **Protocol:** TCP={r['protocol']['tcp_avg']}, UDP={r['protocol']['udp_avg']}, ICMP={r['protocol']['icmp_avg']}")
        lines.append(f"- **IP bị chặn:** {', '.join(r['mitigation']['blocked_ips']) or 'Không'}")
        lines.append(f"- **MAC bị chặn:** {', '.join(r['mitigation']['blocked_macs']) or 'Không'}")
        lines.append(f"- **Unique IPs:** avg={r['unique_ips']['avg']}, max={r['unique_ips']['max']}")
        
        if r["detection_time_sec"] is not None:
            lines.append(f"- **Thời gian phát hiện:** {r['detection_time_sec']}s sau khi bắt đầu tấn công")
        
        lines.append("")
    
    # =========================================
    # KET LUAN
    # =========================================
    lines.append("---\n")
    lines.append("## 7. Kết luận\n")
    lines.append(f"- Hệ thống đạt **Accuracy = {accuracy}%**, **F1-Score = {f1}%** trên {len(results)} kịch bản test.")
    lines.append(f"- **True Positive:** {tp}/{tp+fn} kịch bản tấn công được phát hiện chính xác.")
    lines.append(f"- **True Negative:** {tn}/{tn+fp} kịch bản bình thường không bị báo nhầm.")
    
    if fp > 0:
        lines.append(f"- ⚠️ **False Positive:** {fp} trường hợp traffic bình thường bị nhận nhầm là tấn công.")
    if fn > 0:
        lines.append(f"- ⚠️ **False Negative:** {fn} trường hợp tấn công không được phát hiện.")
    
    lines.append(f"- Hệ thống sử dụng **3 cấp mitigation** (Log → Rate-Limit → Block) cho phản ứng linh hoạt.")
    lines.append(f"- Tấn công IP Spoofing/DNS Amplification được xử lý bằng **chặn MAC** (thay vì IP giả mạo).")
    lines.append("")
    
    return "\n".join(lines)

def main():
    if not os.path.exists(BENCHMARK_DIR):
        print(f"[ERROR] Khong tim thay thu muc benchmark: {BENCHMARK_DIR}")
        print("        Hay chay 'bash code/run_benchmark.sh' truoc.")
        sys.exit(1)
    
    # Doc tat ca kich ban
    scenarios = sorted([d for d in os.listdir(BENCHMARK_DIR) 
                       if os.path.isdir(os.path.join(BENCHMARK_DIR, d))])
    
    if not scenarios:
        print("[ERROR] Khong co kich ban nao trong thu muc benchmark.")
        sys.exit(1)
    
    print(f"[ANALYZE] Tim thay {len(scenarios)} kich ban: {', '.join(scenarios)}")
    
    results = []
    for scenario_id in scenarios:
        scenario_dir = os.path.join(BENCHMARK_DIR, scenario_id)
        print(f"  Phan tich {scenario_id}...")
        r = analyze_scenario(scenario_id, scenario_dir)
        results.append(r)
        
        # In tom tat nhanh
        detected = "✅ Phat hien" if r["detection"]["detected"] else "❌ Khong phat hien"
        print(f"    {detected} | Entropy={r['entropy']['attack_avg']} | PPS={r['pps']['attack_avg']}")
    
    # Tao bao cao
    report = generate_report(results)
    with open(REPORT_PATH, 'w', encoding='utf-8') as f:
        f.write(report)
    print(f"\n[DONE] Bao cao luu tai: {REPORT_PATH}")
    
    # Luu raw JSON
    json_path = os.path.join(BENCHMARK_DIR, 'summary.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"[DONE] Raw data luu tai: {json_path}")
    
    # Tao bieu do
    print("\n[CHARTS] Dang tao bieu do...")
    generate_charts(results)
    
    # In bang tom tat ra console
    print("\n" + "=" * 80)
    print("  BANG TOM TAT")
    print("=" * 80)
    print(f"{'Kich ban':<20} {'Entropy':>8} {'PPS':>8} {'Phat hien':>12} {'Loai':>20}")
    print("-" * 80)
    for r in results:
        detected = "✅" if r["detection"]["detected"] else "❌"
        types = ", ".join(r["detection"]["attack_types"])[:20] or "—"
        print(f"{r['name']:<20} {r['entropy']['attack_avg']:>8} {r['pps']['attack_avg']:>8} {detected:>12} {types:>20}")
    
    # In do chinh xac
    tp = sum(1 for r in results if r["expected"].get("attack") and r["detection"]["detected"])
    tn = sum(1 for r in results if not r["expected"].get("attack") and not r["detection"]["detected"])
    fp = sum(1 for r in results if not r["expected"].get("attack") and r["detection"]["detected"])
    fn = sum(1 for r in results if r["expected"].get("attack") and not r["detection"]["detected"])
    total = tp + tn + fp + fn
    accuracy = round((tp + tn) / max(total, 1) * 100, 1)
    
    print("-" * 80)
    print(f"  TP={tp} TN={tn} FP={fp} FN={fn} | Accuracy={accuracy}%")
    print("=" * 80)

# =============================================================
# CHART GENERATION
# =============================================================

def generate_charts(results):
    """Tao toan bo bieu do PNG tu ket qua benchmark."""
    os.makedirs(CHARTS_DIR, exist_ok=True)
    
    names = [r['id'].replace('_', '\n') for r in results]
    short_names = [r['id'] for r in results]
    
    # Style chung
    plt.rcParams.update({
        'figure.facecolor': '#1a1a2e',
        'axes.facecolor': '#16213e',
        'axes.edgecolor': '#e94560',
        'axes.labelcolor': 'white',
        'text.color': 'white',
        'xtick.color': 'white',
        'ytick.color': 'white',
        'grid.color': '#333355',
        'grid.alpha': 0.5,
        'font.size': 11,
    })
    
    chart_1_entropy(results, names)
    chart_2_pps(results, names)
    chart_3_protocol(results, short_names)
    chart_4_confusion_matrix(results)
    chart_5_detection_summary(results, short_names)
    chart_6_timeline(results, short_names)
    
    print(f"[CHARTS] 6 bieu do da luu tai: {CHARTS_DIR}/")


def chart_1_entropy(results, names):
    """Bieu do 1: So sanh Entropy giua cac kich ban."""
    fig, ax = plt.subplots(figsize=(12, 6))
    
    x = np.arange(len(results))
    width = 0.25
    
    baseline = [r['entropy']['baseline_avg'] for r in results]
    attack = [r['entropy']['attack_avg'] for r in results]
    post = [r['entropy']['post_avg'] for r in results]
    
    bars1 = ax.bar(x - width, baseline, width, label='Baseline', color='#0f3460', edgecolor='white', linewidth=0.5)
    bars2 = ax.bar(x, attack, width, label='Khi tan cong', color='#e94560', edgecolor='white', linewidth=0.5)
    bars3 = ax.bar(x + width, post, width, label='Sau tan cong', color='#53d769', edgecolor='white', linewidth=0.5)
    
    # Ghi gia tri len cot
    for bar in bars2:
        height = bar.get_height()
        ax.annotate(f'{height:.2f}', xy=(bar.get_x() + bar.get_width()/2, height),
                    xytext=(0, 3), textcoords='offset points', ha='center', fontsize=8, color='#e94560')
    
    ax.set_xlabel('Kich ban')
    ax.set_ylabel('Shannon Entropy')
    ax.set_title('So sanh Entropy giua cac kich ban tan cong', fontsize=14, fontweight='bold', color='#e94560')
    ax.set_xticks(x)
    ax.set_xticklabels(names, fontsize=8)
    ax.legend(loc='upper left')
    ax.grid(axis='y')
    ax.set_ylim(bottom=0)
    
    plt.tight_layout()
    plt.savefig(os.path.join(CHARTS_DIR, '1_entropy_comparison.png'), dpi=150)
    plt.close()
    print("  [OK] 1_entropy_comparison.png")


def chart_2_pps(results, names):
    """Bieu do 2: So sanh PPS giua cac kich ban."""
    fig, ax = plt.subplots(figsize=(12, 6))
    
    x = np.arange(len(results))
    width = 0.35
    
    avg_pps = [r['pps']['attack_avg'] for r in results]
    max_pps = [r['pps']['attack_max'] for r in results]
    
    bars1 = ax.bar(x - width/2, avg_pps, width, label='PPS Trung binh', color='#e94560', edgecolor='white', linewidth=0.5)
    bars2 = ax.bar(x + width/2, max_pps, width, label='PPS Cao nhat', color='#f5a623', edgecolor='white', linewidth=0.5)
    
    for bar in bars1:
        height = bar.get_height()
        if height > 0:
            ax.annotate(f'{height:.0f}', xy=(bar.get_x() + bar.get_width()/2, height),
                        xytext=(0, 3), textcoords='offset points', ha='center', fontsize=8, color='#e94560')
    
    ax.set_xlabel('Kich ban')
    ax.set_ylabel('Packets Per Second (PPS)')
    ax.set_title('So sanh PPS giua cac kich ban tan cong', fontsize=14, fontweight='bold', color='#f5a623')
    ax.set_xticks(x)
    ax.set_xticklabels(names, fontsize=8)
    ax.legend()
    ax.grid(axis='y')
    ax.set_ylim(bottom=0)
    
    plt.tight_layout()
    plt.savefig(os.path.join(CHARTS_DIR, '2_pps_comparison.png'), dpi=150)
    plt.close()
    print("  [OK] 2_pps_comparison.png")


def chart_3_protocol(results, short_names):
    """Bieu do 3: Phan bo Protocol (stacked bar)."""
    fig, ax = plt.subplots(figsize=(12, 6))
    
    x = np.arange(len(results))
    
    tcp = [r['protocol']['tcp_avg'] for r in results]
    udp = [r['protocol']['udp_avg'] for r in results]
    icmp = [r['protocol']['icmp_avg'] for r in results]
    
    ax.bar(x, tcp, label='TCP', color='#e94560', edgecolor='white', linewidth=0.5)
    ax.bar(x, udp, bottom=tcp, label='UDP', color='#0f3460', edgecolor='white', linewidth=0.5)
    bottom_icmp = [t + u for t, u in zip(tcp, udp)]
    ax.bar(x, icmp, bottom=bottom_icmp, label='ICMP', color='#53d769', edgecolor='white', linewidth=0.5)
    
    ax.set_xlabel('Kich ban')
    ax.set_ylabel('Ty le (%)')
    ax.set_title('Phan bo Protocol trong moi kich ban', fontsize=14, fontweight='bold', color='#53d769')
    ax.set_xticks(x)
    ax.set_xticklabels(short_names, fontsize=9, rotation=30, ha='right')
    ax.legend()
    ax.grid(axis='y')
    ax.set_ylim(0, 1.1)
    
    plt.tight_layout()
    plt.savefig(os.path.join(CHARTS_DIR, '3_protocol_distribution.png'), dpi=150)
    plt.close()
    print("  [OK] 3_protocol_distribution.png")


def chart_4_confusion_matrix(results):
    """Bieu do 4: Confusion Matrix heatmap."""
    tp = sum(1 for r in results if r["expected"].get("attack") and r["detection"]["detected"])
    tn = sum(1 for r in results if not r["expected"].get("attack") and not r["detection"]["detected"])
    fp = sum(1 for r in results if not r["expected"].get("attack") and r["detection"]["detected"])
    fn = sum(1 for r in results if r["expected"].get("attack") and not r["detection"]["detected"])
    
    total = tp + tn + fp + fn
    accuracy = round((tp + tn) / max(total, 1) * 100, 1)
    precision = round(tp / max(tp + fp, 1) * 100, 1)
    recall = round(tp / max(tp + fn, 1) * 100, 1)
    f1 = round(2 * precision * recall / max(precision + recall, 1), 1)
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5),
                                    gridspec_kw={'width_ratios': [1, 1.2]})
    
    # Confusion Matrix
    cm = np.array([[tp, fn], [fp, tn]])
    im = ax1.imshow(cm, cmap='RdYlGn', aspect='auto')
    
    labels = [['TP\n(Tan cong\nphat hien dung)', 'FN\n(Tan cong\nkhong phat hien)'],
              ['FP\n(Binh thuong\nbao nham)', 'TN\n(Binh thuong\ndung)']]
    
    for i in range(2):
        for j in range(2):
            color = 'white' if cm[i][j] < 3 else 'black'
            ax1.text(j, i, f"{labels[i][j]}\n{cm[i][j]}",
                     ha='center', va='center', fontsize=11, fontweight='bold', color=color)
    
    ax1.set_xticks([0, 1])
    ax1.set_yticks([0, 1])
    ax1.set_xticklabels(['Predicted\nAttack', 'Predicted\nNormal'])
    ax1.set_yticklabels(['Actual\nAttack', 'Actual\nNormal'])
    ax1.set_title('Confusion Matrix', fontsize=13, fontweight='bold', color='#e94560')
    
    # Metrics bar chart
    metrics = {'Accuracy': accuracy, 'Precision': precision, 'Recall': recall, 'F1-Score': f1}
    bars = ax2.barh(list(metrics.keys()), list(metrics.values()),
                     color=['#e94560', '#f5a623', '#53d769', '#0f3460'],
                     edgecolor='white', linewidth=0.5, height=0.5)
    
    for bar, val in zip(bars, metrics.values()):
        ax2.text(bar.get_width() + 1, bar.get_y() + bar.get_height()/2,
                 f'{val}%', ha='left', va='center', fontweight='bold', fontsize=12)
    
    ax2.set_xlim(0, 110)
    ax2.set_title('Do chinh xac phat hien', fontsize=13, fontweight='bold', color='#f5a623')
    ax2.set_xlabel('%')
    ax2.grid(axis='x')
    
    plt.tight_layout()
    plt.savefig(os.path.join(CHARTS_DIR, '4_confusion_matrix.png'), dpi=150)
    plt.close()
    print("  [OK] 4_confusion_matrix.png")


def chart_5_detection_summary(results, short_names):
    """Bieu do 5: Tong hop ket qua phat hien (detected vs expected)."""
    fig, ax = plt.subplots(figsize=(12, 6))
    
    x = np.arange(len(results))
    
    colors = []
    labels_text = []
    for r in results:
        expected = r["expected"].get("attack", True)
        detected = r["detection"]["detected"]
        
        if expected and detected:
            colors.append('#53d769')  # TP - xanh
            labels_text.append('TP')
        elif not expected and not detected:
            colors.append('#53d769')  # TN - xanh
            labels_text.append('TN')
        elif not expected and detected:
            colors.append('#e94560')  # FP - do
            labels_text.append('FP')
        else:
            colors.append('#f5a623')  # FN - vang
            labels_text.append('FN')
    
    # Bar heights = 1 cho moi kich ban, mau sac the hien ket qua
    det_times = []
    for r in results:
        dt = r.get('detection_time_sec')
        det_times.append(dt if dt is not None else 0)
    
    bars = ax.bar(x, [1]*len(results), color=colors, edgecolor='white', linewidth=1.5, width=0.6)
    
    for i, (bar, label, r) in enumerate(zip(bars, labels_text, results)):
        # Label TP/TN/FP/FN
        ax.text(bar.get_x() + bar.get_width()/2, 0.5, label,
                ha='center', va='center', fontweight='bold', fontsize=14, color='white')
        # Attack type
        atypes = ", ".join(r["detection"]["attack_types"]) or "None"
        ax.text(bar.get_x() + bar.get_width()/2, 0.15, atypes[:18],
                ha='center', va='center', fontsize=7, color='white', alpha=0.8)
        # Detection time
        dt = r.get('detection_time_sec')
        if dt is not None:
            ax.text(bar.get_x() + bar.get_width()/2, 0.85, f'{dt}s',
                    ha='center', va='center', fontsize=9, color='white')
    
    ax.set_xticks(x)
    ax.set_xticklabels(short_names, fontsize=9, rotation=30, ha='right')
    ax.set_yticks([])
    ax.set_title('Tong hop ket qua phat hien (Xanh=Dung, Do=Sai)', fontsize=14, fontweight='bold', color='white')
    
    # Legend
    legend_elements = [
        mpatches.Patch(facecolor='#53d769', edgecolor='white', label='Dung (TP/TN)'),
        mpatches.Patch(facecolor='#e94560', edgecolor='white', label='False Positive (FP)'),
        mpatches.Patch(facecolor='#f5a623', edgecolor='white', label='False Negative (FN)'),
    ]
    ax.legend(handles=legend_elements, loc='upper right')
    
    plt.tight_layout()
    plt.savefig(os.path.join(CHARTS_DIR, '5_detection_summary.png'), dpi=150)
    plt.close()
    print("  [OK] 5_detection_summary.png")


def chart_6_timeline(results, short_names):
    """Bieu do 6: Entropy + PPS theo thoi gian cho tung kich ban."""
    n = len(results)
    fig, axes = plt.subplots(n, 1, figsize=(14, 3 * n), sharex=False)
    if n == 1:
        axes = [axes]
    
    for idx, (ax, r) in enumerate(zip(axes, results)):
        scenario_dir = os.path.join(BENCHMARK_DIR, r['id'])
        metrics = load_metrics(scenario_dir)
        
        if not metrics:
            ax.text(0.5, 0.5, 'Khong co du lieu', ha='center', va='center',
                    transform=ax.transAxes, fontsize=12, color='gray')
            ax.set_title(f"{r['id']} — {r['name']}", fontsize=11, color='#e94560')
            continue
        
        timestamps = list(range(len(metrics)))
        
        entropy_vals = []
        pps_vals = []
        for m in metrics:
            feat = m.get('features', {})
            ryu = m.get('ryu', {})
            e = feat.get('entropy_realtime') or feat.get('entropy_src') or ryu.get('entropy', 0)
            p = feat.get('pps') or ryu.get('packet_rate', 0)
            entropy_vals.append(float(e) if e else 0)
            pps_vals.append(float(p) if p else 0)
        
        # Entropy (ax trai)
        color_e = '#e94560'
        ax.plot(timestamps, entropy_vals, color=color_e, linewidth=2, label='Entropy')
        ax.set_ylabel('Entropy', color=color_e, fontsize=9)
        ax.tick_params(axis='y', labelcolor=color_e)
        ax.set_ylim(bottom=0)
        
        # PPS (ax phai)
        ax2 = ax.twinx()
        color_p = '#53d769'
        ax2.plot(timestamps, pps_vals, color=color_p, linewidth=1.5, linestyle='--', label='PPS')
        ax2.set_ylabel('PPS', color=color_p, fontsize=9)
        ax2.tick_params(axis='y', labelcolor=color_p)
        ax2.set_ylim(bottom=0)
        
        # Danh dau vung tan cong (giay 5 den 25)
        baseline_end = 5
        attack_end = 5 + 20
        ax.axvspan(0, baseline_end, alpha=0.1, color='blue', label='Baseline')
        ax.axvspan(baseline_end, min(attack_end, len(timestamps)), alpha=0.15, color='red', label='Tan cong')
        if attack_end < len(timestamps):
            ax.axvspan(attack_end, len(timestamps), alpha=0.1, color='green', label='Phuc hoi')
        
        # Detected?
        detected_icon = '✅' if r['detection']['detected'] else '❌'
        title_color = '#e94560' if r['detection']['detected'] else '#53d769'
        ax.set_title(f"{r['id']} — {r['name']} {detected_icon}", fontsize=11, color=title_color, fontweight='bold')
        ax.grid(alpha=0.3)
    
    plt.xlabel('Thoi gian (giay)')
    plt.tight_layout()
    plt.savefig(os.path.join(CHARTS_DIR, '6_timeline_all.png'), dpi=150)
    plt.close()
    print("  [OK] 6_timeline_all.png")


if __name__ == "__main__":
    main()
