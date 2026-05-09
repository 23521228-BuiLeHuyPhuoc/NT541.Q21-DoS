from flask import Flask, render_template, jsonify, request
import os, json, requests, time, math
from datetime import datetime
from collections import Counter

app = Flask(__name__)
entropy_history = []
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Trạng thái delta cho entropy real-time
_prev_flow_counts = {}

RYU_FLOW_URL = "http://127.0.0.1:8081/stats/flow/2"

def _compute_entropy_from_ryu():
    """Gọi Ryu REST API trực tiếp, tính Shannon entropy từ delta flow stats."""
    global _prev_flow_counts
    
    try:
        resp = requests.get(RYU_FLOW_URL, timeout=2)
        flows = resp.json().get("2", [])
    except Exception as e:
        return 3.4, f"Ryu error: {e}"

    src_ip_counts = Counter()
    current_flow_counts = {}
    
    for flow in flows:
        match = flow.get('match', {})
        pkt_count = flow.get('packet_count', 0)
        
        match_str = str(match)
        current_flow_counts[match_str] = pkt_count
        
        # Delta: chỉ đếm gói TIN MỚI kể từ lần poll trước
        last_count = _prev_flow_counts.get(match_str, 0)
        delta_pkt = pkt_count - last_count if pkt_count >= last_count else pkt_count
        
        if delta_pkt == 0:
            continue
        
        src_ip = match.get('ipv4_src') or match.get('nw_src')
        if src_ip:
            src_ip_counts[src_ip] += delta_pkt

    _prev_flow_counts = current_flow_counts
    
    total = sum(src_ip_counts.values())
    if total > 0:
        entropy = -sum((c/total) * math.log2(c/total) for c in src_ip_counts.values())
        info = f"{len(src_ip_counts)} IPs, {total} pkts/interval"
        return round(entropy, 3), info
    
    return 3.4, "No new packets (idle)"

# ==========================================
# 1. TRANG CHÍNH - BIỂU ĐỒ ENTROPY
# ==========================================
@app.route('/')
def home(): 
    return render_template('index.html')

@app.route('/api/stats')
def stats(): 
    global entropy_history
    
    current_entropy, debug_info = _compute_entropy_from_ryu()

    now_str = datetime.now().strftime('%H:%M:%S')
    entropy_history.append({"label": now_str, "value": current_entropy})
    
    # Giữ lại 30 điểm gần nhất cho mượt
    if len(entropy_history) > 30: 
        entropy_history.pop(0)
    
    labels = [p["label"] for p in entropy_history]
    values = [p["value"] for p in entropy_history]
        
    return jsonify({
        "labels": labels, 
        "values": values,
        "debug_info": debug_info
    })

# ==========================================
# 2. TRANG ALERTS (Danh sách cảnh báo)
# ==========================================
@app.route('/alerts')
def alerts_page():
    alerts_data =[]
    alerts_file = os.path.join(_BASE_DIR, '..', 'results', 'raw', 'alerts.json')
    
    if os.path.exists(alerts_file):
        with open(alerts_file, "r") as f:
            for line in f:
                if line.strip():
                    try:
                        al = json.loads(line)
                        # Xác định hành động (Action) dựa trên rule threshold trong policy.yaml
                        n_rules = al.get("n_rules", 1)
                        if n_rules >= 3 or al.get("severity") == "CRITICAL":
                            action = "Blocked"
                        elif n_rules == 2:
                            action = "Rate-Limited"
                        else:
                            action = "Logged"

                        alerts_data.append({
                            "time": datetime.fromtimestamp(al["timestamp"]).strftime('%H:%M:%S'),
                            "src_ip": al["src_ip"],
                            "attack": al["attack"],
                            "severity": al["severity"],
                            "action": action
                        })
                    except Exception as e: 
                        pass
                        
    # Đảo ngược danh sách để đưa cảnh báo mới nhất lên đầu bảng
    return render_template('alerts.html', alerts=alerts_data[::-1])

# ==========================================
# 3. TRANG FLOWS (Danh sách OpenFlow rules)
# ==========================================
@app.route('/flows')
def flows_page():
    flows_data =[]
    try:
        # Lấy flow thống kê từ Switch s2 (Datapath ID = 2) thông qua Ryu REST API
        resp = requests.get("http://127.0.0.1:8081/stats/flow/2", timeout=2)
        if resp.status_code == 200:
            flows_data = resp.json().get("2", [])
    except Exception as e:
        print(f"[DASHBOARD ERR] Lỗi kết nối đến Ryu: {e}")
        
    return render_template('flows.html', dpid=2, flows=flows_data)

# ==========================================
# 4. ENDPOINT MANUAL BLOCK (Chặn IP thủ công)
# ==========================================
@app.route('/api/block', methods=['POST'])
def manual_block():
    try:
        ip = request.json['src_ip']
        if not ip:
            return jsonify({"ok": False, "error": "Thiếu thông tin IP"})
            
        # Theo policy.yaml, hệ thống yêu cầu threshold=3 mới thực hiện Block (cấp độ 3)
        # Do đó chúng ta gửi ép 3 requests liên tiếp sang Ryu Controller để đạt mức Block ngay lập tức.
        for _ in range(3):
            requests.post('http://127.0.0.1:8081/api/alert',
                          json={"src_ip": ip, "attack": "manual_block", "severity": "CRITICAL"}, 
                          timeout=1)
            time.sleep(0.1)
            
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

# ==========================================
# KHỞI CHẠY FLASK SERVER
# ==========================================
if __name__ == '__main__':
    # Chạy trên mọi interface (0.0.0.0) cổng 8080
    app.run(host='0.0.0.0', port=8080, debug=True)