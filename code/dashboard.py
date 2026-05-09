from flask import Flask, render_template, jsonify, request
import os, json, requests, time
from datetime import datetime

app = Flask(__name__)
entropy_history =[]
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
JSON_PATH = os.path.join(_BASE_DIR, "..", "results", "raw", "current_features.json")

# ==========================================
# 1. TRANG CHÍNH - BIỂU ĐỒ ENTROPY
# ==========================================
@app.route('/')
def home(): 
    return render_template('index.html')

@app.route('/api/stats')
def stats(): 
    global entropy_history
    # Mặc định là 3.4 (Safe level) để tránh biểu đồ nhảy xuống 0 khi lỗi đọc file
    current_entropy = 3.4 
    
    try:
        # Kiểm tra file tồn tại và có dữ liệu không
        if os.path.exists(JSON_PATH) and os.path.getsize(JSON_PATH) > 0:
            with open(JSON_PATH, "r") as f:
                features = json.load(f)
                current_entropy = features.get("entropy_src_ip", 3.4)
    except Exception as e:
        print(f"[DASHBOARD ERR] {e}")

    now_ms = int(time.time() * 1000)
    entropy_history.append({"x": now_ms, "y": current_entropy})
    
    # Giữ lại 30 điểm gần nhất cho mượt
    if len(entropy_history) > 30: 
        entropy_history.pop(0)
        
    return jsonify({"entropy": entropy_history})

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