from flask import Flask, render_template, jsonify, request
import os, json, requests, time, random
from datetime import datetime

app = Flask(__name__)

@app.route('/')
def home(): 
    return render_template('index.html')

@app.route('/api/stats')
def stats(): 
    # MÔ PHỎNG INFLUXDB CHO VIDEO DEMO:
    # Nếu có cảnh báo trong 20s gần nhất -> Entropy giảm xuống 1.0 - 1.5
    # Nếu bình thường -> Entropy dao động ổn định 3.4 - 3.8
    is_attack = False
    log_path = "results/raw/alerts.json"
    if os.path.exists(log_path):
        try:
            with open(log_path, 'r') as f:
                lines = [l for l in f if l.strip()]
                if lines:
                    last_alert = json.loads(lines[-1])
                    if time.time() - last_alert.get("timestamp", 0) < 20:
                        is_attack = True
        except: pass

    entropy_data =[]
    now_ms = int(time.time() * 1000)
    # Sinh 20 điểm dữ liệu giả lập cho biểu đồ kéo dài mượt mà
    for i in range(20, -1, -1):
        ts = now_ms - (i * 2000)
        val = random.uniform(1.0, 1.5) if is_attack else random.uniform(3.4, 3.8)
        entropy_data.append({"x": ts, "y": val})
        
    return jsonify({"entropy": entropy_data, "pps": []})

@app.route('/alerts')
def alerts():
    alert_list =[]
    log_path = "results/raw/alerts.json"
    
    if os.path.exists(log_path):
        with open(log_path, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        data = json.loads(line)
                        dt = datetime.fromtimestamp(data.get("timestamp", 0))
                        data["time"] = dt.strftime("%Y-%m-%d %H:%M:%S")
                        
                        sev = data.get("severity", "")
                        if sev == "CRITICAL" or sev == "critical_repeat": 
                            data["action"] = "BLOCK"
                        elif sev == "WARN": 
                            data["action"] = "RATE_LIMIT"
                        else: 
                            data["action"] = "LOG"
                            
                        alert_list.append(data)
                    except: pass
                        
    alert_list.reverse()
    return render_template('alerts.html', alerts=alert_list)

@app.route('/flows')
def flows():
    dpid = request.args.get('dpid', '2')
    flows_data =[]
    try:
        # CẬP NHẬT GỌI ĐÚNG CỔNG 8081 CỦA RYU CONTROLLER
        url = f'http://127.0.0.1:8081/stats/flow/{dpid}'
        r = requests.get(url, timeout=2)
        if r.status_code == 200:
            flows_data = r.json().get(dpid,[])
    except Exception as e:
        print(f"Loi goi Ryu API: {e}")
        
    return render_template('flows.html', flows=flows_data, dpid=dpid)

@app.route('/api/block', methods=['POST'])
def manual_block():
    try:
        ip = request.json['src_ip']
        # Gửi 3 Alert liên tiếp để ép Graduated Response nhảy thẳng lên Cấp 3 (Block Drop)
        for _ in range(3):
            requests.post('http://127.0.0.1:8081/api/alert', 
                          json={"src_ip": ip, "severity": "critical_repeat"})
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)