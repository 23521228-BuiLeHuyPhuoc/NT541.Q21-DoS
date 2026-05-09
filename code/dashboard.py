from flask import Flask, render_template, jsonify, request
import os, json, requests, time
from datetime import datetime

app = Flask(__name__)

# Bien toan cuc de luu lich su bieu do entropy
entropy_history = []

@app.route('/')
def home(): 
    return render_template('index.html')

@app.route('/api/stats')
def stats(): 
    global entropy_history
    current_entropy = 3.4
    
    # Doc du lieu that do detector.py ghi ra thay vi dung random
    try:
        if os.path.exists("results/raw/current_features.json"):
            with open("results/raw/current_features.json", "r") as f:
                features = json.load(f)
                current_entropy = features.get("entropy_src_ip", 3.4)
    except Exception:
        pass

    now_ms = int(time.time() * 1000)
    entropy_history.append({"x": now_ms, "y": current_entropy})
    
    # Giu toi da 20 diem de bieu do nhe va muot
    if len(entropy_history) > 20:
        entropy_history.pop(0)
        
    return jsonify({"entropy": entropy_history, "pps": []})

@app.route('/alerts')
def alerts():
    alert_list = []
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
    flows_data = []
    try:
        url = f'http://127.0.0.1:8081/stats/flow/{dpid}'
        r = requests.get(url, timeout=2)
        if r.status_code == 200:
            flows_data = r.json().get(dpid, [])
    except Exception as e:
        print(f"Loi goi Ryu API: {e}")
        
    return render_template('flows.html', flows=flows_data, dpid=dpid)

@app.route('/api/block', methods=['POST'])
def manual_block():
    try:
        ip = request.json['src_ip']
        # Gui 3 Alert lien tiep de ep Graduated Response nhay len Cap 3 (Block)
        for _ in range(3):
            requests.post('http://127.0.0.1:8081/api/alert', 
                          json={"src_ip": ip, "severity": "critical_repeat"})
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)