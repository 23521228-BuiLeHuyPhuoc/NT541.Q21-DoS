from flask import Flask, render_template, jsonify, request
from influxdb_client import InfluxDBClient
import os, json, requests
from datetime import datetime

app = Flask(__name__)

# --- CAU HINH INFLUXDB ---
INFLUX_TOKEN = "2Bdyw5xOnRrLQK-s7NFS0IxylcXDSt86UhpqFr-H4moUw4nxR-QxmsD5LkNQHMcC66hk7A9X-NUvk7iNk4MNvQ=="
INFLUX_URL = "http://localhost:8086"
ORG = "sdn"
BUCKET = "sdn"

@app.route('/')
def home(): 
    return render_template('index.html')

@app.route('/api/stats')
def stats(): 
    try:
        client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=ORG)
        query = f'''from(bucket:"{BUCKET}") 
                    |> range(start:-5m)
                    |> filter(fn:(r)=> r._measurement=="entropy")'''
        
        result = client.query_api().query(query)
        
        entropy_data = []
        for table in result:
            for record in table.records:
                timestamp_ms = int(record.get_time().timestamp() * 1000)
                val = record.get_value()
                entropy_data.append({"x": timestamp_ms, "y": val})
                
        return jsonify({"entropy": entropy_data, "pps": []})
        
    except Exception as e:
        print(f"Loi truy van InfluxDB: {e}")
        return jsonify({"entropy": [], "pps": []})

# --- PHAN C: /alerts ---
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
                    except Exception as e:
                        print(f"Loi parse JSON: {e}")
                        
    alert_list.reverse()
    return render_template('alerts.html', alerts=alert_list)

# --- PHAN D: /flows ---
@app.route('/flows')
def flows():
    dpid = request.args.get('dpid', '2')
    flows_data = []
    try:
        url = f'http://127.0.0.1:8080/stats/flow/{dpid}'
        r = requests.get(url, timeout=2)
        if r.status_code == 200:
            flows_data = r.json().get(dpid, [])
    except Exception as e:
        print(f"Loi goi Ryu API: {e}")
        
    return render_template('flows.html', flows=flows_data, dpid=dpid)

# --- PHAN E: Manual Block ---
@app.route("/api/block", methods=["POST"])
def manual_block():
    try:
        ip = request.json["src_ip"]
        # Gửi 3 Alert liên tiếp để ép Graduated Response nhảy thẳng lên Cấp 3 (Block)
        for _ in range(3):
            requests.post("http://127.0.0.1:8081/api/alert", 
                          json={"src_ip": ip, "severity": "critical_repeat"})
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)