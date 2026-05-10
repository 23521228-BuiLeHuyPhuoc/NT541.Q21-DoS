from flask import Flask, render_template, jsonify, request
import os, json, requests, time
from datetime import datetime

app = Flask(__name__)
entropy_history = []
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))


RYU_ENTROPY_URL = "http://127.0.0.1:8081/api/entropy"
RYU_FLOW_URL = "http://127.0.0.1:8081/stats/flow/2"

def _compute_entropy_from_ryu():
    """Doc entropy truc tiep tu Ryu controller -- cung gia tri voi Ryu log."""
    try:
        resp = requests.get(RYU_ENTROPY_URL, timeout=2)
        data = resp.json()
        entropy = data.get("entropy", 0.0)
        unique_ips = data.get("unique_ips", 0)
        window_size = data.get("window_size", 0)
        attack = data.get("attack_status", 0)
        info = f"{unique_ips} IPs, window={window_size}, attack={attack}"
        return round(entropy, 4), info
    except Exception as e:
        return 0.0, f"Ryu error: {e}"

# ==========================================
# 1. TRANG CHINH - BIEU DO ENTROPY
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
    
    # Giu lai 30 diem gan nhat cho muot
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
# 2. TRANG ALERTS (Danh sach canh bao)
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
                        # Doc action truc tiep tu log (da duoc alert_system.py ghi chinh xac)
                        action = al.get("action", "Logged")
                        severity = al.get("severity", "INFO")

                        alerts_data.append({
                            "time": datetime.fromtimestamp(al["timestamp"]).strftime('%H:%M:%S'),
                            "src_ip": al["src_ip"],
                            "attack": al["attack"],
                            "severity": severity,
                            "action": action
                        })
                    except Exception:
                        pass

    return render_template('alerts.html', alerts=alerts_data[::-1])

# ==========================================
# 3. TRANG FLOWS (Danh sach OpenFlow rules)
# ==========================================
@app.route('/flows')
def flows_page():
    flows_data =[]
    try:
        # Lay flow thong ke tu Switch s2 (Datapath ID = 2) thong qua Ryu REST API
        resp = requests.get("http://127.0.0.1:8081/stats/flow/2", timeout=2)
        if resp.status_code == 200:
            flows_data = resp.json().get("2", [])
    except Exception:
        pass
        
    return render_template('flows.html', dpid=2, flows=flows_data)

# ==========================================
# 4. ENDPOINT MANUAL BLOCK (Chan IP thu cong)
# ==========================================
@app.route('/api/block', methods=['POST'])
def manual_block():
    try:
        ip = request.json['src_ip']
        if not ip:
            return jsonify({"ok": False, "error": "Thieu thong tin IP"})
            
        # Theo policy.yaml, he thong yeu cau threshold=3 moi thuc hien Block (cap do 3)
        # Do do chung ta gui ep 3 requests lien tiep sang Ryu Controller de dat muc Block ngay lap tuc.
        for _ in range(3):
            requests.post('http://127.0.0.1:8081/api/alert',
                          json={"src_ip": ip, "attack": "manual_block", "severity": "CRITICAL"}, 
                          timeout=1)
            time.sleep(0.1)
            
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

# ==========================================
# 5. DEBUG - XEM RAW DATA TU RYU
# ==========================================
@app.route('/api/debug')
def debug_ryu():
    """Truy cap http://VM_IP:8080/api/debug de xem Ryu tra ve gi."""
    result = {}
    for dpid in ['1', '2', '3', '4', '5']:
        url = f"http://127.0.0.1:8081/stats/flow/{dpid}"
        try:
            resp = requests.get(url, timeout=2)
            flows = resp.json().get(dpid, [])
            # Chi lay 5 flow dau, gon nhe
            summary = []
            for f in flows[:5]:
                summary.append({
                    "match": f.get("match", {}),
                    "packet_count": f.get("packet_count", 0),
                    "priority": f.get("priority", 0)
                })
            result[f"switch_{dpid}"] = {
                "total_flows": len(flows),
                "sample_flows": summary
            }
        except Exception as e:
            result[f"switch_{dpid}"] = {"error": str(e)}
    
    # Them thong tin entropy computation
    entropy_val, entropy_info = _compute_entropy_from_ryu()
    result["entropy_result"] = {"value": entropy_val, "info": entropy_info}

    
    return jsonify(result)

# ==========================================
# KHOI CHAY FLASK SERVER
# ==========================================
if __name__ == '__main__':
    print(f"[DASHBOARD] http://0.0.0.0:8080")
    app.run(host='0.0.0.0', port=8080, debug=False)