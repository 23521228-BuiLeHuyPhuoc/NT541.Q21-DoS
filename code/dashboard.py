from flask import Flask, render_template, jsonify, request
import os, json, requests, time
from datetime import datetime

app = Flask(__name__)
entropy_history = []
JSON_PATH = "results/raw/current_features.json"

@app.route('/')
def home(): return render_template('index.html')

@app.route('/api/stats')
def stats(): 
    global entropy_history
    # Mac dinh la 3.4 (Safe level) de tranh bieu do nhay xuong 0 khi loi doc file
    current_entropy = 3.4 
    
    try:
        # Kiem tra file ton tai va co du lieu khong
        if os.path.exists(JSON_PATH) and os.path.getsize(JSON_PATH) > 0:
            with open(JSON_PATH, "r") as f:
                features = json.load(f)
                current_entropy = features.get("entropy_src_ip", 3.4)
                # Debug ra terminal cua Dashboard de kiem tra viec doc file
                print(f"[DASHBOARD DBG] Read entropy: {current_entropy}")
    except Exception as e:
        print(f"[DASHBOARD ERR] {e}")

    now_ms = int(time.time() * 1000)
    entropy_history.append({"x": now_ms, "y": current_entropy})
    if len(entropy_history) > 30: # Tang len 30 diem cho muot
        entropy_history.pop(0)
        
    return jsonify({"entropy": entropy_history})

# ... (Cac router alerts, flows, manual_block giu nguyen) ...

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)