from flask import Flask, render_template, jsonify, request
from influxdb_client import InfluxDBClient
import os

app = Flask(__name__)

# --- CAU HINH INFLUXDB ---
# Thay doan text ben duoi bang Token cua TV2 tao o task truoc
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
        # B.1: Query Flux
        client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=ORG)
        query = f'''from(bucket:"{BUCKET}") 
                    |> range(start:-5m)
                    |> filter(fn:(r)=> r._measurement=="entropy")'''
        
        result = client.query_api().query(query)
        
        # B.2: Chuyen ket qua thanh [{x: time, y: value}] cho Chart.js
        entropy_data = []
        for table in result:
            for record in table.records:
                # Chart.js time adapter can thoi gian o dinh dang milliseconds
                timestamp_ms = int(record.get_time().timestamp() * 1000)
                val = record.get_value()
                entropy_data.append({"x": timestamp_ms, "y": val})
                
        return jsonify({"entropy": entropy_data, "pps": []})
        
    except Exception as e:
        print(f"Loi truy van InfluxDB: {e}")
        return jsonify({"entropy": [], "pps": []})

if __name__ == '__main__':
    # Chay server tren port 8080
    app.run(host='0.0.0.0', port=8080, debug=True)