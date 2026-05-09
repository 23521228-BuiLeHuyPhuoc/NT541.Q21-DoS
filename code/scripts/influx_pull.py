from influxdb_client import InfluxDBClient
import csv
import os

# --- CẤU HÌNH INFLUXDB ---
INFLUX_TOKEN = "my-super-secret-auth-token" 
INFLUX_URL = "http://localhost:8086"
ORG = "sdn"
BUCKET = "sdn"

# 1. Đảm bảo thư mục tồn tại
os.makedirs('datasets/features', exist_ok=True)

# 2. Kết nối InfluxDB bằng chìa khóa
client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=ORG)
q = f'''from(bucket:"{BUCKET}") |> range(start:-30m)
       |> filter(fn:(r)=> r._measurement=="entropy")'''

# 3. Kéo dữ liệu và lưu CSV
try:
    tables = client.query_api().query(q)
    with open('datasets/features/realtime.csv', 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['t','metric','value'])
        
        for tbl in tables:
            for rec in tbl.records:
                w.writerow([rec.get_time(), rec.get_field(), rec.get_value()])
                
    print("[OK] Pipeline da chay thanh cong va tao file realtime.csv!")
except Exception as e:
    print(f"[LOI] Co van de xay ra: {e}")