#!/usr/bin/env python3
"""
Pipeline doc InfluxDB router cu
Trich xuat du lieu entropy realtime de TV1 va TV3 su dung.
"""

import csv
import os
import sys

try:
    from influxdb_client import InfluxDBClient
except ImportError:
    print("[ERROR] Thieu thu vien influxdb-client. Chay: pip3 install influxdb-client")
    sys.exit(1)

# Thiet lap ket noi InfluxDB
URL = "http://localhost:8086"
# Luu y: Ban can hoi TV4 de lay Token chinh xac thay vao chu admin-token nay
TOKEN = "admin-token" 
ORG = "sdn"
BUCKET = "sdn"
OUT_CSV = "datasets/features/realtime.csv"

def pull_data():
    print(f"[*] Dang ket noi den InfluxDB tai {URL}...")
    client = InfluxDBClient(url=URL, token=TOKEN, org=ORG)
    
    query = f'''
        from(bucket:"{BUCKET}") 
        |> range(start: -30m)
        |> filter(fn: (r) => r._measurement == "entropy")
    '''
    
    try:
        tables = client.query_api().query(query)
    except Exception as e:
        print(f"[ERROR] Khong the truy van InfluxDB. DB da chay chua? Chi tiet loi: {e}")
        sys.exit(1)

    os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)

    row_count = 0
    with open(OUT_CSV, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['t', 'metric', 'value'])
        
        for tbl in tables:
            for rec in tbl.records:
                w.writerow([rec.get_time(), rec.get_field(), rec.get_value()])
                row_count += 1

    print(f"[+] Da pull thanh cong {row_count} records tu InfluxDB.")
    print(f"[+] Output luu tai: {OUT_CSV}")

if __name__ == '__main__':
    pull_data()
