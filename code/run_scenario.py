import subprocess, time, json, sys, os, requests

RYU_REST = "http://localhost:8080/stats/flow/2"
ALERT_LOG = "results/raw/alerts.json"

def start_topology():
    subprocess.run(["sudo", "mn", "-c"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    p = subprocess.Popen(["sudo", "python3", "code/topology/topology_v4.py"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    time.sleep(8)
    return p

def start_ryu():
    p = subprocess.Popen(["ryu-manager", "--wsapi-port", "8081",
                          "code/l3_router_extended.py"])
    time.sleep(3)
    return p

def start_detector():
    return subprocess.Popen(["python3", "code/detector.py"])

def wait_for_alert(t0, timeout=10):
    while time.time() - t0 < timeout:
        if os.path.exists(ALERT_LOG):
            try:
                for line in open(ALERT_LOG):
                    if not line.strip(): continue
                    ev = json.loads(line)
                    if ev["timestamp"] >= t0:
                        return ev["timestamp"] - t0
            except Exception: pass
        time.sleep(0.2)
    return None

def wait_for_flowmod(t0, src_ip, timeout=10):
    while time.time() - t0 < timeout:
        try:
            r = requests.get(RYU_REST, timeout=1).json()
            if src_ip in str(r): return time.time() - t0
        except Exception: pass
        time.sleep(0.3)
    return None

def run(scenario_id):
    os.makedirs("results/raw", exist_ok=True)
    open(ALERT_LOG, 'w').close()
    
    print(f"[*] Đang khởi động mạng và hệ thống cho kịch bản {scenario_id}...")
    mn = start_topology()
    ryu = start_ryu()
    det = start_detector()
    
    try:
        t0 = time.time()
        print(f"[*] Đang tấn công...")
        mn.stdin.write(f"h_att1 bash code/attack_scripts/{scenario_id}.sh &\n".encode())
        mn.stdin.flush()
        
        src = "10.0.4.10" if scenario_id == "s08_flashcrowd" else "10.0.1.10"
        
        detect_lat = wait_for_alert(t0)
        print(f"[+] Độ trễ phát hiện: {detect_lat}s")
        
        mitigate_lat = wait_for_flowmod(t0, src, timeout=15)
        print(f"[+] Độ trễ ngăn chặn: {mitigate_lat}s")
        
        result = {"scenario": scenario_id, "timestamp": t0,
                  "detect_latency": detect_lat, "mitigate_latency": mitigate_lat,
                  "attack_window": [t0, t0 + 300],
                  "expected_alert": scenario_id != "s08_flashcrowd"}
                  
        out = f"results/raw/run_{scenario_id}_{int(t0)}.json"
        json.dump(result, open(out, 'w'), indent=2)
        print(f"[+] Đã lưu kết quả tại: {out}\n")
        return result
        
    finally:
        print("[*] Đang dọn dẹp hệ thống...")
        det.terminate()
        ryu.terminate()
        try: mn.communicate(b"exit\n", timeout=10)
        except: mn.kill()
        subprocess.run(["sudo", "mn", "-c"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

if __name__ == "__main__": 
    if len(sys.argv) > 1: run(sys.argv[1])
    else: print("Vui lòng truyền kịch bản. VD: python3 code/run_scenario.py s01_syn")