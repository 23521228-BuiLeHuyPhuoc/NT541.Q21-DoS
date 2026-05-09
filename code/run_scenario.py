import subprocess, time, json, sys, os, requests

RYU_REST = "http://localhost:8080/stats/flow/2"
ALERT_LOG = "results/raw/alerts.json"

def start_topology():
    print("[*] Dang khoi dong Mininet (topology_v4)...")
    subprocess.run(["sudo", "mn", "-c"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    p = subprocess.Popen(["sudo", "python3", "code/topology/topology_v4.py"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    time.sleep(8)
    return p

def start_ryu():
    print("[*] Dang khoi dong Ryu Controller (l3_router_extended)...")
    p = subprocess.Popen(["ryu-manager", "--wsapi-port", "8081",
                          "code/l3_router_extended.py"])
    time.sleep(3)
    return p

def start_detector():
    print("[*] Dang khoi dong Detector...")
    return subprocess.Popen(["python3", "code/detector.py"])

def wait_for_alert(t0, timeout=10):
    while time.time() - t0 < timeout:
        if os.path.exists(ALERT_LOG):
            try:
                with open(ALERT_LOG, 'r') as f:
                    for line in f:
                        if not line.strip(): continue
                        ev = json.loads(line)
                        if ev.get("timestamp", 0) >= t0:
                            return ev["timestamp"] - t0
            except Exception:
                pass
        time.sleep(0.2)
    return None

def wait_for_flowmod(t0, src_ip, timeout=10):
    while time.time() - t0 < timeout:
        try:
            r = requests.get(RYU_REST, timeout=1).json()
            if src_ip in str(r): 
                return time.time() - t0
        except Exception: 
            pass
        time.sleep(0.3)
    return None

def run(scenario_id):
    os.makedirs("results/raw", exist_ok=True)
    # Tao file log rong
    open(ALERT_LOG, 'w').close()
    
    mn = start_topology()
    ryu = start_ryu()
    det = start_detector()
    
    try:
        t0 = time.time()
        print(f"[*] Dang phat dong tan cong: {scenario_id}")
        mn.stdin.write(f"h_att1 bash code/attack_scripts/{scenario_id}.sh &\n".encode())
        mn.stdin.flush()
        
        src = "10.0.4.10" if scenario_id == "s08_flashcrowd" else "10.0.1.10"
        
        print("[*] Dang doi he thong phat hien (alert)...")
        detect_lat = wait_for_alert(t0)
        
        print("[*] Dang doi he thong chan (flowmod)...")
        mitigate_lat = wait_for_flowmod(t0, src, timeout=15)
        
        result = {
            "scenario": scenario_id, 
            "timestamp": t0,
            "detect_latency": detect_lat, 
            "mitigate_latency": mitigate_lat,
            "attack_window": [t0, t0 + 300],
            "expected_alert": scenario_id != "s08_flashcrowd"
        }
        
        out = f"results/raw/run_{scenario_id}_{int(t0)}.json"
        with open(out, 'w') as f:
            json.dump(result, f, indent=2)
            
        print(f"[+] Kich ban hoan tat! Ket qua da luu tai: {out}")
        return result
        
    finally:
        print("[*] Dang don dep va tat he thong...")
        det.terminate()
        ryu.terminate()
        try: 
            mn.communicate(b"exit\n", timeout=10)
        except: 
            mn.kill()
        subprocess.run(["sudo", "mn", "-c"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

if __name__ == "__main__": 
    if len(sys.argv) > 1:
        run(sys.argv[1])
    else:
        print("Vui long truyen kich ban. VD: python3 code/run_scenario.py s01_syn")