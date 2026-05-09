import subprocess
import time
import json
import sys
import os
import requests

RYU_REST = "http://localhost:8081/stats/flow/2"
ALERT_LOG = "results/raw/alerts.json"
DETECTOR_LOG = "results/raw/detector.log"
RYU_LOG = "results/raw/ryu.log"

def start_topology():
    print("[*] Dang don dep Mininet...")
    subprocess.run(["sudo", "mn", "-c"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    print("[*] Dang khoi dong Topology V4...")
    p = subprocess.Popen(["sudo", "python3", "code/topology/topology_v4.py"],
                         stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(8)
    return p

def start_ryu():
    print(f"[*] Dang khoi dong Ryu (log: {RYU_LOG})...")
    ryu_out = open(RYU_LOG, 'w')
    p = subprocess.Popen(["ryu-manager", "--wsapi-port", "8081", "ryu.app.ofctl_rest", "code/l3_router_extended.py"],
                         stdout=ryu_out, stderr=subprocess.STDOUT)
    time.sleep(3)
    return p, ryu_out

def start_detector():
    print(f"[*] Dang khoi dong Detector (log: {DETECTOR_LOG})...")
    det_out = open(DETECTOR_LOG, 'w')
    p = subprocess.Popen(["python3", "-u", "code/detector.py"], stdout=det_out, stderr=subprocess.STDOUT)
    return p, det_out

def wait_for_alert(t0, timeout=15):
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

def wait_for_flowmod(t0, src_ip, timeout=20):
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
    
    # Reset log alert
    open(ALERT_LOG, 'w').close()

    print(f"\n========== BAT DAU KICH BAN: {scenario_id} ==========")
    mn = start_topology()
    ryu, ryu_out = start_ryu()
    det, det_out = start_detector()
    
    try:
        t0 = time.time()
        
        # --- DOAN CODE MOI DUOC THEM VAO ---
        print("[*] Chay pingall de hoc ARP...")
        mn.stdin.write(b"pingall\n")
        mn.stdin.flush()
        time.sleep(5)
        # ----------------------------------

        print(f"[*] Tien hanh kich hoat ma doc tan cong (h_att1)...")
        mn.stdin.write(f"h_att1 bash code/attack_scripts/{scenario_id}.sh &\n".encode())
        mn.stdin.flush()
        
        src = "10.0.4.10" if scenario_id == "s08_flashcrowd" else "10.0.1.10"
        
        print("[*] Dang cho he thong phat hien (Detect)...")
        detect_lat = wait_for_alert(t0, timeout=15)
        if detect_lat:
            print(f"  [+] Da phat hien tan cong! Do tre: {detect_lat:.3f}s")
        else:
            print("  [-] Khong phat hien duoc canh bao. Kiem tra log cua detector hoac ryu.")

        print("[*] Dang cho he thong ngan chan (Mitigate)...")
        mitigate_lat = wait_for_flowmod(t0, src, timeout=20)
        if mitigate_lat:
            print(f"  [+] Da cai Flow Drop! Do tre: {mitigate_lat:.3f}s")
        else:
            print(f"  [-] Khong tim thay Flow Drop nao cho {src}.")

        result = {
            "scenario": scenario_id, 
            "timestamp": t0,
            "detect_latency": detect_lat, 
            "mitigate_latency": mitigate_lat,
            "attack_window":[t0, t0 + 300],
            "expected_alert": scenario_id != "s08_flashcrowd"
        }
        
        out_file = f"results/raw/run_{scenario_id}_{int(t0)}.json"
        with open(out_file, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"[+] Hoan tat! Da luu ket qua tai: {out_file}\n")
        
        return result
    finally:
        print("[*] Dang don dep va tat cac tien trinh...")
        det.terminate()
        ryu.terminate()
        det_out.close()
        ryu_out.close()
        try: 
            mn.communicate(b"exit\n", timeout=10)
        except: 
            mn.kill()
        subprocess.run(["sudo", "mn", "-c"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

if __name__ == "__main__": 
    if len(sys.argv) > 1:
        run(sys.argv[1])
    else:
        print("Loi: Vui long truyen kich ban. VD: sudo python3 code/run_scenario.py s01_syn")