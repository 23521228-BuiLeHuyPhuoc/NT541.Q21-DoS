import subprocess
import time
import json
import sys
import os
import signal
import requests

RYU_REST = "http://localhost:8081/stats/flow/2"
ALERT_LOG = "results/raw/alerts.json"
DETECTOR_LOG = "results/raw/detector.log"
RYU_LOG = "results/raw/ryu.log"

def kill_existing():
    """Kill moi ryu-manager va detector dang chay truoc khi bat dau."""
    print("[*] Dang kill cac tien trinh cu (ryu-manager, detector)...")
    subprocess.run(["pkill", "-9", "-f", "ryu-manager"], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["pkill", "-9", "-f", "code/detector.py"], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)  # Doi port 8081 duoc nha ra

def start_ryu():
    """Khoi dong Ryu TRUOC topology de switches ket noi ngay."""
    print(f"[*] Dang khoi dong Ryu (log: {RYU_LOG})...")
    ryu_out = open(RYU_LOG, 'w', encoding='utf-8')
    p = subprocess.Popen(["ryu-manager", "--wsapi-port", "8081", "ryu.app.ofctl_rest", "code/l3_router_extended.py"],
                         stdout=ryu_out, stderr=subprocess.STDOUT,
                         start_new_session=True)
    time.sleep(3)

    # Kiem tra Ryu con song khong
    if p.poll() is not None:
        print("  [!] LOI: Ryu da chet ngay khi khoi dong! Kiem tra results/raw/ryu.log")
        ryu_out.close()
        sys.exit(1)

    # Kiem tra REST API hoat dong
    try:
        r = requests.get("http://localhost:8081/stats/switches", timeout=2)
        print(f"  [OK] Ryu REST API hoat dong (switches: {r.text.strip()})")
    except Exception:
        print("  [!] CANH BAO: Ryu REST API chua san sang, tiep tuc...")

    return p, ryu_out

def start_topology():
    print("[*] Dang khoi dong Topology V4...")
    p = subprocess.Popen(["sudo", "python3", "code/topology/topology_v4.py"],
                         stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    time.sleep(8)

    # Kiem tra switches da ket noi voi Ryu chua
    try:
        r = requests.get("http://localhost:8081/stats/switches", timeout=2)
        switches = r.json()
        print(f"  [OK] {len(switches)} switches da ket noi: {switches}")
    except Exception:
        print("  [!] CANH BAO: Chua kiem tra duoc switches.")

    return p

def start_detector():
    print(f"[*] Dang khoi dong Detector (log: {DETECTOR_LOG})...")
    det_out = open(DETECTOR_LOG, 'w', encoding='utf-8')
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    p = subprocess.Popen(["python3", "-u", "code/detector.py"], stdout=det_out, stderr=subprocess.STDOUT,
                         start_new_session=True, env=env)
    return p, det_out

def wait_for_alert(t0, timeout=30):
    """Doi canh bao trong alerts.json voi timestamp >= t0."""
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
        time.sleep(0.5)
    return None

def wait_for_flowmod(t0, src_ip, timeout=30):
    """Doi flow drop duoc cai cho src_ip."""
    while time.time() - t0 < timeout:
        try:
            r = requests.get(RYU_REST, timeout=2).json()
            if src_ip in str(r): 
                return time.time() - t0
        except Exception: 
            pass
        time.sleep(0.5)
    return None

def run_feature_extraction(scenario_id):
    """Tu dong chay feature_extraction.py neu co file pcap."""
    pcap_path = f"datasets/{scenario_id}.pcap"
    csv_path = f"datasets/features/{scenario_id}.csv"
    
    if not os.path.exists(pcap_path):
        print(f"  [!] Khong tim thay {pcap_path}, bo qua feature extraction.")
        return
    
    pcap_size = os.path.getsize(pcap_path)
    if pcap_size < 100:
        print(f"  [!] {pcap_path} qua nho ({pcap_size} bytes), bo qua.")
        return
    
    print(f"[*] Dang trich xuat features: {pcap_path} -> {csv_path}")
    os.makedirs("datasets/features", exist_ok=True)
    try:
        result = subprocess.run(
            ["python3", "code/feature_extraction.py", pcap_path, csv_path],
            timeout=300
        )
        if result.returncode == 0:
            if os.path.exists(csv_path):
                print(f"  [OK] Da tao {csv_path} ({os.path.getsize(csv_path)} bytes)")
            else:
                print(f"  [!] feature_extraction exit 0 nhung khong tao duoc CSV")
        else:
            print(f"  [!] Feature extraction thoat voi ma loi {result.returncode}")
    except subprocess.TimeoutExpired:
        print(f"  [!] Feature extraction timeout (300s) - pcap qua lon?")
    except Exception as e:
        print(f"  [!] Feature extraction exception: {e}")

def run(scenario_id):
    os.makedirs("results/raw", exist_ok=True)
    
    # Fix quyen truy cap file (truong hop sudo tao file root)
    for f in [ALERT_LOG, DETECTOR_LOG, RYU_LOG]:
        if os.path.exists(f):
            subprocess.run(["chmod", "666", f], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Kill moi tien trinh cu truoc
    kill_existing()

    # Reset log alert — tao file voi quyen cho tat ca
    open(ALERT_LOG, 'w').close()
    os.chmod(ALERT_LOG, 0o666)

    print(f"\n========== BAT DAU KICH BAN: {scenario_id} ==========")

    # THU TU: mn -c -> Ryu -> Topology
    # mn -c phai chay TRUOC Ryu vi no kill ca controller processes
    print("[*] Dang don dep Mininet...")
    subprocess.run(["sudo", "mn", "-c"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

    ryu, ryu_out = start_ryu()
    mn = start_topology()
    det, det_out = start_detector()
    
    # Bat tcpdump tren host system de capture pcap (khong phu thuoc attack script)
    pcap_path = f"datasets/{scenario_id}.pcap"
    os.makedirs("datasets", exist_ok=True)
    tcpdump_proc = None
    try:
        tcpdump_proc = subprocess.Popen(
            ["sudo", "tcpdump", "-i", "any", "-w", pcap_path, "-U"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True
        )
        print(f"[*] Bat dau capture pcap: {pcap_path}")
    except Exception as e:
        print(f"  [!] Khong khoi dong duoc tcpdump: {e}")
    
    # Cho detector warm up (can vai chu ky doc flow stats)
    print("[*] Cho detector warm up 5s...")
    time.sleep(5)

    try:
        # Ping chi dinh thay vi pingall (nhanh hon 10x)
        print("[*] Hoc ARP bang ping chi dinh (h_att1 -> victims)...")
        for target in ["10.0.2.10", "10.0.2.11", "10.0.3.10"]:
            mn.stdin.write(f"h_att1 ping -c 1 -W 1 {target} &\n".encode())
            mn.stdin.flush()
        time.sleep(5)

        # Bat dau do thoi gian NGAY TRUOC khi tan cong
        t0 = time.time()

        print(f"[*] Tien hanh kich hoat tan cong ({scenario_id})...")
        mn.stdin.write(f"h_att1 bash code/attack_scripts/{scenario_id}.sh &\n".encode())
        mn.stdin.flush()
        
        src = "10.0.4.10" if scenario_id == "s08_flash_crowd" else "10.0.1.10"
        
        print("[*] Dang cho he thong phat hien (Detect) - timeout 30s...")
        detect_lat = wait_for_alert(t0, timeout=30)
        if detect_lat:
            print(f"  [+] Da phat hien tan cong! Do tre: {detect_lat:.3f}s")
        else:
            print("  [-] Khong phat hien duoc canh bao.")
            # In 5 dong cuoi cua detector.log de debug
            try:
                with open(DETECTOR_LOG, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    tail = lines[-5:] if len(lines) >= 5 else lines
                    print("  [DEBUG] detector.log (cuoi):")
                    for l in tail:
                        print(f"    {l.rstrip()}")
            except Exception:
                pass

        print("[*] Dang cho he thong ngan chan (Mitigate) - timeout 30s...")
        mitigate_lat = wait_for_flowmod(t0, src, timeout=30)
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
            "expected_alert": scenario_id != "s08_flash_crowd"
        }
        
        out_file = f"results/raw/run_{scenario_id}_{int(t0)}.json"
        with open(out_file, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"[+] Hoan tat! Da luu ket qua tai: {out_file}\n")
        
        return result
    finally:
        print("[*] Dang don dep va tat cac tien trinh...")
        # Dung os.killpg vi moi subprocess chay trong session rieng
        try:
            os.killpg(os.getpgid(det.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            det.terminate()
        try:
            os.killpg(os.getpgid(ryu.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            ryu.terminate()
        det_out.close()
        ryu_out.close()
        try: 
            mn.communicate(b"exit\n", timeout=10)
        except: 
            mn.kill()
        subprocess.run(["sudo", "mn", "-c"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Dung tcpdump va flush pcap
        if tcpdump_proc:
            try:
                os.killpg(os.getpgid(tcpdump_proc.pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                try: tcpdump_proc.terminate()
                except: pass
            tcpdump_proc.wait(timeout=5)
            print(f"  [OK] Da luu pcap: {pcap_path}")
        
        # Tu dong trich xuat features tu pcap sang CSV
        run_feature_extraction(scenario_id)

if __name__ == "__main__": 
    if len(sys.argv) > 1:
        run(sys.argv[1])
    else:
        print("Loi: Vui long truyen kich ban. VD: sudo python3 code/run_scenario.py s01_syn")