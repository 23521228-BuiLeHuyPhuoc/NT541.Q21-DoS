import subprocess
import time
import json
import sys
import os
import requests

RYU_REST = "http://localhost:8080/stats/flow/2"
ALERT_LOG = "results/raw/alerts.json"

def start_topology():
    print("[*] Đang dọn dẹp môi trường Mininet cũ...")
    subprocess.run(["sudo", "mn", "-c"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    print("[*] Đang khởi động Topology V4...")
    p = subprocess.Popen(["sudo", "python3", "code/topology/topology_v4.py"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    time.sleep(8)
    return p

def start_ryu():
    print("[*] Đang khởi động Ryu Controller...")
    p = subprocess.Popen(["ryu-manager", "--wsapi-port", "8081", "code/l3_router_extended.py"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    return p

def start_detector():
    print("[*] Đang khởi động Detector Orchestrator...")
    return subprocess.Popen(["python3", "code/detector.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def wait_for_alert(t0, timeout=15):
    """Đợi đến khi có alert trong khoảng thời gian timeout"""
    while time.time() - t0 < timeout:
        if os.path.exists(ALERT_LOG):
            try:
                with open(ALERT_LOG, 'r') as f:
                    for line in f:
                        if not line.strip(): continue
                        ev = json.loads(line)
                        if ev["timestamp"] >= t0:
                            return ev["timestamp"] - t0
            except Exception: 
                pass # Bỏ qua nếu file json đang ghi dở bị lỗi parse
        time.sleep(0.2)
    return None

def wait_for_flowmod(t0, src_ip, timeout=20):
    """Đợi đến khi Switch 2 được cài đặt Flow chặn IP"""
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
    
    # Reset file log alert
    with open(ALERT_LOG, 'w') as f:
        pass 

    print(f"\n========== BẮT ĐẦU KỊCH BẢN: {scenario_id} ==========")
    mn = start_topology()
    ryu = start_ryu()
    det = start_detector()
    
    try:
        t0 = time.time()
        print(f"[*] Tiến hành kích hoạt mã độc tấn công (h_att1)...")
        mn.stdin.write(f"h_att1 bash code/attack_scripts/{scenario_id}.sh &\n".encode())
        mn.stdin.flush()
        
        # Flashcrowd xuất phát từ h_pc1 (10.0.4.10), còn lại từ h_att1 (10.0.1.10)
        src = "10.0.4.10" if scenario_id == "s08_flashcrowd" else "10.0.1.10"
        
        print("[*] Đang chờ hệ thống phát hiện (Detect)...")
        detect_lat = wait_for_alert(t0, timeout=15)
        if detect_lat:
            print(f"  [+] Đã phát hiện tấn công! Độ trễ: {detect_lat:.3f}s")
        else:
            print(f"  [-] Không phát hiện được cảnh báo nào trong 15s.")

        print("[*] Đang chờ hệ thống ngăn chặn (Mitigate)...")
        mitigate_lat = wait_for_flowmod(t0, src, timeout=20)
        if mitigate_lat:
            print(f"  [+] Đã cài Flow Drop! Độ trễ: {mitigate_lat:.3f}s")
        else:
            print(f"  [-] Không tìm thấy Flow Drop nào cho {src}.")

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
        print(f"[+] Hoàn tất! Đã lưu kết quả tại: {out_file}\n")
        
        return result
    finally:
        print("[*] Đang dọn dẹp và tắt các tiến trình...")
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
        print("Lỗi: Vui lòng truyền kịch bản. VD: sudo python3 code/run_scenario.py s01_syn")