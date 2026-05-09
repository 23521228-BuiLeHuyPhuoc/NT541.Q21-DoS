import subprocess, time, requests, pytest, os

@pytest.fixture(scope="module")
def stack():
    # Xóa sạch cấu hình Mininet cũ trước khi chạy
    subprocess.run(["sudo", "mn", "-c"], check=False)
    
    # Khởi động Ryu Controller
    ryu = subprocess.Popen(["ryu-manager", "--wsapi-port", "8081",
                            "code/l3_router_extended.py"])
    time.sleep(3)
    
    # Khởi động Topology Mininet của nhóm
    mn = subprocess.Popen(["sudo", "python3", "code/topology/topology_nhom4.py"],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    time.sleep(8)
    
    # Khởi động Orchestrator (Detector)
    detector = subprocess.Popen(["python3", "code/detector.py"])
    time.sleep(2)
    
    yield {"ryu": ryu, "mn": mn, "detector": detector}
    
    # Dọn dẹp sau khi test xong
    detector.terminate()
    ryu.terminate()
    mn.communicate(b"exit\n", timeout=10)
    subprocess.run(["sudo", "mn", "-c"])

def test_s01_syn_flow(stack):
    # Kích hoạt script tấn công SYN flood từ host h_att1
    stack["mn"].stdin.write(b"h_att1 bash code/attack_scripts/s01_syn.sh &\n")
    stack["mn"].stdin.flush()
    
    t0 = time.time()
    alerts = ""
    
    # Chờ tối đa 5s để hệ thống ghi log cảnh báo
    while time.time() - t0 < 5:
        if os.path.exists('results/raw/alerts.json'):
            alerts = open('results/raw/alerts.json').read()
            if 'syn' in alerts.lower(): 
                break
        time.sleep(0.2)
        
    # Kiểm tra xem có cảnh báo 'syn' không
    assert 'syn' in alerts.lower()
    
    # Kiểm tra thời gian phát hiện phải <= 3 giây
    detect_lat = time.time() - t0
    assert detect_lat <= 3
    
    time.sleep(3)
    
    # Gọi Ryu REST API để kiểm tra xem rule block IP kẻ tấn công (10.0.1.10) đã được cài xuống switch chưa
    r = requests.get("http://localhost:8080/stats/flow/2").json()
    assert "10.0.1.10" in str(r)