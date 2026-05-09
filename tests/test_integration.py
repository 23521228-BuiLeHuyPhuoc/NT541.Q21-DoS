import subprocess, time, pytest, os

@pytest.fixture(scope="module")
def stack():
    # Xoa Mininet cu
    subprocess.run(["sudo", "mn", "-c"], check=False)
    
    # 1. Goi file router cu hien co trong thu muc
    ryu = subprocess.Popen(["ryu-manager", "code/l3_router_test.py"])
    time.sleep(3)
    
    # 2. Goi file topology cu hien co trong thu muc
    mn = subprocess.Popen(["sudo", "python3", "code/topology/topology_nhom4.py"],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    time.sleep(8)
    
    # Chua co code/detector.py nen khong khoi dong subprocess detector
    
    yield {"ryu": ryu, "mn": mn}
    
    # Don dep
    ryu.terminate()
    mn.communicate(b"exit\n", timeout=10)
    subprocess.run(["sudo", "mn", "-c"])

def test_s01_syn_flow_temporary(stack):
    # Kich hoat script tan cong tu host
    stack["mn"].stdin.write(b"h_att1 bash code/attack_scripts/s01_syn.sh &\n")
    stack["mn"].stdin.flush()
    
    t0 = time.time()
    
    # Vi he thong cu khong co alerts.json, ta test tam bang cach 
    # check xem script s01_syn.sh co thuc su chay va sinh file pcap khong
    while time.time() - t0 < 5:
        if os.path.exists('datasets/s01_syn.pcap'):
            break
        time.sleep(0.5)
        
    assert os.path.exists('datasets/s01_syn.pcap')