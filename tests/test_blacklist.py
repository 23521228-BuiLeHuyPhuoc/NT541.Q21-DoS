import time
import sys
import os

# Tu dong the thu muc goc cua project vao sys.path de doc duoc thu muc 'code'
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
sys.path.append(root_dir)

try:
    from code.mitigation import BlacklistManager
except ModuleNotFoundError:
    print("[LỖI] Không tìm thấy file code/mitigation.py.")
    sys.exit(1)

class MockApp:
    pass

def test_ttl():
    print("Khoi tao BlacklistManager...")
    bm = BlacklistManager(MockApp())
    
    print("1. Them IP 1.2.3.4 vao blacklist voi TTL = 2s")
    bm.add("1.2.3.4", ttl=2)
    
    blocked_now = bm.is_blocked("1.2.3.4")
    print(f"2. is_blocked('1.2.3.4') ngay lap tuc: {blocked_now}")
    assert blocked_now is True
    
    print("3. Cho 3 giay...")
    time.sleep(3)
    
    blocked_later = bm.is_blocked("1.2.3.4")
    print(f"4. is_blocked('1.2.3.4') sau 3 giay: {blocked_later}")
    assert blocked_later is False
    
    print("=> TEST PASSED")
    bm._stop = True

if __name__ == "__main__":
    test_ttl()