import time
import sys
import os

# Uu tien thu muc goc cua project vao dau sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
sys.path.insert(0, root_dir)

try:
    from code.mitigation import BlacklistManager
except ModuleNotFoundError as e:
    print("[ERROR] Khong the import module: " + str(e))
    sys.exit(1)

class MockApp:
    class logger:
        @staticmethod
        def info(msg):
            print(msg)

def test_ttl():
    print("Khoi tao BlacklistManager...")
    bm = BlacklistManager(MockApp())
    
    print("1. Them IP 1.2.3.4 vao blacklist voi TTL = 2s")
    bm.add("1.2.3.4", ttl=2)
    
    blocked_now = bm.is_blocked("1.2.3.4")
    print("2. is_blocked('1.2.3.4') ngay lap tuc: " + str(blocked_now))
    assert blocked_now is True
    
    print("3. Cho 3 giay...")
    time.sleep(3)
    
    blocked_later = bm.is_blocked("1.2.3.4")
    print("4. is_blocked('1.2.3.4') sau 3 giay: " + str(blocked_later))
    assert blocked_later is False
    
    print("=> TEST PASSED")
    bm._stop = True

if __name__ == "__main__":
    test_ttl()