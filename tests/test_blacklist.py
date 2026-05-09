import time
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from code.mitigation import BlacklistManager

# Tao mot app gia (mock) de tranh loi khi in log
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
    
    print("2. is_blocked('1.2.3.4') ngay lap tuc:", bm.is_blocked("1.2.3.4"))
    assert bm.is_blocked("1.2.3.4") is True
    
    print("3. Cho 3 giay...")
    time.sleep(3)
    
    print("4. is_blocked('1.2.3.4') sau 3 giay:", bm.is_blocked("1.2.3.4"))
    assert bm.is_blocked("1.2.3.4") is False
    print("=> TEST PASSED")
    
    bm._stop = True

if __name__ == "__main__":
    test_ttl()