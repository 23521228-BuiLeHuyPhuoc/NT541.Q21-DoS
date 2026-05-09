import sys
import os
import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../code')))
from signature_matcher import safe_eval, SignatureMatcher

def test_safe_eval_simple():
    # Giả lập tham số mạng
    ctx = {'syn_rate': 1500, 'ack_rate': 5}
    # Phải trả về True vì thỏa mãn cả 2 điều kiện
    assert safe_eval("syn_rate > 1000 and ack_rate < 10", ctx) == True
    # Phải trả về False vì 1500 không lớn hơn 2000
    assert safe_eval("syn_rate > 2000", ctx) == False

def test_blocks_dangerous():
    # Cố tình chèn mã độc xóa hệ thống
    malicious_code = "__import__('os').system('rm -rf /')"
    ctx = {}
    # Phải văng lỗi ValueError, chứng tỏ hệ thống phòng thủ tốt
    with pytest.raises(ValueError):
        safe_eval(malicious_code, ctx)

def test_match_syn():
    matcher = SignatureMatcher(csv_path='docs/attack_signatures.csv')
    
    # Test với thông số bình thường (không có tấn công)
    normal_features = {'syn_rate': 500, 'ack_rate': 500, 'udp_rate': 100}
    assert len(matcher.match(normal_features)) == 0
    
    # Test với thông số của một vụ SYN Flood
    attack_features = {'syn_rate': 1200, 'ack_rate': 2, 'udp_rate': 10}
    hits = matcher.match(attack_features)
    
    assert len(hits) == 1
    assert hits[0]['attack'] == 's01_syn'