import sys
import os
import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../code')))
from signature_matcher import safe_eval, SignatureMatcher

def test_safe_eval_simple():
    ctx = {'entropy_src': 1.0, 'syn_pct': 0.8}
    assert safe_eval("entropy_src < 1.5 and syn_pct > 0.6", ctx) == True
    assert safe_eval("entropy_src > 2.0", ctx) == False

def test_blocks_dangerous():
    malicious_code = "__import__('os').system('rm -rf /')"
    ctx = {}
    with pytest.raises(ValueError):
        safe_eval(malicious_code, ctx)

def test_match_syn():
    matcher = SignatureMatcher(csv_path='docs/attack_signatures.csv')
    
    # 1. Trạng thái bình thường: Cung cấp đầy đủ các chỉ số khỏe mạnh
    # Entropy cao, %SYN thấp, flow mới tạo ra liên tục, phân tán port tốt
    normal_features = {
        'entropy_src': 3.0, 
        'syn_pct': 0.1, 
        'pps': 100,
        'new_flows_per_sec': 50,     # Mạng khỏe tạo nhiều kết nối
        'entropy_dst_port': 5.0      # Truy cập nhiều cổng dịch vụ
    }
    assert len(matcher.match(normal_features)) == 0
    
    # 2. Bị tấn công SYN Flood
    attack_features = {
        'entropy_src': 1.0, 
        'syn_pct': 0.8, 
        'pps': 6000,
        'new_flows_per_sec': 50,
        'entropy_dst_port': 5.0
    }
    hits = matcher.match(attack_features)
    
    assert len(hits) >= 1
    assert hits[0]['attack'] == 's01_syn_flood'