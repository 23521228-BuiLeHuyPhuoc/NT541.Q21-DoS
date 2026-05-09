import pytest
import math
import json
from code.entropy import shannon, renyi, EntropyDetector

# Tạo file baseline giả lập để test không bị phụ thuộc vào file thật
@pytest.fixture
def dummy_baseline(tmp_path):
    baseline_file = tmp_path / "baseline_stats.json"
    dummy_data = {
        "pps": {"mean": 11.4, "std": 6.4},
        "bps": {"mean": 10662.5, "std": 6515.0},
        "entropy_src_ip": {"mean": 1.29, "std": 0.29},
        "entropy_dst_port": {"mean": 1.33, "std": 0.35},
        "entropy_renyi_src": {"mean": 1.25, "std": 0.25}
    }
    baseline_file.write_text(json.dumps(dummy_data))
    return str(baseline_file)

# Khởi tạo detector dùng chung cho các test case
@pytest.fixture
def detector(dummy_baseline):
    return EntropyDetector(baseline_path=dummy_baseline, k_sigma=3)

# --- BẮT ĐẦU 5 TEST CASES YÊU CẦU ---

# 1. Test entropy Shannon với phân phối đều (đạt max)
def test_shannon_uniform():
    items = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4']
    assert math.isclose(shannon(items), 2.0, rel_tol=1e-5)

# 2. Test entropy Shannon khi chỉ có 1 IP (tập trung 100% -> entropy = 0)
def test_shannon_single():
    items = ['10.0.0.1', '10.0.0.1', '10.0.0.1']
    assert shannon(items) == 0

# 3. Test entropy Renyi với bậc q=2
def test_renyi_q2():
    items = ['A', 'A', 'B', 'B']
    assert math.isclose(renyi(items, q=2), 1.0, rel_tol=1e-5)

# 4. Test mạng bình thường (không vượt ngưỡng 3-sigma)
def test_detector_normal(detector):
    features = {
        'entropy_src_ip': 1.3,
        'entropy_dst_port': 1.35,
        'entropy_renyi_src': 1.26
    }
    result = detector.check(features)
    assert result["anomaly"] is False
    assert len(result["alerts"]) == 0

# 5. Test khi bị SYN Flood (entropy tụt mạnh -> phải có alert)
def test_detector_flood(detector):
    features = {
        'entropy_src_ip': 0.1,  # 0.1 cách 1.29 rất xa, vượt quá 3 lần độ lệch chuẩn (3*0.29)
        'entropy_dst_port': 1.0,
        'entropy_renyi_src': 0.2
    }
    result = detector.check(features)
    assert result["anomaly"] is True
    assert len(result["alerts"]) > 0
    assert result["alerts"][0]["feature"] == "entropy_src_ip"