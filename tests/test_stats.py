
import pytest
import json
import os
import sys

# Đưa thư mục code vào sys.path để import
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../code')))
from stats import StatsDetector

@pytest.fixture
def dummy_baseline(tmp_path):
    # Tạo baseline giả định
    baseline_file = tmp_path / "baseline_stats.json"
    dummy_data = {
        "pps": {"mean": 100.0, "std": 10.0},
        "bps": {"mean": 80000.0, "std": 5000.0}
    }
    baseline_file.write_text(json.dumps(dummy_data))
    return str(baseline_file)

@pytest.fixture
def detector(dummy_baseline):
    return StatsDetector(baseline_path=dummy_baseline)

def test_zscore_normal(detector):
    # Dữ liệu bình thường (pps = 110, lệch 1 std so với mean 100)
    features = {"pps": 110.0, "bps": 82000.0}
    res = detector.check(features)
    assert res["anomaly"] is False
    assert len(res["alerts"]) == 0

def test_zscore_attack(detector):
    # Dữ liệu tấn công đột ngột (pps = 200, lệch 10 std -> Chắc chắn Z-score phải hú còi)
    features = {"pps": 200.0, "bps": 80000.0}
    res = detector.check(features)
    assert res["anomaly"] is True
    sources = [a["source"] for a in res["alerts"]]
    assert "zscore" in sources

def test_cusum_gradual(detector):
    # Tấn công tăng chậm (Low-rate DDoS): 
    # Mỗi chu kỳ pps = 115 (tăng nhẹ, Z-score sẽ KHÔNG phát hiện vì < 3 std)
    # Tuy nhiên, CUSUM sẽ tích lũy dần: x - mu - k = 115 - 100 - (0.5*10) = 10
    # Ngưỡng h_factor = 5 -> h = 5*10 = 50. Sau 5-6 chu kỳ sẽ báo động.
    features = {"pps": 115.0}
    
    # 4 chu kỳ đầu chưa báo động
    for _ in range(4):
        res = detector.check(features)
        cusum_alerts = [a for a in res.get("alerts", []) if a["source"] == "cusum"]
        assert len(cusum_alerts) == 0
        
    # Chu kỳ thứ 6 chắc chắn vượt ngưỡng 50
    detector.check(features)
    res = detector.check(features)
    cusum_alerts = [a for a in res.get("alerts", []) if a["source"] == "cusum"]
    assert len(cusum_alerts) > 0
