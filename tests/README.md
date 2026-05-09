# [cite_start]Hướng dẫn chạy Kiểm thử (Testing) [cite: 125]

Thư mục `tests/` chứa toàn bộ các kịch bản kiểm thử cho hệ thống phát hiện và giảm thiểu DDoS. [cite_start]Thư mục này bao gồm các bài test độc lập (Unit Test) và bài test tích hợp toàn hệ thống (Integration Test). [cite: 125]

## 1. Cấu trúc thư mục (Layout)

- [cite_start]`fixtures/`: Chứa các dữ liệu giả lập (mock data) như `baseline.json`, `features_benign.csv`, `features_attack.csv` để phục vụ cho Unit Test. [cite: 123, 124]

- [cite_start]`test_*.py`: Các kịch bản kiểm thử cho từng module tương ứng (entropy, stats, signature, mitigation, integration). [cite: 126, 127]

## 2. Hướng dẫn chạy (How to run)

### 2.1. [cite_start]Unit Test (Không cần Mininet) [cite: 126]

Unit Test được sử dụng để kiểm tra logic toán học và xử lý của từng module một cách độc lập. [cite_start]Tốc độ chạy rất nhanh và **không yêu cầu quyền root**. [cite: 126]

Để chạy toàn bộ các Unit Test, sử dụng lệnh sau:

```bash
pytest tests/test_entropy.py tests/test_stats.py tests/test_signature.py tests/test_mitigation.py -v
```

### 2.2. Integration Test (Cần Root)

Integration Test sẽ dựng toàn bộ hệ thống thực tế (bao gồm Ryu Controller, topo mạng Mininet, và luồng Detector) để kiểm tra kiểm thử đầu cuối (E2E).

Do cần can thiệp vào card mạng ảo, loại test này bắt buộc chạy với quyền root (`sudo`) và cần set timeout cao do thời gian dựng topology mạng.

Để chạy Integration Test, sử dụng lệnh sau:

```bash
sudo pytest tests/test_integration.py -v --timeout=120
```