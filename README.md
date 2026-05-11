# Denial-of-Service attack detection

## Thông tin đồ án
- **Môn học:** NT541.Q21 – Công nghệ mạng khả lập trình
- **Tên đồ án:** Denial-of-Service attack detection

## Thành viên nhóm
- Ngô Thị Mai Anh – 23520053
- Phạm Nguyễn Tấn Sang – 23521346
- Bùi Lê Huy Phước – 23521228
- Đỗ Hoàng Phúc – 23521195
- Phạm Ngọc Trúc Quỳnh – 23521334

## Cấu trúc thư mục

### Root
- `.gitignore`: cấu hình bỏ qua file không cần theo dõi.
- `README.md`: mô tả tổng quan dự án.
- `code/`: mã nguồn và tài nguyên chạy hệ thống.
- `datasets/`: dữ liệu đầu vào (pcap, CSV, thống kê).
- `docs/`: tài liệu mô tả và chữ ký tấn công.
- `results/`: dữ liệu kết quả/đầu ra.

### code/
- `__init__.py`: khai báo package.
- `alert_system.py`: xử lý cảnh báo.
- `attack_scripts/`: script tạo các kịch bản tấn công.
  - `s01_syn.sh`: tấn công SYN flood.
  - `s02_udp.sh`: tấn công UDP flood.
  - `s03_icmp.sh`: tấn công ICMP flood.
  - `s04_http.sh`: tấn công HTTP flood.
  - `s05_dns_ampl.sh`: tấn công DNS amplification.
  - `s06_ip_spoof.sh`: tấn công IP spoofing.
  - `s07_slowloris.sh`: tấn công Slowloris.
  - `s08_flash_crowd.sh`: kịch bản flash crowd.
- `dashboard.py`: giao diện/luồng dashboard.
- `detector.py`: mô-đun phát hiện tấn công.
- `entropy.py`: tính toán entropy.
- `feature_extraction.py`: trích xuất đặc trưng.
- `l3_router_extended.py`: mô phỏng router L3 mở rộng.
- `l3_router_test.py`: kiểm thử/kịch bản router.
- `mitigation.py`: giảm thiểu tấn công.
- `policy.yaml`: cấu hình/chính sách.
- `signature_matcher.py`: so khớp chữ ký tấn công.
- `stats.py`: thống kê dữ liệu.
- `templates/`: giao diện HTML.
  - `alerts.html`: trang hiển thị cảnh báo.
  - `flows.html`: trang hiển thị luồng.
  - `index.html`: trang chính.
- `topology/`: mô tả topology.
  - `topology_v4.py`: mô hình topology IPv4.

### datasets/
- `baseline.pcap`: dữ liệu nền.
- `baseline_stats.json`: thống kê nền.
- `s01_syn.pcap` → `s08_flash_crowd.pcap`: dữ liệu pcap cho các kịch bản.
- `features/`: đặc trưng trích xuất.
  - `baseline.csv`: đặc trưng dữ liệu nền.
  - `s01_syn.csv` → `s08_flash_crowd.csv`: đặc trưng theo kịch bản.
- `.gitkeep`: giữ thư mục trong git.

### docs/
- `DEMO_SCENARIO.md`: mô tả kịch bản demo.
- `LOGIC_EXPLANATION.md`: giải thích logic hệ thống.
- `attack_signatures.csv`: danh sách chữ ký tấn công.
- `.gitkeep`: giữ thư mục trong git.

### results/
- `raw/`: kết quả thô.
- `.gitkeep`: giữ thư mục trong git.
