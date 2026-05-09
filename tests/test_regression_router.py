import sys
import os
import pytest
from unittest.mock import MagicMock
from scapy.all import rdpcap, IP

# Bơm đường dẫn để import được module trong thư mục code/
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../code')))

from l3_router_test import SimpleRouterEntropy
from l3_router_extended import L3RouterExtended

def test_regression_pcap():
    # 1. Khởi tạo Controller Cũ và Mới (Dùng Mock để giả lập môi trường Ryu)
    kwargs = {'wsgi': MagicMock()}
    old_router = SimpleRouterEntropy(**kwargs)
    new_router = L3RouterExtended(**kwargs)
    
    old_router.logger = MagicMock()
    new_router.logger = MagicMock()
    
    dp_mock = MagicMock()
    dp_mock.id = 1
    
    # Gắn switch giả vào cả 2 router
    old_router.datapaths = {1: dp_mock}
    new_router.datapaths = {1: dp_mock}
    
    # Mock hàm block của router mới để kiểm tra xem nó có được gọi không
    new_router.block.apply = MagicMock() 

    # 2. Đọc file dữ liệu tấn công s01
    pcap_file = 'datasets/s01_syn.pcap'
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        pytest.skip(f"Không tìm thấy file {pcap_file}, bỏ qua test này.")
    
    # 3. Trích xuất IP tấn công nhiều nhất từ file PCAP
    attack_ips = [pkt[IP].src for pkt in packets if IP in pkt]
    if not attack_ips:
        pytest.skip("Không có gói tin IP nào trong file pcap.")
        
    top_attacker = max(set(attack_ips), key=attack_ips.count)

    # 4. Chạy Router Mới trên dữ liệu này (Bắn 3 cảnh báo để kích hoạt Level 3 - Block)
    for _ in range(3):
        new_router.handle_alert({"src_ip": top_attacker, "attack": "syn_flood_pcap"})

    # =========================================================
    # ASSERTIONS (KIỂM CHỨNG KẾT QUẢ)
    # =========================================================
    
    # (a) Kiểm tra Router Mới VẪN ALERT (Không gãy logic cũ)
    new_router.logger.warning.assert_any_call(f"[GR1 LOG] {top_attacker} attack=syn_flood_pcap")
    
    # (b) Kiểm tra Router Mới có tính năng chặn mạnh mẽ (Điều mà Router cũ không có)
    new_router.block.apply.assert_called_with(dp_mock, top_attacker, timeout=60)