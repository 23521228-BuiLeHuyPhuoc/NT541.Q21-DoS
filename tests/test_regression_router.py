import sys
import os
import pytest
import socket
from unittest.mock import MagicMock
import dpkt

# Bơm đường dẫn để import được module trong thư mục code/
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../code')))

from l3_router_test import SimpleRouterEntropy
from l3_router_extended import L3RouterExtended

def test_regression_pcap():
    # 1. Khởi tạo Controller Cũ và Mới
    kwargs = {'wsgi': MagicMock()}
    old_router = SimpleRouterEntropy(**kwargs)
    new_router = L3RouterExtended(**kwargs)
    
    old_router.logger = MagicMock()
    new_router.logger = MagicMock()
    
    dp_mock = MagicMock()
    dp_mock.id = 1
    
    old_router.datapaths = {1: dp_mock}
    new_router.datapaths = {1: dp_mock}
    
    new_router.block.apply = MagicMock() 

    # 2. Đọc file dữ liệu tấn công s01 bằng dpkt
    pcap_file = 'datasets/s01_syn.pcap'
    if not os.path.exists(pcap_file):
        pytest.skip(f"Không tìm thấy file {pcap_file}, bỏ qua test này.")
        
    attack_ips = []
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            # Kiểm tra xem gói tin có phải là IP không
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                src_ip = socket.inet_ntoa(ip.src)
                attack_ips.append(src_ip)
    
    if not attack_ips:
        pytest.skip("Không có gói tin IP nào trong file pcap.")
        
    # 3. Lấy IP xuất hiện nhiều nhất (Kẻ tấn công)
    top_attacker = max(set(attack_ips), key=attack_ips.count)

    # 4. Chạy Router Mới trên dữ liệu này (Bắn 3 cảnh báo để lên Level 3 - Block)
    for _ in range(3):
        new_router.handle_alert({"src_ip": top_attacker, "attack": "syn_flood_pcap"})

    # =========================================================
    # ASSERTIONS (KIỂM CHỨNG)
    # =========================================================
    
    # (a) Kiểm tra Router Mới VẪN ALERT (Không gãy logic cũ)
    new_router.logger.warning.assert_any_call(f"[GR1 LOG] {top_attacker} attack=syn_flood_pcap")
    
    # (b) Kiểm tra Router Mới gọi hàm Block (Tính năng mới)
    new_router.block.apply.assert_called_with(dp_mock, top_attacker, timeout=60)