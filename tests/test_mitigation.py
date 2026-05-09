import sys
import os
from unittest.mock import MagicMock

# Ép Python nhận diện thư mục code/ chứa module
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../code')))
from mitigation import BlockModule

def test_block_module_apply():
    # 1. Tạo các đối tượng giả (Mock) thay cho Ryu và Mininet
    app_mock = MagicMock()
    dp_mock = MagicMock()
    parser_mock = MagicMock()
    dp_mock.ofproto_parser = parser_mock

    # 2. Chạy thử hàm chặn
    block = BlockModule(app_mock)
    block.apply(dp_mock, "10.0.1.99", timeout=60)

    # 3. Kiểm tra xem parser.OFPFlowMod có được gọi với đúng tham số không
    parser_mock.OFPFlowMod.assert_called_once()
    kwargs = parser_mock.OFPFlowMod.call_args.kwargs
    
    assert kwargs['priority'] == 100
    assert kwargs['instructions'] == []  # Phải rỗng để Drop
    assert kwargs['hard_timeout'] == 60
    
    # Kiểm tra xem có gửi lệnh xuống Switch không
    dp_mock.send_msg.assert_called_once()