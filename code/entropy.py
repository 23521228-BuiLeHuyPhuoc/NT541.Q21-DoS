"""
Module Entropy - Tách từ l3_router_test.py phục vụ pipeline 4 tầng.
Cơ sở khoa học: Lakhina (2005) [2] và Mousavi (2014).[3]
"""
import math
from collections import Counter

def _compute_entropy(items):
    """
    Tính toán Shannon Entropy.
    Công thức: $H(X) = -\sum p(x_i) \log_2 p(x_i)$
    """
    if not items:
        return 0.0
    counts = Counter(items)
    total = len(items)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy

def _window_buffer(data_list, new_item, max_size=1000):
    """
    Duy trì cửa sổ trượt cho danh sách IP/Port.
    Dựa trên thiết kế WINDOW_SIZE của router cũ.
    """
    data_list.append(new_item)
    if len(data_list) > max_size:
        data_list.pop(0)
    return data_list

def _monitor_entropy(current_entropy, low_threshold=1.5, high_threshold=8.0):
    """
    Phân loại trạng thái tấn công dựa trên ngưỡng.
    Ngưỡng 1.5 được Mousavi (2014) xác định là tối ưu cho SDN.[4, 3]
    """
    if current_entropy < low_threshold:
        return 1  # DoS IP cố định
    elif current_entropy > high_threshold:
        return 2  # DoS Spoofing
    return 0  # Bình thường