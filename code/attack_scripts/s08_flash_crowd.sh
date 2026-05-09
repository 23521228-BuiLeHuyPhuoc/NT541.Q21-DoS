#!/bin/bash
# Kich ban mo phong Flash Crowd (Nguoi dung that truy cap dot bien)
VICTIM="10.0.2.10"
DURATION=300

echo "Bat dau Flash Crowd vao $VICTIM trong $DURATION giay..."
echo "START_TS=$(date +%s)"

# 1. Bat tcpdump ghi lai traffic
tcpdump -i s2-eth99 -w datasets/s08_flash_crowd.pcap -G $DURATION -W 1 2>/dev/null &
TCPDUMP_PID=$!

# 2. Chay 4 tien trinh Apache Benchmark song song (mo phong h_pc1 den h_pc4)
for i in {1..4}; do
    ab -c 50 -n 25000 http://$VICTIM/ > /dev/null 2>&1 &
    AB_PIDS+=($!)
done

# 3. Cho het thoi gian roi dung
sleep $DURATION
kill $TCPDUMP_PID ${AB_PIDS[@]} 2>/dev/null

echo "END_TS=$(date +%s)"
echo "Hoan tat mo phong Flash Crowd!"