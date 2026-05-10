#!/bin/bash
VICTIM="10.0.2.10"
DURATION=300

echo "Bat dau Flash Crowd vao $VICTIM trong $DURATION giay..."
echo "START_TS=$(date +%s)"

# Da sua -i s2-eth99 thanh -i any
tcpdump -i any -w datasets/s08_flash_crowd.pcap -G $DURATION -W 1 2>/dev/null &
TCPDUMP_PID=$!

for i in {1..4}; do
    ab -c 50 -n 25000 http://$VICTIM/ > /dev/null 2>&1 &
    AB_PIDS+=($!)
done

sleep $DURATION
kill $TCPDUMP_PID ${AB_PIDS[@]} 2>/dev/null

echo "END_TS=$(date +%s)"
echo "Hoan tat mo phong Flash Crowd!"