#!/bin/bash
VICTIM="10.0.2.10"
DURATION=20

echo "Bat dau Flash Crowd vao $VICTIM trong $DURATION giay..."
# Mo phong traffic tu nhieu nguon hop phap (entropy cao, PPS vua phai)
# Kich ban nay KHONG nen bi phat hien la tan cong
timeout $DURATION hping3 -p 80 -i u2000 $VICTIM &
PID1=$!
sleep 1
timeout $DURATION hping3 -p 443 -i u2000 $VICTIM &
PID2=$!
sleep $DURATION
kill $PID1 $PID2 2>/dev/null
echo "Hoan tat mo phong Flash Crowd!"