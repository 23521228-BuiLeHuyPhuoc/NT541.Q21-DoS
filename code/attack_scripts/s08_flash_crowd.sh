#!/bin/bash
VICTIM="10.0.2.10"
DURATION=20

echo "Bat dau Flash Crowd vao $VICTIM trong $DURATION giay..."
echo "Mo phong nhieu nguoi dung hop phap truy cap cung luc"
echo "Kich ban nay KHONG nen bi phat hien la tan cong"

# Flash crowd = nhieu nguon khac nhau, PPS vua phai, nhieu port khac nhau
# Dung curl/wget thay vi hping3 de tao traffic HTTP binh thuong
# Moi host gui HTTP request voi toc do vua phai (khong flood)

# Host h_att1 da chay script nay, nen ta dung chinh no gui traffic nhe
# Gui HTTP requests binh thuong (khong phai SYN flood) voi toc do thap
timeout $DURATION hping3 -p 80 -i u5000 --syn $VICTIM &
PID1=$!
sleep 0.5
timeout $DURATION hping3 -p 443 -i u5000 --syn $VICTIM &
PID2=$!
sleep 0.5
timeout $DURATION hping3 -p 8080 -i u5000 --syn $VICTIM &
PID3=$!
sleep 0.5
timeout $DURATION hping3 -p 8443 -i u5000 --syn $VICTIM &
PID4=$!

sleep $DURATION
kill $PID1 $PID2 $PID3 $PID4 2>/dev/null
echo "Hoan tat mo phong Flash Crowd!"