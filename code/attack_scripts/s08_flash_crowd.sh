#!/bin/bash
VICTIM="10.0.2.10"
DURATION=20

echo "Bat dau Flash Crowd vao $VICTIM trong $DURATION giay..."
echo "Mo phong nhieu nguoi dung hop phap truy cap dong thoi"

# Flash crowd = nhieu nguon IP khac nhau, PPS vua phai, nhieu port
# Dung -a (spoof source) de gia lap traffic tu nhieu host noi bo
# Moi "user" gui ~20 pps toi cac port khac nhau -> entropy cao, PPS thap
# He thong KHONG nen phat hien la tan cong

# User 1: PC1 truy cap web (port 80)
timeout $DURATION hping3 -a 10.0.4.10 -S -p 80   -i u50000 $VICTIM &
PID1=$!
sleep 0.2

# User 2: PC2 truy cap HTTPS (port 443)
timeout $DURATION hping3 -a 10.0.4.11 -S -p 443  -i u50000 $VICTIM &
PID2=$!
sleep 0.2

# User 3: PC3 truy cap API (port 8080)
timeout $DURATION hping3 -a 10.0.4.12 -S -p 8080 -i u50000 $VICTIM &
PID3=$!
sleep 0.2

# User 4: PC4 truy cap web (port 80)
timeout $DURATION hping3 -a 10.0.4.13 -S -p 80   -i u50000 $VICTIM &
PID4=$!
sleep 0.2

# User 5: External user truy cap HTTPS
timeout $DURATION hping3 -a 10.0.1.20 -S -p 443  -i u50000 $VICTIM &
PID5=$!
sleep 0.2

# User 6: DB server callback (port 3306)
timeout $DURATION hping3 -a 10.0.3.10 -S -p 3306 -i u50000 $VICTIM &
PID6=$!

sleep $DURATION
kill $PID1 $PID2 $PID3 $PID4 $PID5 $PID6 2>/dev/null
echo "Hoan tat mo phong Flash Crowd!"
echo "Ket qua mong doi: 6 IPs, entropy ~2.5, PPS ~120, KHONG bi chan"