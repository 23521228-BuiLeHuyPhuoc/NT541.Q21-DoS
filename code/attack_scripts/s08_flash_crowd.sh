#!/bin/bash
VICTIM="10.0.2.10"
DURATION=20

echo "Bat dau Flash Crowd vao $VICTIM trong $DURATION giay..."
echo "Mo phong nhieu nguoi dung hop phap truy cap dong thoi"

# Flash crowd = nhieu host gui traffic HOP PHAP (khong spoof IP)
# Moi host gui ~20 pps toi cac port khac nhau
# He thong KHONG nen phat hien la tan cong

# Dung h_att1 IP that (10.0.1.10) gui toi nhieu port khac nhau
# Mo phong nhieu phien ket noi dong thoi tu 1 user

# Phien 1: Web port 80
timeout $DURATION hping3 -S -p 80   -i u50000 $VICTIM &
PID1=$!
sleep 0.1

# Phien 2: HTTPS port 443
timeout $DURATION hping3 -S -p 443  -i u50000 $VICTIM &
PID2=$!
sleep 0.1

# Phien 3: API port 8080
timeout $DURATION hping3 -S -p 8080 -i u50000 $VICTIM &
PID3=$!
sleep 0.1

# Phien 4: Web khac port 8888
timeout $DURATION hping3 -S -p 8888 -i u50000 $VICTIM &
PID4=$!
sleep 0.1

# Phien 5: SSH port 22
timeout $DURATION hping3 -S -p 22   -i u50000 $VICTIM &
PID5=$!
sleep 0.1

# Phien 6: FTP port 21
timeout $DURATION hping3 -S -p 21   -i u50000 $VICTIM &
PID6=$!

sleep $DURATION
kill $PID1 $PID2 $PID3 $PID4 $PID5 $PID6 2>/dev/null
echo "Hoan tat mo phong Flash Crowd!"
echo "Ket qua mong doi: 1 IP (10.0.1.10), nhieu port, entropy ~0, PPS thap, KHONG bi chan"