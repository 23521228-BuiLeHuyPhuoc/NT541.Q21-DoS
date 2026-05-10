#!/bin/bash
VICTIM="10.0.2.10"
DURATION=20

echo "Flash Crowd: gui traffic hop phap vao $VICTIM trong $DURATION giay..."
echo "HUONG DAN: Chay dong thoi tu nhieu host de mo phong flash crowd that:"
echo "  mininet> h_pc1 bash code/attack_scripts/s08_flash_crowd.sh &"
echo "  mininet> h_pc2 bash code/attack_scripts/s08_flash_crowd.sh &"
echo "  mininet> h_pc3 bash code/attack_scripts/s08_flash_crowd.sh &"
echo "  mininet> h_pc4 bash code/attack_scripts/s08_flash_crowd.sh &"
echo ""

# Flash crowd = nhieu nguoi dung hop phap truy cap cung luc
# Moi host gui traffic THAP (~20-30 pps) de KHONG giong flood
# Khi nhieu host chay cung luc -> entropy CAO -> he thong nhan dien la flash crowd
timeout $DURATION hping3 -S -p 80 -i u50000 $VICTIM &
PID1=$!
sleep 0.3
timeout $DURATION hping3 -S -p 443 -i u50000 $VICTIM &
PID2=$!

sleep $DURATION
kill $PID1 $PID2 2>/dev/null
echo "Hoan tat Flash Crowd tu $(hostname)!"