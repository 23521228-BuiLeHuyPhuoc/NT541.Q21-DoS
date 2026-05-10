#!/bin/bash
VICTIM="10.0.2.10"
DURATION=60

echo "Bat dau Flash Crowd vao $VICTIM trong $DURATION giay..."

# Mo phong nhieu nguoi dung cung truy cap (tu nhieu host khac nhau)
for i in {1..4}; do
    ab -c 20 -n 5000 http://$VICTIM/ > /dev/null 2>&1 &
    AB_PIDS+=($!)
done

sleep $DURATION
kill ${AB_PIDS[@]} 2>/dev/null

echo "Hoan tat mo phong Flash Crowd!"