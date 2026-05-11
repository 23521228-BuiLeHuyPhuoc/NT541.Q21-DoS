#!/bin/bash
# =============================================================
# run_benchmark.sh — Chay toan bo 8 kich ban tan cong va thu thap
# ket qua de phan tich cho bao cao.
#
# CACH DUNG (tu VM terminal, KHONG phai tu Mininet CLI):
#   cd ~/NT541.Q21-DoS
#   sudo bash code/run_benchmark.sh
#
# YEU CAU: Ryu + Mininet + detector.py phai dang chay
# =============================================================

RESULTS_DIR="results/benchmark"
ATTACK_DIR="code/attack_scripts"
WAIT_BETWEEN=40         # Thoi gian cho giua cac kich ban (giay)
ATTACK_DURATION=20      # Thoi gian tan cong (giay)
COLLECT_BEFORE=5        # Thu thap metric truoc tan cong (giay)
COLLECT_AFTER=10        # Thu thap metric sau tan cong (giay)

RYU_ENTROPY_URL="http://127.0.0.1:8081/api/entropy"
RYU_FLOW_URL="http://127.0.0.1:8081/stats/flow/2"
ALERTS_FILE="results/raw/alerts.json"
FEATURES_FILE="results/raw/current_features.json"

# Danh sach kich ban
SCENARIOS=(
    "s01_syn:s01_syn.sh:SYN Flood"
    "s02_udp:s02_udp.sh:UDP Flood"
    "s03_icmp:s03_icmp.sh:ICMP Flood"
    "s04_http:s04_http.sh:HTTP Flood"
    "s05_dns_ampl:s05_dns_ampl.sh:DNS Amplification"
    "s06_ip_spoof:s06_ip_spoof.sh:IP Spoof Flood"
    "s07_slowloris:s07_slowloris.sh:Slowloris"
    "s08_flash_crowd:s08_flash_crowd.sh:Flash Crowd"
)

mkdir -p "$RESULTS_DIR"

# =============================================================
# HAM CHAY LENH TREN MININET HOST
# =============================================================
run_on_host() {
    local host="$1"
    shift
    
    # Tim PID cua Mininet host
    local pid
    pid=$(pgrep -f "mininet:$host" 2>/dev/null | head -1)
    
    if [ -z "$pid" ]; then
        echo "[ERROR] Khong tim thay host $host trong Mininet"
        return 1
    fi
    
    # Dung mnexec neu co, khong thi dung nsenter
    if command -v mnexec &>/dev/null; then
        mnexec -a "$pid" "$@"
    else
        nsenter --target "$pid" --net --pid -- "$@"
    fi
}

# =============================================================
# HAM THU THAP METRIC
# =============================================================
collect_metrics() {
    local label="$1"
    local outfile="$2"
    
    # Thu thap tu Ryu entropy API
    local ryu_data
    ryu_data=$(curl -s "$RYU_ENTROPY_URL" 2>/dev/null || echo '{}')
    
    # Thu thap tu current_features.json (detector output)
    local feat_data
    if [ -f "$FEATURES_FILE" ]; then
        feat_data=$(cat "$FEATURES_FILE" 2>/dev/null || echo '{}')
    else
        feat_data='{}'
    fi
    
    # Thu thap flow count tu switch s2
    local flow_count
    flow_count=$(curl -s "$RYU_FLOW_URL" 2>/dev/null | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    flows = data.get('2', [])
    print(len(flows))
except:
    print(0)
" 2>/dev/null || echo "0")
    
    # Ghi ket qua
    echo "{\"label\":\"$label\",\"timestamp\":\"$(date '+%H:%M:%S')\",\"ryu\":$ryu_data,\"features\":$feat_data,\"flow_count\":$flow_count}" >> "$outfile"
}

# =============================================================
# HAM CHAY 1 KICH BAN
# =============================================================
run_scenario() {
    local id="$1"
    local script="$2"
    local name="$3"
    local scenario_dir="$RESULTS_DIR/$id"
    local metrics_file="$scenario_dir/metrics.jsonl"
    local alerts_before="$scenario_dir/alerts_before.json"
    local alerts_after="$scenario_dir/alerts_after.json"
    
    mkdir -p "$scenario_dir"
    
    echo ""
    echo "============================================================="
    echo "  KICH BAN: $name ($id)"
    echo "  Thoi gian: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "============================================================="
    
    # Xoa alerts cu
    > "$ALERTS_FILE" 2>/dev/null || true
    
    # --- GIAI DOAN 1: Thu thap baseline (truoc tan cong) ---
    echo "[BENCHMARK] Thu thap baseline ($COLLECT_BEFORE giay)..."
    > "$metrics_file"
    for i in $(seq 1 $COLLECT_BEFORE); do
        collect_metrics "baseline_${i}" "$metrics_file"
        sleep 1
    done
    
    # Luu alerts truoc tan cong
    cp "$ALERTS_FILE" "$alerts_before" 2>/dev/null || echo "[]" > "$alerts_before"
    
    # --- GIAI DOAN 2: Chay tan cong ---
    echo "[BENCHMARK] Bat dau tan cong: $script ($ATTACK_DURATION giay)..."
    local attack_start=$(date +%s)
    
    # Chay tan cong tren h_att1 qua namespace
    run_on_host h_att1 bash "$ATTACK_DIR/$script" &
    ATTACK_PID=$!
    
    # Thu thap metric moi giay trong khi tan cong
    for i in $(seq 1 $ATTACK_DURATION); do
        collect_metrics "attack_${i}" "$metrics_file"
        sleep 1
    done
    
    # Dam bao attack process da ket thuc
    wait $ATTACK_PID 2>/dev/null
    local attack_end=$(date +%s)
    
    echo "[BENCHMARK] Tan cong ket thuc. Thu thap ket qua..."
    
    # --- GIAI DOAN 3: Thu thap sau tan cong ---
    for i in $(seq 1 $COLLECT_AFTER); do
        collect_metrics "post_attack_${i}" "$metrics_file"
        sleep 1
    done
    
    # Luu alerts sau tan cong
    cp "$ALERTS_FILE" "$alerts_after" 2>/dev/null || echo "[]" > "$alerts_after"
    
    # Luu metadata
    cat > "$scenario_dir/metadata.json" << EOF
{
    "id": "$id",
    "name": "$name",
    "script": "$script",
    "attack_duration": $ATTACK_DURATION,
    "attack_start": $attack_start,
    "attack_end": $attack_end,
    "timestamp": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
    
    echo "[BENCHMARK] $name hoan tat. Ket qua luu tai: $scenario_dir/"
    echo ""
}

# =============================================================
# MAIN: CHAY TOAN BO KICH BAN
# =============================================================
echo "============================================================="
echo "  SDN DDoS BENCHMARK — $(date '+%Y-%m-%d %H:%M:%S')"
echo "  8 kich ban, $ATTACK_DURATION giay moi kich ban"
echo "  Thoi gian cho giua cac kich ban: ${WAIT_BETWEEN}s"
echo "============================================================="

# Kiem tra Ryu da san sang chua
if ! curl -s "$RYU_ENTROPY_URL" > /dev/null 2>&1; then
    echo "[ERROR] Khong ket noi duoc toi Ryu controller!"
    echo "        Dam bao Ryu, Mininet va Detector dang chay."
    exit 1
fi
echo "[OK] Ryu controller san sang."

# Warm up ARP table (tuong tu pingall) de flow rules duoc cai dat tren s2
echo "[BENCHMARK] Warming up ARP table (ping giua cac host)..."
HOSTS=("h_att1" "h_att2" "h_sv1" "h_sv2" "h_pc1" "h_pc2" "h_pc3" "h_pc4" "h_pc5" "h_pc6" "h_admin")
TARGETS=("10.0.2.10" "10.0.2.11" "10.0.1.10" "10.0.1.20" "10.0.3.10" "10.0.3.11" "10.0.4.10" "10.0.4.11" "10.0.4.12" "10.0.4.13")

# Ping tu h_att1 toi tat ca host khac
for target in "${TARGETS[@]}"; do
    run_on_host h_att1 ping -c 1 -W 1 "$target" > /dev/null 2>&1 &
done
wait

# Ping tu h_sv1 toi h_att1
run_on_host h_sv1 ping -c 1 -W 1 10.0.1.10 > /dev/null 2>&1
# Ping tu h_sv2 toi h_att1
run_on_host h_sv2 ping -c 1 -W 1 10.0.1.10 > /dev/null 2>&1

echo "[OK] ARP table da duoc khoi tao. Flow rules da cai dat tren s2."
sleep 3  # Cho detector ghi nhan baseline

TOTAL_START=$(date +%s)
SCENARIO_NUM=0
TOTAL=${#SCENARIOS[@]}

for scenario in "${SCENARIOS[@]}"; do
    IFS=':' read -r id script name <<< "$scenario"
    SCENARIO_NUM=$((SCENARIO_NUM + 1))
    
    echo ""
    echo ">>> [$SCENARIO_NUM/$TOTAL] $name"
    
    run_scenario "$id" "$script" "$name"
    
    if [ $SCENARIO_NUM -lt $TOTAL ]; then
        echo "[BENCHMARK] Cho ${WAIT_BETWEEN}s de he thong go chan va on dinh..."
        sleep $WAIT_BETWEEN
    fi
done

TOTAL_END=$(date +%s)
TOTAL_ELAPSED=$((TOTAL_END - TOTAL_START))

echo ""
echo "============================================================="
echo "  BENCHMARK HOAN TAT"
echo "  Tong thoi gian: ${TOTAL_ELAPSED} giay"
echo "  Ket qua luu tai: $RESULTS_DIR/"
echo "============================================================="
echo ""
echo "Chay phan tich: python3 code/analyze_benchmark.py"
